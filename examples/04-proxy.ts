// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Spawn vrpc-proxy, then call it with a plain fetch. The client imports no SDK
// code, yet every byte it receives was verified fail-closed before relay.
import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

// Set ANKR_API_KEY for a verified-success run; without it the upstream rejects
// the request and the proxy fails closed — still a valid demo.
const API_KEY = process.env.ANKR_API_KEY;
const UPSTREAM_URL = "https://rpc.ankr.com/arbitrum_vrpc";
const CHAIN_ID = "42161";
const LISTEN = "127.0.0.1:8970";
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

async function main() {
  const { child, url } = await spawnProxy();
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getBlockByNumber",
        params: ["latest", false],
      }),
    });
    const body = await res.text();

    // The proxy never relays a body it could not verify.
    if (!res.ok) {
      console.log(
        `Proxy failed closed: HTTP ${res.status}. Set ANKR_API_KEY=<key> for a verified-success run.`,
      );
      return;
    }

    // A relayed 200 carries the node's vRPC-* headers verbatim — re-verifiable by the client.
    const { result } = JSON.parse(body) as { result?: { number?: string; hash?: string } };
    console.log({
      httpStatus: res.status,
      blockNumber: result?.number,
      blockHash: result?.hash,
      pubkey: res.headers.get("vrpc-pubkey"),
    });
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit").catch(() => {});
    }
  }
}

// Resolve once the proxy's stderr banner reports its listen URL.
function spawnProxy(): Promise<{ child: ChildProcess; url: string }> {
  const args = [
    "packages/proxy/src/cli.ts",
    "--upstream",
    UPSTREAM_URL,
    "--chain",
    CHAIN_ID,
    "--listen",
    LISTEN,
  ];
  if (API_KEY) args.push("--api-key", API_KEY);
  const child = spawn("tsx", args, { cwd: REPO_ROOT, stdio: ["ignore", "ignore", "pipe"] });
  return new Promise((resolve, reject) => {
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`proxy did not start within 30s:\n${stderr}`));
    }, 30_000);
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      const url = stderr.match(/listening on (http:\/\/\S+)/)?.[1];
      if (url) {
        clearTimeout(timer);
        resolve({ child, url });
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`proxy exited before binding (code ${code}):\n${stderr}`));
    });
  });
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
