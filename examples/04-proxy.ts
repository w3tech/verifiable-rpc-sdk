// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Verifying proxy demo: spawn the local vrpc-proxy as a child process, then
// call it with a plain `fetch` — the client imports zero SDK code, yet every
// byte it receives was verified fail-closed (signature + attestation +
// mandatory hardware verify) by the proxy before being relayed.
import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

// Ankr's production ingress may require a valid API key in the URL path and
// rejects the committed placeholder. Set ANKR_API_KEY to see a
// verified-success run; without it this example still demonstrates the
// proxy's fail-closed refusal (no unverified byte is ever relayed).
const API_KEY = process.env.ANKR_API_KEY ?? "123456";
const HAS_REAL_KEY = !!process.env.ANKR_API_KEY;
const UPSTREAM_URL = `https://rpc.ankr.com/arbitrum_vrpc/${API_KEY}`;
const CHAIN_ID = "42161";
// Explicit non-default port so the example never collides with a dev-running
// default instance on 8969.
const LISTEN = "127.0.0.1:8970";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const BOOT_TIMEOUT_MS = 30_000;

/**
 * Spawn the proxy CLI directly via tsx and resolve with its listen URL parsed
 * out of the single stderr banner line.
 */
function spawnProxy(): Promise<{ child: ChildProcess; url: string }> {
  const child = spawn(
    "tsx",
    [
      "packages/proxy/src/cli.ts",
      "--upstream",
      UPSTREAM_URL,
      "--chain",
      CHAIN_ID,
      "--listen",
      LISTEN,
    ],
    { cwd: REPO_ROOT, stdio: ["ignore", "ignore", "pipe"] },
  );

  return new Promise((resolve, reject) => {
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`proxy did not print its banner within ${BOOT_TIMEOUT_MS}ms:\n${stderr}`));
    }, BOOT_TIMEOUT_MS);
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      const banner = stderr.match(/vrpc-proxy listening on (http:\/\/\S+)/);
      if (banner?.[1]) {
        clearTimeout(timer);
        resolve({ child, url: banner[1] });
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`proxy exited before binding (code ${code}):\n${stderr}`));
    });
  });
}

function truncate(value: string, max = 24): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function main() {
  const { child, url } = await spawnProxy();
  try {
    // Plain HTTP client — no SDK imports; the proxy owns all verification and
    // never relays a body it could not verify.
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
    if (!res.ok) {
      if (!HAS_REAL_KEY) {
        // Expected without a key: the upstream rejects the placeholder, the
        // proxy refuses to relay the unsigned reply — fail-closed by design.
        console.log(
          `Upstream rejected the placeholder API key; the proxy failed closed ` +
            `(HTTP ${res.status}: ${truncate(body, 200)}).\n` +
            `This is the fail-closed guarantee in action — no unverified byte was relayed.\n` +
            `Set ANKR_API_KEY=<your Ankr API key> to see a verified-success run.`,
        );
        return;
      }
      throw new Error(`proxy returned HTTP ${res.status}: ${body}`);
    }
    // The vRPC-* headers pass through untouched — proof the relayed response
    // is the node-signed original, re-verifiable by the client at any time.
    const vrpcHeaders = ["vrpc-signature", "vrpc-timestamp", "vrpc-pubkey"].map(
      (name) => [name, res.headers.get(name)] as const,
    );
    if (vrpcHeaders.some(([, value]) => value === null)) {
      throw new Error(`vRPC headers missing on a relayed response: ${truncate(body, 200)}`);
    }
    const parsed = JSON.parse(body) as { result?: { number?: string; hash?: string } };
    console.log({
      httpStatus: res.status,
      blockNumber: parsed.result?.number,
      blockHash: parsed.result?.hash,
      verifiedHeaders: Object.fromEntries(
        vrpcHeaders.map(([name, value]) => [name, truncate(value ?? "")]),
      ),
    });
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit").catch(() => {});
    }
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
