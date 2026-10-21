// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The built CLI's startup banner masks key-shaped path segments and every query value.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { type AddressInfo, createServer } from "node:net";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
// Fake key literals — never real keys.
const KEY32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
const KEY64 = "deadbeef".repeat(8);

async function banner(upstream: string): Promise<string> {
  const srv = createServer();
  await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const { port } = srv.address() as AddressInfo;
  await new Promise((resolve) => srv.close(resolve));
  const args = [CLI, "--upstream", upstream, "--chain-id", "1", "--listen", `127.0.0.1:${port}`];
  const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH } });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
    if (stderr.includes("confidential:")) child.kill("SIGTERM");
  });
  await new Promise((resolve) => child.once("exit", resolve));
  return stderr;
}

describe.skipIf(!existsSync(CLI) && process.env.REQUIRE_DIST !== "1")("startup banner", () => {
  test.each([
    [
      `https://h.example/arbitrum_vrpc/${KEY32}?apikey=sentinel-query&x=1`,
      "https://h.example/arbitrum_vrpc/***?apikey=***&x=***",
    ],
    [`https://h.example/arbitrum_vrpc/${KEY64}`, "https://h.example/arbitrum_vrpc/***"],
    ["http://127.0.0.1:8969/eth_vrpc", "http://127.0.0.1:8969/eth_vrpc"],
  ])("upstream %s is shown as %s", async (upstream, shown) => {
    const out = await banner(upstream);
    expect(/upstream: +(\S+)/.exec(out)?.[1]).toBe(shown);
    for (const secret of [KEY32, KEY64, "sentinel-query"]) expect(out).not.toContain(secret);
  });
});
