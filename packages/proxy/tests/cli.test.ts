// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The built CLI prints its startup banner with the upstream URL redacted.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { type AddressInfo, createServer } from "node:net";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
// Fake key literal — never a real key.
const KEY32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";

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
  test("shows the upstream redacted and no key or query value", async () => {
    const out = await banner(`https://h.example/arbitrum_vrpc/${KEY32}?apikey=sentinel-query&x=1`);
    expect(/upstream: +(\S+)/.exec(out)?.[1]).toBe(
      "https://h.example/arbitrum_vrpc/***?apikey=***&x=***",
    );
    for (const secret of [KEY32, "sentinel-query"]) expect(out).not.toContain(secret);
  });
});
