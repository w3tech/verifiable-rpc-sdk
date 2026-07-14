// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// End-to-end integration tests: dstack simulator + real sidecar binary + the
// in-process verifying proxy. The proxy runs its production pipeline (real
// attestation fetch from the live sidecar, real Ed25519 verify, replay window)
// with only the hardware verifier mocked — a simulator quote is not real TDX.
// Every test re-verifies the client-visible bytes with core's `verifyResponse`;
// that re-verification IS the byte-identity proof (the Ed25519 signature covers
// the exact bytes, so any relay mutation fails verification).
//
// Env-gated: if any of `DSTACK_SIMULATOR_BIN`, `DSTACK_SIMULATOR_FIXTURES_DIR`,
// or `SIDECAR_BIN` is unset, the entire `describe` block is skipped and a
// one-line skip message is logged at module load.

import { verifyResponse } from "@w3tech.io/vrpc-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  cleanup,
  integrationEnabled,
  type MockUpstreamHandle,
  type ProxyHandle,
  type SidecarHandle,
  type SimulatorHandle,
  spawnMockUpstream,
  spawnProxy,
  spawnSidecar,
  spawnSimulator,
} from "./harness";

if (!integrationEnabled) {
  console.log(
    "[integration] skipping — set DSTACK_SIMULATOR_BIN, DSTACK_SIMULATOR_FIXTURES_DIR, SIDECAR_BIN to run",
  );
}

const d = integrationEnabled ? describe : describe.skip;

// Single shared chain id passed to BOTH the sidecar and the proxy config — a
// mismatch means BadSignature on every verify (sha256(chain_id) leads the
// 104-byte pre-image).
const CHAIN_ID = "1";

// Canned upstream body: a JSON-RPC batch response. The whole stack is
// payload-agnostic — the mock never parses JSON-RPC, it just returns this
// string for every request, which is exactly the point.
const BATCH_CANNED =
  '[{"jsonrpc":"2.0","id":1,"result":"0x1"},{"jsonrpc":"2.0","id":2,"result":"0x2"}]';

// Auto-incrementing JSON-RPC id: consecutive calls must send distinct request
// bytes so their pre-images (and deterministic Ed25519 signatures) always
// differ, even when two loopback round-trips land in the same millisecond.
let nextId = 1;

/** POST a JSON-RPC envelope through the proxy and return the raw wire triple. */
async function rpcCall(
  url: string,
  method: string,
  params: unknown[],
): Promise<{
  status: number;
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  headers: Headers;
}> {
  const requestBytes = new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  );
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBytes,
  });
  const responseBytes = new Uint8Array(await res.arrayBuffer());
  return { status: res.status, requestBytes, responseBytes, headers: res.headers };
}

d("integration: proxy e2e", () => {
  let simulator: SimulatorHandle | undefined;
  let upstream: MockUpstreamHandle | undefined;
  let sidecar: SidecarHandle | undefined;
  let proxy: ProxyHandle | undefined;

  beforeAll(async () => {
    simulator = await spawnSimulator();
    upstream = await spawnMockUpstream(BATCH_CANNED);
    sidecar = await spawnSidecar(simulator.socketPath, upstream.url, CHAIN_ID);
    proxy = await spawnProxy({ upstreamUrl: sidecar.url, chainId: CHAIN_ID });
  });

  afterAll(async () => {
    await cleanup([proxy, sidecar, upstream, simulator]);
  });

  it("single JSON-RPC POST through the proxy verifies client-side (smoke)", async () => {
    if (!sidecar || !proxy) throw new Error("harness not initialised");

    const { status, requestBytes, responseBytes, headers } = await rpcCall(
      proxy.url,
      "eth_blockNumber",
      [],
    );
    expect(status).toBe(200);

    // Client-side re-verification over the exact bytes the proxy delivered —
    // first full-TrustedVerifier run against a simulator quote happens inside
    // the proxy before these bytes ever reach us.
    const pair = await verifyResponse(requestBytes, responseBytes, headers, {
      chainId: CHAIN_ID,
    });
    expect(pair.verification.pubkeyHex).toBe(sidecar.pubkeyHex);
  });
});
