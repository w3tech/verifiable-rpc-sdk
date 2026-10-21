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
import type { Server } from "node:http";
import { verifyResponse } from "@w3tech.io/vrpc-core";
import { mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "@w3tech.io/vrpc-test-support/interop";
import { closeServer, listen } from "@w3tech.io/vrpc-test-support/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServerWith } from "../../src/server";
import { testConfig } from "../support/test-overrides";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

// Auto-incrementing JSON-RPC id: consecutive calls must send distinct request
// bytes so their pre-images (and deterministic Ed25519 signatures) always
// differ, even when two loopback round-trips land in the same millisecond.
let nextId = 1;

function encode(payload: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}

async function post(
  url: string,
  requestBytes: Uint8Array,
): Promise<{ status: number; responseBytes: Uint8Array; headers: Headers }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBytes,
  });
  return {
    status: res.status,
    responseBytes: new Uint8Array(await res.arrayBuffer()),
    headers: res.headers,
  };
}

d("integration: proxy e2e", () => {
  let env: Interop | undefined;
  let sidecar: Interop["sidecar"] | undefined;
  let upstream: Interop["upstream"] | undefined;
  let proxy: { url: string; server: Server } | undefined;
  let chainId = "";

  // The relay blanks app_compose, which the simulator fixtures need for the compose-hash check.
  beforeAll(async () => {
    env = await spawnInterop();
    sidecar = env.sidecar;
    upstream = env.upstream;
    chainId = env.chainId;
    const relayUrl = env.relay.url;
    const server = createServerWith(
      testConfig(relayUrl, { chainId, attestationUrl: `${relayUrl}/attestation` }),
      { hardwareVerifier: mockHardwareVerifier() },
    );
    proxy = { url: await listen(server), server };
  }, 60_000);

  afterAll(async () => {
    if (proxy) await closeServer(proxy.server);
    await env?.kill();
  });

  it("single JSON-RPC POST through the proxy verifies client-side (smoke)", async () => {
    if (!sidecar || !proxy) throw new Error("harness not initialised");

    const requestBytes = encode({
      jsonrpc: "2.0",
      id: nextId++,
      method: "eth_blockNumber",
      params: [],
    });
    const { status, responseBytes, headers } = await post(proxy.url, requestBytes);
    expect(status).toBe(200);

    // Client-side re-verification over the exact bytes the proxy delivered —
    // first full-TrustedVerifier run against a simulator quote happens inside
    // the proxy before these bytes ever reach us.
    const pair = await verifyResponse(requestBytes, responseBytes, headers, {
      chainId,
    });
    expect(pair.verification.pubkeyHex).toBe(sidecar.pubkeyHex);
  });

  it("batch JSON-RPC POST relays as ONE upstream request and re-verifies (R6)", async () => {
    if (!sidecar || !proxy || !upstream) throw new Error("harness not initialised");

    // Count delta, not absolute count — assertions stay order-independent.
    const before = upstream.requests().length;

    // A JSON-RPC ARRAY of 2 calls; capture the exact bytes we send because
    // the sidecar signs over them (batch is opaque bytes, not a code branch).
    const requestBytes = encode([
      { jsonrpc: "2.0", id: nextId++, method: "eth_blockNumber", params: [] },
      { jsonrpc: "2.0", id: nextId++, method: "eth_chainId", params: [] },
    ]);
    const res = await post(proxy.url, requestBytes);
    const { responseBytes } = res;

    expect(res.status).toBe(200);
    // Single relay: the batch traversed proxy → sidecar → upstream as exactly
    // one request — no per-item fan-out anywhere in the pipeline.
    expect(upstream.requests().length - before).toBe(1);

    // The stack never parses bodies; the TEST parses to prove the echoed
    // batch array survived the round trip intact.
    const body = JSON.parse(new TextDecoder().decode(responseBytes)) as unknown[];
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(2);

    // Byte-identity proof: the Ed25519 signature covers the exact bytes, so
    // re-verifying client-side proves the proxy relayed the sidecar's signed
    // output unmutated (signatures are per-call — never byte-diff two calls).
    const pair = await verifyResponse(requestBytes, responseBytes, res.headers, {
      chainId,
    });
    expect(pair.verification.pubkeyHex).toBe(sidecar.pubkeyHex);

    expect(res.headers.get("vrpc-signature")).toBeTruthy();
    expect(res.headers.get("vrpc-timestamp")).toBeTruthy();
    expect(res.headers.get("vrpc-pubkey")).toBe(sidecar.pubkeyHex);
  });

  it("path-based REST GET with empty body forwards path+query and verifies (R7)", async () => {
    if (!sidecar || !proxy || !upstream) throw new Error("harness not initialised");

    // Plain path+query, no body. (No dot-dot segments — the proxy normalizes
    // traversal out of client paths.)
    const res = await fetch(`${proxy.url}/v1/accounts/GABC?limit=1`, { method: "GET" });
    const responseBytes = new Uint8Array(await res.arrayBuffer());

    expect(res.status).toBe(200);

    // The echo upstream captured the request line — proves path+query
    // traversed proxy → sidecar → upstream intact.
    const hit = upstream
      .requests()
      .find((r) => r.method === "GET" && r.url === "/v1/accounts/GABC?limit=1");
    expect(hit).toBeDefined();

    // The sidecar signs the raw received request bytes — EMPTY for a bodyless
    // GET — and core's buildPreImage hashes an empty request identically, so
    // verification is symmetric with requestBytes = new Uint8Array(0).
    const pair = await verifyResponse(new Uint8Array(0), responseBytes, res.headers, {
      chainId,
    });
    expect(pair.verification.pubkeyHex).toBe(sidecar.pubkeyHex);

    expect(res.headers.get("vrpc-signature")).toBeTruthy();
    expect(res.headers.get("vrpc-timestamp")).toBeTruthy();
    expect(res.headers.get("vrpc-pubkey")).toBe(sidecar.pubkeyHex);
  });
});
