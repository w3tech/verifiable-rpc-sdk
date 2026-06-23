// Scaffold self-check (Wave 0): proves the mirrored request-aware signer in
// `fixtures.ts` produces `vRPC-*` headers that `@ankr.com/vrpc-core`
// `verifyResponse` ACCEPTS for the happy path, and that the fail-closed paths
// (wrong-chain signature, unsigned) reject as expected. This guards the offline
// test harness itself — NOT core crypto, which `packages/core/tests/verify.test.ts`
// already covers (TEST-04). The adapter WIRING proper is Plan 31-02.

import { BadSignature, MissingHeader, verifyResponse } from "@ankr.com/vrpc-core";
import { describe, expect, test } from "vitest";

import { CHAIN_ID, signResponseBytes } from "./fixtures";

const REQUEST_BYTES = new TextEncoder().encode(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBalance",
    params: ["0x1111111111111111111111111111111111111111", "latest"],
  }),
);
const RESPONSE_BYTES = new TextEncoder().encode(
  JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1bc16d674ec80000" }),
);

describe("offline fixture scaffold (viem)", () => {
  test("signResponseBytes output verifies under vrpc-core", async () => {
    const headers = await signResponseBytes(REQUEST_BYTES, RESPONSE_BYTES);
    const pair = await verifyResponse(REQUEST_BYTES, RESPONSE_BYTES, headers, {
      chainId: CHAIN_ID,
      replayWindowMs: Number.MAX_SAFE_INTEGER,
    });
    expect(pair.responseBytes).toEqual(RESPONSE_BYTES);
    expect(pair.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(pair.verification.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("wrong signing chain id rejects with BadSignature", async () => {
    const headers = await signResponseBytes(REQUEST_BYTES, RESPONSE_BYTES, {
      signingChainId: 1n,
    });
    await expect(
      verifyResponse(REQUEST_BYTES, RESPONSE_BYTES, headers, {
        chainId: CHAIN_ID,
        replayWindowMs: Number.MAX_SAFE_INTEGER,
      }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  test("unsigned header set rejects with MissingHeader", async () => {
    await expect(
      verifyResponse(
        REQUEST_BYTES,
        RESPONSE_BYTES,
        { "content-type": "application/json" },
        { chainId: CHAIN_ID, replayWindowMs: Number.MAX_SAFE_INTEGER },
      ),
    ).rejects.toBeInstanceOf(MissingHeader);
  });
});
