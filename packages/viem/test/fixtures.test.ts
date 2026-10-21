// Scaffold self-check: proves the kit signer `signedJsonHeaders` produces
// `vRPC-*` headers that `@w3tech.io/vrpc-core` `verifyResponse` ACCEPTS for the
// happy path, and that the fail-closed paths (wrong-chain signature, unsigned)
// reject as expected. This guards the offline test harness itself — NOT core crypto, which `packages/core/tests/verify.test.ts`
// already covers. The adapter WIRING proper is covered by the transport suite.

import { BadSignature, MissingHeader, verifyResponse } from "@w3tech.io/vrpc-core";
import { CHAIN_ID, signedJsonHeaders, WIDE_WINDOW } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";

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
  test("signedJsonHeaders output verifies under vrpc-core", async () => {
    const headers = signedJsonHeaders(CHAIN_ID, REQUEST_BYTES, RESPONSE_BYTES);
    const pair = await verifyResponse(REQUEST_BYTES, RESPONSE_BYTES, headers, {
      chainId: CHAIN_ID,
      replayWindowMs: WIDE_WINDOW,
    });
    expect(pair.responseBytes).toEqual(RESPONSE_BYTES);
    expect(pair.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(pair.verification.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("wrong signing chain id rejects with BadSignature", async () => {
    const headers = signedJsonHeaders("1", REQUEST_BYTES, RESPONSE_BYTES);
    await expect(
      verifyResponse(REQUEST_BYTES, RESPONSE_BYTES, headers, {
        chainId: CHAIN_ID,
        replayWindowMs: WIDE_WINDOW,
      }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  test("unsigned header set rejects with MissingHeader", async () => {
    await expect(
      verifyResponse(
        REQUEST_BYTES,
        RESPONSE_BYTES,
        { "content-type": "application/json" },
        { chainId: CHAIN_ID, replayWindowMs: WIDE_WINDOW },
      ),
    ).rejects.toBeInstanceOf(MissingHeader);
  });
});
