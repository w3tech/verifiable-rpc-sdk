// Scaffold self-check (Wave 0): proves the synthesized SINGLE_RESULT fixture is
// genuinely verifiable under `@ankr.com/vrpc-core` `verifyResponse`, and that
// `fixtureRequest` yields the fixture body+headers with no network. This
// validates the offline test scaffold itself — NOT core crypto behaviors,
// which `packages/core/tests/verify.test.ts` already covers.

import { describe, expect, test } from "bun:test";

import { verifyResponse } from "@ankr.com/vrpc-core";

import { CHAIN_ID, SINGLE_RESULT } from "./fixtures";
import { fixtureRequest } from "./helpers";

describe("offline fixture scaffold", () => {
  test("synthesized SINGLE_RESULT verifies under vrpc-core", async () => {
    const pair = await verifyResponse(
      SINGLE_RESULT.requestBytes,
      SINGLE_RESULT.responseBytes,
      SINGLE_RESULT.headers,
      { chainId: CHAIN_ID, nowMs: SINGLE_RESULT.timestampMs },
    );
    expect(pair.responseBytes).toEqual(SINGLE_RESULT.responseBytes);
    expect(pair.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(pair.verification.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(pair.verification.timestampMs).toBe(SINGLE_RESULT.timestampMs);
  });

  test("fixtureRequest injects the fixture body+headers via getUrlFunc", async () => {
    const req = fixtureRequest(SINGLE_RESULT.responseBytes, SINGLE_RESULT.headers);
    const resp = await req.getUrlFunc(req);
    expect(resp.statusCode).toBe(200);
    expect(resp.body).toEqual(SINGLE_RESULT.responseBytes);
    expect(resp.headers["vRPC-Signature"]).toBe(SINGLE_RESULT.headers["vRPC-Signature"]);
  });
});
