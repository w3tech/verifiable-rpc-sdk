// VrpcProvider E2E always-on lazy-attestation suite (ethers half).
//
// Verification is ALWAYS on: every VrpcProvider runs the TrustedVerifier (plain
// Ed25519 verify + lazy TDX attestation). This suite proves the attestation leg
// end-to-end against the mock verifier (allowInsecureMock hard-set true
// by buildVerifyPolicy in vrpc-core):
//   - an unknown signing pubkey → the attestation GET is hit ONCE, the mock
//     verifier resolves, the call returns the decoded value, and a second call
//     within TTL skips the fetch (cache proof).
//   - a signed response WITHOUT `vRPC-NodeId` against a gateway-style route that
//     requires `node_id` → the attestation fetch 404s → fail-closed (the
//     no-node_id path: the endpoint decides, the error propagates).
//   - a signed response WITHOUT `vRPC-NodeId` against a direct node (the route
//     resolves without `node_id`) → still verifies (no-node_id is not a hard
//     error; the endpoint decides).
//
// Offline: the RPC POST leg is served by the request-aware `signingRequest`
// fetch-mock; the `/attestation` GET leg by the injected `fetch` option
// (`attestationStub`). No live network.

import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
import {
  type AttestationStub,
  attestationAnswer,
  attestationStub,
  CHAIN_ID,
  mockHardwareVerifier,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import { jsonResult, SINGLE_RESULT_BALANCE_HEX, WIDE_WINDOW } from "./fixtures";
import { signingRequest } from "./helpers";

const CHAIN_ID_NUMBER = Number(CHAIN_ID); // 42161 (arbitrum)
const ADDR = "0x1111111111111111111111111111111111111111";
const NODE_ID = "node-abc";

/** Construct a VrpcProvider whose RPC leg is the signing mock + injected attestation fetch. */
function vrpcProviderWith(mock: AttestationStub, signOpts: { nodeId?: string }): VrpcProvider {
  return new VrpcProvider(
    signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), signOpts),
    CHAIN_ID_NUMBER,
    {
      fetch: mock.fetch,
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: mockHardwareVerifier(),
    },
  );
}

describe("VrpcProvider always-on attestation E2E", () => {
  test("attestsOnceAndCaches: unknown pubkey attests once, second call within TTL skips fetch", async () => {
    const mock = attestationStub();
    const provider = vrpcProviderWith(mock, { nodeId: NODE_ID });

    const first = await provider.getBalance(ADDR);
    expect(first).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // mock verifier ran → value decoded
    expect(mock.urls.length).toBe(1);

    const second = await provider.getBalance(ADDR);
    expect(second).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.urls.length).toBe(1); // cache hit → no extra attestation fetch
  });

  test("missingNodeIdGateway: signed response without vRPC-NodeId against a gateway route fails closed", async () => {
    // Gateway route requires `node_id`; the signed response carries none → the
    // attestation fetch lacks `node_id` → 404 → AttestationNodeNotFoundError
    // propagates (fail-closed; no unverified data returned).
    const mock = attestationStub({ requireNodeId: true });
    const provider = vrpcProviderWith(mock, {});
    await expect(provider.getBalance(ADDR)).rejects.toThrow();
    expect(mock.urls.length).toBe(1); // the fetch WAS attempted (the route 404'd)
  });

  test("missingNodeIdDirectNode: signed response without vRPC-NodeId against a direct node still verifies", async () => {
    // Direct node: the route resolves WITHOUT `node_id`. The no-node_id fetch
    // succeeds → the mock verifier resolves → the verified value is returned.
    const mock = attestationStub();
    const provider = vrpcProviderWith(mock, {});
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.urls.length).toBe(1);
  });

  test("connectionAuthReachesAttestation: x-api-key set on the FetchRequest authenticates the attestation leg", async () => {
    // Regression: the auth header set on the RPC connection (FetchRequest) MUST
    // also reach the attestation GET — parity with viem's `headers`. Without the
    // fix the attestation leg went out unauthenticated and a gateway route rejected
    // it. Capture the headers the attestation fetch receives and assert the key.
    let attHeaders: Headers | undefined;
    const capturingFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).includes("/attestation")) {
        attHeaders = new Headers(init?.headers);
        return attestationAnswer(String(input));
      }
      throw new Error(`unexpected fetch: ${String(input)}`);
    }) as typeof fetch;

    const req = signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID });
    req.setHeader("x-api-key", "regression-key");
    // No apiKey/headers option — auth comes ONLY from the FetchRequest, like a
    // consumer who sets x-api-key once on the connection.
    const provider = new VrpcProvider(req, CHAIN_ID_NUMBER, {
      fetch: capturingFetch,
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: mockHardwareVerifier(),
    });

    await provider.getBalance(ADDR);
    expect(attHeaders?.get("x-api-key")).toBe("regression-key");
  });
});
