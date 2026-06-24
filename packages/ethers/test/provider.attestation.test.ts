// TEST-03 — VrpcProvider E2E always-on lazy-attestation suite (ethers half).
//
// Verification is ALWAYS on: every VrpcProvider runs the TrustedVerifier (plain
// Ed25519 verify + lazy TDX attestation). This suite proves the attestation leg
// end-to-end against the Phase-33 mock verifier (allowInsecureMock hard-set true
// by buildVerifyPolicy in vrpc-core):
//   - an unknown signing pubkey → the attestation GET is hit ONCE, the mock
//     verifier resolves, the call returns the decoded value, and a second call
//     within TTL skips the fetch (cache proof, FLOW-04).
//   - a signed response WITHOUT `vRPC-NodeId` against a shark-style route that
//     requires `node_id` → the attestation fetch 404s → fail-closed (the
//     no-node_id path: the endpoint decides, the error propagates).
//   - a signed response WITHOUT `vRPC-NodeId` against a direct node (the route
//     resolves without `node_id`) → still verifies (no-node_id is not a hard
//     error; the endpoint decides).
//
// Offline: the RPC POST leg is served by the request-aware `signingRequest`
// fetch-mock; the `/attestation` GET leg by the injected `fetch` option
// (`installAttestationMock`). No live network.

import { VrpcProvider } from "@ankr.com/vrpc-ethers";
import { getPublicKeyAsync } from "@noble/ed25519";
import { describe, expect, test } from "vitest";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, TEST_SEED } from "./fixtures";
import { type AttMockState, installAttestationMock, signingRequest } from "./helpers";

const CHAIN_ID_NUMBER = Number(CHAIN_ID); // 42161 (arbitrum)
const ADDR = "0x1111111111111111111111111111111111111111";
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness.
const WIDE = Number.MAX_SAFE_INTEGER;
const NODE_ID = "node-abc";

function jsonResult(id: number, result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

/** Construct a VrpcProvider whose RPC leg is the signing mock + injected attestation fetch. */
function vrpcProviderWith(mock: AttMockState, signOpts: { nodeId?: string }): VrpcProvider {
  return new VrpcProvider(
    signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), signOpts),
    CHAIN_ID_NUMBER,
    {
      fetch: mock.fetch,
      replayWindowMs: WIDE,
    },
  );
}

describe("VrpcProvider always-on attestation E2E (TEST-03)", () => {
  test("attestsOnceAndCaches: unknown pubkey attests once, second call within TTL skips fetch", async () => {
    const mock = installAttestationMock();
    const provider = vrpcProviderWith(mock, { nodeId: NODE_ID });

    const first = await provider.getBalance(ADDR);
    expect(first).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // mock verifier ran → value decoded
    expect(mock.attGetCount).toBe(1);

    const second = await provider.getBalance(ADDR);
    expect(second).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.attGetCount).toBe(1); // cache hit → no extra attestation fetch
  });

  test("missingNodeIdShark: signed response without vRPC-NodeId against a shark route fails closed", async () => {
    // Shark route requires `node_id`; the signed response carries none → the
    // attestation fetch lacks `node_id` → 404 → AttestationNodeNotFoundError
    // propagates (fail-closed; no unverified data returned).
    const mock = installAttestationMock({ requireNodeId: true });
    const provider = vrpcProviderWith(mock, {});
    await expect(provider.getBalance(ADDR)).rejects.toThrow();
    expect(mock.attGetCount).toBe(1); // the fetch WAS attempted (the route 404'd)
  });

  test("missingNodeIdDirectNode: signed response without vRPC-NodeId against a direct node still verifies", async () => {
    // Direct node: the route resolves WITHOUT `node_id`. The no-node_id fetch
    // succeeds → the mock verifier resolves → the verified value is returned.
    const mock = installAttestationMock();
    const provider = vrpcProviderWith(mock, {});
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.attGetCount).toBe(1);
  });

  test("connectionAuthReachesAttestation: x-api-key set on the FetchRequest authenticates the attestation leg", async () => {
    // Regression: the auth header set on the RPC connection (FetchRequest) MUST
    // also reach the attestation GET — parity with viem's `headers`. Without the
    // fix the attestation leg went out unauthenticated and a shark route rejected
    // it. Capture the headers the attestation fetch receives and assert the key.
    let attHeaders: Headers | undefined;
    const attPubkey = await getPublicKeyAsync(TEST_SEED);
    const pubkeyHex = `0x${Array.from(attPubkey, (b) => b.toString(16).padStart(2, "0")).join("")}`;
    const capturingFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).includes("/attestation")) {
        attHeaders = new Headers(init?.headers);
        // CHK-A1: report_data = pubkey(bare) ‖ nonce(bare); echo the `?nonce=`
        // query so the binding + 128-hex shape gate pass.
        const nonceHex = new URL(String(input)).searchParams.get("nonce") ?? "";
        const reportData = `${pubkeyHex.slice(2)}${nonceHex}`;
        return new Response(
          JSON.stringify({
            quote: { quote: "00", event_log: "00", report_data: reportData, vm_config: "" },
            pubkey: pubkeyHex,
            composeHash: "deadbeef",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected fetch: ${String(input)}`);
    }) as typeof fetch;

    const req = signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID });
    req.setHeader("x-api-key", "regression-key");
    // No apiKey/headers option — auth comes ONLY from the FetchRequest, like a
    // consumer who sets x-api-key once on the connection.
    const provider = new VrpcProvider(req, CHAIN_ID_NUMBER, {
      fetch: capturingFetch,
      replayWindowMs: WIDE,
    });

    await provider.getBalance(ADDR);
    expect(attHeaders?.get("x-api-key")).toBe("regression-key");
  });
});
