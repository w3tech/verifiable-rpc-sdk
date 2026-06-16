// TEST-03 — VrpcProvider E2E lazy-attestation suite (Phase 35, ethers half).
//
// Proves the opt-in seam path end-to-end against the Phase-33 mock verifier
// (allowInsecureMock hard-set true by buildVerifyPolicy in vrpc-core):
//   - unknown signing pubkey → the attestation GET is hit ONCE, the mock
//     verifier resolves, the call returns the decoded value, and a second call
//     within TTL skips the fetch (cache proof, FLOW-04).
//   - a signed response missing `vRPC-NodeId` fails closed (MissingHeader) on
//     the miss path (downgrade-resistance).
//   - constructing WITHOUT sharkBase/chain never hits the attestation GET
//     (opt-in routing proof).
//
// Offline: the RPC POST leg is served by the request-aware `signingRequest`
// fetch-mock (existing helper); the `/attestation` GET leg by the injected
// `fetch` option. No live network.

import { describe, expect, test } from "bun:test";
import { MissingHeader, VrpcProvider } from "@ankr.com/vrpc-ethers";
import { getPublicKeyAsync } from "@noble/ed25519";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX } from "./fixtures";
import { signingRequest } from "./helpers";

const CHAIN_ID_NUMBER = Number(CHAIN_ID); // 42161 (arbitrum)
const ADDR = "0x1111111111111111111111111111111111111111";
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness.
const WIDE = Number.MAX_SAFE_INTEGER;
const SHARK_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const TEST_SEED = new Uint8Array(32).fill(0x42); // same seed the fixtures sign with

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function jsonResult(id: number, result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

interface AttMockState {
  fetch: typeof fetch;
  attGetCount: number;
}

/**
 * Mock ONLY the attestation GET leg. The returned `pubkey` is derived from the
 * SAME TEST_SEED the RPC response is signed with, so the seam's pubkey
 * correlation passes. Counts how many times `/attestation` is fetched.
 */
function installAttestationMock(): AttMockState {
  const state: AttMockState = { fetch: (() => {}) as unknown as typeof fetch, attGetCount: 0 };
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
      const attPubkey = await getPublicKeyAsync(TEST_SEED);
      const body = {
        quote: { quote: "00", event_log: "00", report_data: "00", vm_config: "" },
        pubkey: `0x${toHex(attPubkey)}`,
        composeHash: "deadbeef",
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
  state.fetch = impl as typeof fetch;
  return state;
}

describe("VrpcProvider lazy-attestation E2E (TEST-03)", () => {
  test("routesThroughSeamAndCaches: unknown pubkey attests once, second call within TTL skips fetch", async () => {
    const mock = installAttestationMock();
    const provider = new VrpcProviderWith(mock, { nodeId: "node-abc" });

    const first = await provider.getBalance(ADDR);
    expect(first).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // mock verifier ran → value decoded
    expect(mock.attGetCount).toBe(1);

    const second = await provider.getBalance(ADDR);
    expect(second).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.attGetCount).toBe(1); // cache hit → no extra attestation fetch
  });

  test("missingNodeIdFailsClosed: a signed response without vRPC-NodeId rejects on the miss path", async () => {
    const mock = installAttestationMock();
    // No nodeId on the signed response → the seam's miss path throws MissingHeader.
    const provider = new VrpcProviderWith(mock, {});
    await expect(provider.getBalance(ADDR)).rejects.toBeInstanceOf(MissingHeader);
    expect(mock.attGetCount).toBe(0); // fail-closed before any fetch
  });

  test("optInOnlyNoSeamWithoutConfig: no sharkBase/chain → attestation GET never hit", async () => {
    const mock = installAttestationMock();
    // Seam NOT engaged (no sharkBase/chain); a verified read uses plain
    // verifyResponse and never touches the attestation leg.
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: "node-abc" }),
      CHAIN_ID_NUMBER,
      { replayWindowMs: WIDE, fetch: mock.fetch },
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(mock.attGetCount).toBe(0);
  });
});

// ── local helpers ──────────────────────────────────────────────────────────

/** Construct a seam-engaged VrpcProvider whose RPC leg is the signing mock. */
function VrpcProviderWith(mock: AttMockState, signOpts: { nodeId?: string }): VrpcProvider {
  return new VrpcProvider(
    signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), signOpts),
    CHAIN_ID_NUMBER,
    {
      sharkBase: SHARK_BASE,
      chain: CHAIN,
      fetch: mock.fetch,
      replayWindowMs: WIDE,
    },
  );
}
