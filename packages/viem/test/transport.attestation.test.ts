// TEST-03 (viem half) — E2E lazy-attestation suite for vrpcHttp (Phase 35).
//
// Proves the viem adapter routes the NORMAL verify through the vrpc-core
// `TrustedVerifier` seam end-to-end against the Phase-33 mock verifier
// (allowInsecureMock is hard-set true by buildVerifyPolicy):
//   1. an unknown signing pubkey triggers the attestation GET exactly once, the
//      mock resolves, the read returns the decoded value, and a second read
//      within TTL skips the fetch (cache proof — FLOW-04).
//   2. a signed response missing `vRPC-NodeId` fails closed on the miss path
//      (MissingHeader, a VerificationError).
//   3. WITHOUT sharkBase/chain the seam never engages → no attestation GET
//      (opt-in proof).
//
// A single injected `fetchFn` serves BOTH legs: it signs the RPC POST over the
// EXACT bytes the transport emits (reusing the request-aware fixture signer) and
// answers the attestation GET with a correlated-pubkey body (the same shape as
// core/tests/trust.test.ts installAttestationMock). Offline, no live network.

import { describe, expect, test } from "bun:test";
import { MissingHeader, vrpcHttp } from "@ankr.com/vrpc-viem";
import { getPublicKeyAsync } from "@noble/ed25519";
import { createPublicClient } from "viem";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";

const URL = "http://test.invalid";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
// Fixed seed used by the fixture signer — its pubkey is what the attestation
// body must correlate to.
const TEST_SEED = new Uint8Array(32).fill(0x42);
const SHARK_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const NODE_ID = "node-abc";
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness.
const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;

function jsonResult(result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, result });
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

interface SeamFetch {
  fetchFn: (url: string, init: RequestInit) => Promise<Response>;
  attGetCount: number;
}

/**
 * Build a single `fetchFn` that branches on the URL: the attestation GET returns
 * a body whose `pubkey` correlates to TEST_SEED (same shape as the core mock);
 * every other (POST) call signs `init.body` with TEST_SEED and attaches the
 * `vRPC-*` headers (optionally omitting `vRPC-NodeId` to drive the fail-closed
 * miss path). Counts attestation GETs for the cache proof.
 */
function seamFetch(opts: { withNodeId?: boolean } = {}): SeamFetch {
  const withNodeId = opts.withNodeId ?? true;
  const state: SeamFetch = {
    fetchFn: (() => {}) as unknown as SeamFetch["fetchFn"],
    attGetCount: 0,
  };
  state.fetchFn = async (url, init) => {
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
    // RPC POST leg: sign over the EXACT bytes the transport POSTed.
    const bodyStr = init.body as string;
    const requestBytes = new TextEncoder().encode(bodyStr);
    const responseBody = jsonResult(SINGLE_RESULT_BALANCE_HEX);
    const responseBytes = new TextEncoder().encode(responseBody);
    const headers = await signResponseBytes(requestBytes, responseBytes, {
      ...(withNodeId ? { nodeId: NODE_ID } : {}),
    });
    return new Response(responseBody, { status: 200, headers });
  };
  return state;
}

describe("vrpcHttp lazy-attestation seam (TEST-03, viem half)", () => {
  test("routesThroughSeamAndCaches: unknown pubkey attests once, second read within TTL skips the fetch", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      transport: vrpcHttp(URL, {
        chainId: CHAIN_ID,
        attestationBaseUrl: SHARK_BASE,
        chainSlug: CHAIN,
        fetchFn: seam.fetchFn,
        replayWindowMs: WIDE_WINDOW,
      }),
    });

    // First verified read: mock verifier runs (attestation GET once) + decodes.
    const first = await c.getBalance({ address: ADDR });
    expect(first).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(seam.attGetCount).toBe(1);

    // Second read within TTL: pubkey is cached → NO further attestation GET.
    const second = await c.getBalance({ address: ADDR });
    expect(second).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(seam.attGetCount).toBe(1);
  });

  test("missingNodeIdFailsClosed: a signed response without vRPC-NodeId rejects on the miss path", async () => {
    const seam = seamFetch({ withNodeId: false });
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      attestationBaseUrl: SHARK_BASE,
      chainSlug: CHAIN,
      fetchFn: seam.fetchFn,
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MissingHeader);
  });

  test("optInOnlyNoSeamWithoutConfig: without sharkBase/chain a verified read never hits the attestation GET", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      transport: vrpcHttp(URL, {
        chainId: CHAIN_ID,
        fetchFn: seam.fetchFn,
        replayWindowMs: WIDE_WINDOW,
      }),
    });
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(seam.attGetCount).toBe(0);
  });
});
