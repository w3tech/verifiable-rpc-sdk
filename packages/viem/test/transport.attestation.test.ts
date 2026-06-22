// TEST-03 (viem half) — E2E always-on attestation suite for vrpcHttp.
//
// Proves the viem adapter ALWAYS routes the NORMAL verify through the vrpc-core
// `TrustedVerifier` end-to-end against the Phase-33 mock verifier
// (allowInsecureMock is hard-set true by buildVerifyPolicy):
//   1. an unknown signing pubkey triggers the attestation GET exactly once, the
//      mock resolves, the read returns the decoded value, and a second read
//      within TTL skips the fetch (cache proof — FLOW-04).
//   2. a signed response WITHOUT `vRPC-NodeId` still verifies: the verifier
//      fetches the attestation WITHOUT a `node_id` query param (the endpoint
//      decides) and the read succeeds.
//   3. the attestation GET targets the `_vrpc/attestation` route derived from the
//      single user URL (deriveVrpcUrls) — no separate attestation base / chain.
//
// A single injected `fetchFn` serves BOTH legs: it signs the RPC POST over the
// EXACT bytes the transport emits (reusing the request-aware fixture signer) and
// answers the attestation GET with a correlated-pubkey body (the same shape as
// core/tests/trusted-verifier.test.ts installAttestationMock). Offline, no live
// network.

import { vrpcHttp } from "@ankr.com/vrpc-viem";
import { getPublicKeyAsync } from "@noble/ed25519";
import { createPublicClient, defineChain } from "viem";
import { describe, expect, test } from "vitest";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";

const URL = "http://test.invalid";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
// Fixed seed used by the fixture signer — its pubkey is what the attestation
// body must correlate to.
const TEST_SEED = new Uint8Array(32).fill(0x42);
const NODE_ID = "node-abc";
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness.
const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;
// chainId is pinned via the viem client's `chain` (`chain.id`), not an option;
// TEST_CHAIN pins CHAIN_ID so these tests skip the eth_chainId bootstrap.
const TEST_CHAIN = defineChain({
  id: Number(CHAIN_ID),
  name: "vrpc-test",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [URL] } },
});

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
  /** Last attestation GET URL — asserts the derived `_vrpc/attestation` route. */
  lastAttUrl: string | undefined;
}

/**
 * Build a single `fetchFn` that branches on the URL: the attestation GET returns
 * a body whose `pubkey` correlates to TEST_SEED (same shape as the core mock);
 * every other (POST) call signs `init.body` with TEST_SEED and attaches the
 * `vRPC-*` headers (optionally omitting `vRPC-NodeId` to drive the no-node_id
 * path). Counts attestation GETs for the cache proof and records the last GET URL.
 */
function seamFetch(opts: { withNodeId?: boolean } = {}): SeamFetch {
  const withNodeId = opts.withNodeId ?? true;
  const state: SeamFetch = {
    fetchFn: (() => {}) as unknown as SeamFetch["fetchFn"],
    attGetCount: 0,
    lastAttUrl: undefined,
  };
  state.fetchFn = async (url, init) => {
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
      state.lastAttUrl = url;
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

describe("vrpcHttp always-on attestation (TEST-03, viem half)", () => {
  test("routesThroughVerifierAndCaches: unknown pubkey attests once, second read within TTL skips the fetch", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      chain: TEST_CHAIN,
      transport: vrpcHttp(URL, {
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

  test("noNodeIdFetchesWithoutRouting: a signed response without vRPC-NodeId verifies (attestation GET carries no node_id)", async () => {
    const seam = seamFetch({ withNodeId: false });
    const transport = vrpcHttp(URL, {
      fetchFn: seam.fetchFn,
      replayWindowMs: WIDE_WINDOW,
    })({ chain: TEST_CHAIN } as never);
    const result = await transport.config.request({
      method: "eth_getBalance",
      params: [ADDR, "latest"],
    });
    expect(result).toBe(SINGLE_RESULT_BALANCE_HEX);
    // The verifier attested without a serving node id → no `node_id` query param.
    expect(seam.attGetCount).toBe(1);
    expect(seam.lastAttUrl).not.toContain("node_id");
  });

  test("derivedAttestationRoute: the attestation GET targets the `_vrpc/attestation` route from the single URL", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      chain: TEST_CHAIN,
      transport: vrpcHttp(URL, {
        fetchFn: seam.fetchFn,
        replayWindowMs: WIDE_WINDOW,
      }),
    });
    await c.getBalance({ address: ADDR });
    expect(seam.attGetCount).toBe(1);
    expect(seam.lastAttUrl).toContain(`${URL}_vrpc/attestation`);
    expect(seam.lastAttUrl).toContain(`node_id=${NODE_ID}`);
  });
});
