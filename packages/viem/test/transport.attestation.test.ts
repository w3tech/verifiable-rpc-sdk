// E2E always-on attestation suite for vrpcHttp (viem half).
//
// Proves the viem adapter ALWAYS routes the NORMAL verify through the vrpc-core
// `TrustedVerifier` end-to-end against the mock verifier
// (allowInsecureMock is hard-set true by buildVerifyPolicy):
//   1. an unknown signing pubkey triggers the attestation GET exactly once, the
//      mock resolves, the read returns the decoded value, and a second read
//      within TTL skips the fetch (cache proof).
//   2. a signed response WITHOUT `vRPC-NodeId` still verifies: the verifier
//      fetches the attestation WITHOUT a `node_id` query param (the endpoint
//      decides) and the read succeeds.
//   3. the attestation GET targets the `_vrpc/attestation` route derived from the
//      single user URL (deriveVrpcUrls) — no separate attestation base / chain.
//
// A single injected `fetchFn` serves BOTH legs: it signs the RPC POST over the
// EXACT bytes the transport emits (reusing the request-aware fixture signer) and
// answers the attestation GET through the kit's attestation stub. Offline, no
// live network.

import {
  type AttestationStub,
  attestationStub,
  mockHardwareVerifier,
} from "@w3tech.io/vrpc-test-support";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { createPublicClient, defineChain } from "viem";
import { describe, expect, test } from "vitest";
import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";

// Path-ful URL (vRPC route): used verbatim as the rpc route; the attestation
// leg is `${URL}/attestation`.
const URL = "http://test.invalid/arbitrum_vrpc";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
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

interface SeamFetch {
  fetchFn: (url: string, init: RequestInit) => Promise<Response>;
  attestation: AttestationStub;
}

/**
 * Build a single `fetchFn` that branches on the URL: the attestation GET goes to
 * the attestation stub; every other (POST) call signs `init.body` with TEST_SEED
 * and attaches the `vRPC-*` headers (optionally omitting `vRPC-NodeId` to drive
 * the no-node_id path).
 */
function seamFetch(opts: { withNodeId?: boolean } = {}): SeamFetch {
  const withNodeId = opts.withNodeId ?? true;
  const attestation = attestationStub();
  const fetchFn = async (url: string, init: RequestInit): Promise<Response> => {
    if (url.includes("/attestation")) return attestation.fetch(url);
    // RPC POST leg: sign over the EXACT bytes the transport POSTed.
    const requestBytes = init.body as Uint8Array;
    const responseBody = jsonResult(SINGLE_RESULT_BALANCE_HEX);
    const responseBytes = new TextEncoder().encode(responseBody);
    const headers = await signResponseBytes(requestBytes, responseBytes, {
      ...(withNodeId ? { nodeId: NODE_ID } : {}),
    });
    return new Response(responseBody, { status: 200, headers });
  };
  return { fetchFn, attestation };
}

describe("vrpcHttp always-on attestation (viem half)", () => {
  test("routesThroughVerifierAndCaches: unknown pubkey attests once, second read within TTL skips the fetch", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      chain: TEST_CHAIN,
      transport: vrpcHttp(URL, {
        fetchFn: seam.fetchFn,
        replayWindowMs: WIDE_WINDOW,
        hardwareVerifier: mockHardwareVerifier(),
      }),
    });

    // First verified read: mock verifier runs (attestation GET once) + decodes.
    const first = await c.getBalance({ address: ADDR });
    expect(first).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(seam.attestation.urls.length).toBe(1);

    // Second read within TTL: pubkey is cached → NO further attestation GET.
    const second = await c.getBalance({ address: ADDR });
    expect(second).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(seam.attestation.urls.length).toBe(1);
  });

  test("noNodeIdFetchesWithoutRouting: a signed response without vRPC-NodeId verifies (attestation GET carries no node_id)", async () => {
    const seam = seamFetch({ withNodeId: false });
    const transport = vrpcHttp(URL, {
      fetchFn: seam.fetchFn,
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: mockHardwareVerifier(),
    })({ chain: TEST_CHAIN } as never);
    const result = await transport.config.request({
      method: "eth_getBalance",
      params: [ADDR, "latest"],
    });
    expect(result).toBe(SINGLE_RESULT_BALANCE_HEX);
    // The verifier attested without a serving node id → no `node_id` query param.
    expect(seam.attestation.urls.length).toBe(1);
    expect(seam.attestation.urls.at(-1)).not.toContain("node_id");
  });

  test("derivedAttestationRoute: the attestation GET targets the `/attestation` route from the single URL", async () => {
    const seam = seamFetch();
    const c = createPublicClient({
      chain: TEST_CHAIN,
      transport: vrpcHttp(URL, {
        fetchFn: seam.fetchFn,
        replayWindowMs: WIDE_WINDOW,
        hardwareVerifier: mockHardwareVerifier(),
      }),
    });
    await c.getBalance({ address: ADDR });
    expect(seam.attestation.urls.length).toBe(1);
    expect(seam.attestation.urls.at(-1)).toContain(`${URL}/attestation`);
    expect(seam.attestation.urls.at(-1)).toContain(`node_id=${NODE_ID}`);
  });
});
