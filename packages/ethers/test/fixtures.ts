// Signed-response fixtures for the vrpc-ethers adapter tests.

import { signResponse } from "@w3tech.io/vrpc-test-support";

/**
 * Chain id bound into every fixture's pre-image (arbitrum — matches
 * `examples/shared.ts` conventions). Exported so tests pass it to
 * `verifyResponse({ chainId: CHAIN_ID })`. Decimal string — the exact value the
 * sidecar is configured with and hashes into the pre-image.
 */
export const CHAIN_ID = "42161";

/** Fixed signing timestamp (unix ms) so fixtures are byte-stable across runs. */
const FIXTURE_TIMESTAMP_MS = 1_700_000_000_000n;

export interface Fixture {
  /** Request body bytes, exactly as signed (= `buildPreImage` request input). */
  requestBytes: Uint8Array;
  /** Response body bytes, exactly as signed. */
  responseBytes: Uint8Array;
  /** Signed `vRPC-*` triple plus `content-type`. */
  headers: Record<string, string>;
  /** The exact `timestampMs` the triple was signed over. */
  timestampMs: bigint;
}

export interface SignFixtureOptions {
  chainId?: string;
  timestampMs?: bigint;
  signingChainId?: string;
  nodeId?: string;
}

/** `vRPC-*` headers plus `content-type` signing the pair with `TEST_SEED`. */
export async function signResponseBytes(
  requestBytes: Uint8Array,
  responseBytes: Uint8Array,
  opts: SignFixtureOptions = {},
): Promise<Record<string, string>> {
  return {
    "content-type": "application/json",
    ...signResponse(opts.signingChainId ?? opts.chainId ?? CHAIN_ID, requestBytes, responseBytes, {
      timestampMs: opts.timestampMs,
      nodeId: opts.nodeId,
    }),
  };
}

// ---------------------------------------------------------------------------
// The static fixture. Signed with the fixed TEST_SEED, so the matching pubkey is
// deterministic. Synthesized eagerly at module load.
// ---------------------------------------------------------------------------

/** Known decoded balance carried by SINGLE_RESULT. `0x1bc16d674ec80000` = 2 ETH (wei). */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";

const singleRequestBytes = new TextEncoder().encode(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBalance",
    params: ["0x1111111111111111111111111111111111111111", "latest"],
  }),
);
const singleResponseBytes = new TextEncoder().encode(
  JSON.stringify({ jsonrpc: "2.0", id: 1, result: SINGLE_RESULT_BALANCE_HEX }),
);

/** Single signed `eth_getBalance` result. */
export const SINGLE_RESULT: Fixture = {
  requestBytes: singleRequestBytes,
  responseBytes: singleResponseBytes,
  headers: await signResponseBytes(singleRequestBytes, singleResponseBytes, {
    timestampMs: FIXTURE_TIMESTAMP_MS,
  }),
  timestampMs: FIXTURE_TIMESTAMP_MS,
};
