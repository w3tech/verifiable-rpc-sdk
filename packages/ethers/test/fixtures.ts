// Offline signed-response fixture synthesizer for the vrpc-ethers adapter tests.
//
// This module PRODUCES bytes + `vRPC-*` headers that `@w3tech.io/vrpc-core`
// `verifyResponse` accepts — it does NOT re-test core crypto. It mirrors the
// `signTriple` helper in core's `tests/verify.test.ts` exactly: Ed25519 over the
// canonical 104-byte pre-image built by `buildPreImage`, signed with a single
// fixed `TEST_SEED` so the matching pubkey is deterministic across runs.
//
// `provider.test.ts` consumes these fixtures to exercise
// `VrpcProvider._send` against synthesized signed bytes with NO live network.

import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { buildPreImage } from "@w3tech.io/vrpc-core";
import { TEST_SEED, toHex } from "@w3tech.io/vrpc-test-support";

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
  /** Chain id bound into the pre-image AND used for signing. Defaults to `CHAIN_ID`. */
  chainId?: string;
  /** Signed timestamp. Defaults to `FIXTURE_TIMESTAMP_MS`. */
  timestampMs?: bigint;
  /**
   * Chain id used ONLY for signing (to forge a chain-id-mismatch fixture whose
   * signature is valid but verifies against a different chain). Defaults to
   * `chainId`.
   */
  signingChainId?: string;
  /** Optional `vRPC-NodeId` header value. */
  nodeId?: string;
}

/**
 * Sign an arbitrary `(requestBytes, responseBytes)` pair with `TEST_SEED` over
 * the canonical 104-byte pre-image and return the matching `vRPC-*` headers.
 * Mirrors core's `signTriple`. Signs over the EXACT request bytes a transport
 * actually emitted — used by the request-aware `getUrlFunc` so a real
 * ethers `getBalance`/Contract payload (whose key order, id counter and
 * resolved blockTag are ethers-internal) verifies without the fixture having to
 * predict those bytes. The wiring under test is `_send` → `verifyResponse`,
 * not pre-image construction (that is core's verify suite).
 */
export async function signResponseBytes(
  requestBytes: Uint8Array,
  responseBytes: Uint8Array,
  opts: SignFixtureOptions = {},
): Promise<Record<string, string>> {
  const chainId = opts.chainId ?? CHAIN_ID;
  const timestampMs = opts.timestampMs ?? FIXTURE_TIMESTAMP_MS;
  const preImage = buildPreImage(
    opts.signingChainId ?? chainId,
    requestBytes,
    responseBytes,
    timestampMs,
  );
  const signature = await signAsync(preImage, TEST_SEED);
  const pubkey = await getPublicKeyAsync(TEST_SEED);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "vRPC-Signature": `0x${toHex(signature)}`,
    "vRPC-Timestamp": timestampMs.toString(),
    "vRPC-Pubkey": `0x${toHex(pubkey)}`,
  };
  if (opts.nodeId !== undefined) {
    headers["vRPC-NodeId"] = opts.nodeId;
  }
  return headers;
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
  headers: await signResponseBytes(singleRequestBytes, singleResponseBytes),
  timestampMs: FIXTURE_TIMESTAMP_MS,
};
