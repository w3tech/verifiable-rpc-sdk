// Offline signed-response fixture synthesizer for the vrpc-viem adapter tests.
//
// This module PRODUCES bytes + `vRPC-*` headers that `@ankr.com/vrpc-core`
// `verifyResponse` accepts — it does NOT re-test core crypto. It mirrors the
// request-aware `signResponseBytes` helper in `packages/ethers/test/fixtures.ts`:
// Ed25519 over the canonical 80-byte pre-image built by `buildPreImage`, signed
// with a single fixed `TEST_SEED` so the matching pubkey is deterministic.
//
// Unlike the ethers mirror, the eagerly-synthesized static `Fixture` objects and
// the fixed-request `signFixture` variant are DROPPED: viem's body encoding
// (key order, id counter, resolved blockTag) differs from ethers, so the viem
// suite signs ONLY over the EXACT request bytes the transport actually POSTs via
// the request-aware `signResponseBytes`. The wiring suite consumes this
// against a real `createPublicClient` read path with NO live network.

import { buildPreImage } from "@ankr.com/vrpc-core";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";

/**
 * Fixed 32-byte Ed25519 seed — the literal seed used in core's `verify.test.ts`
 * so the derived pubkey is stable and recognizable across test suites.
 */
const TEST_SEED = new Uint8Array(32).fill(0x42);

/**
 * Chain id bound into every fixture's pre-image (arbitrum — matches
 * `examples/shared.ts` conventions). Exported so tests pass it to
 * `verifyResponse({ chainId: CHAIN_ID })`.
 */
export const CHAIN_ID = 42161n;

/**
 * Fixed signing timestamp (unix ms) so fixtures are byte-stable across runs.
 * 31-02 neutralizes staleness by passing `nowMs: FIXTURE_TIMESTAMP_MS` (or a
 * wide `replayWindowMs`) to `verifyResponse`.
 */
export const FIXTURE_TIMESTAMP_MS = 1_700_000_000_000n;

/**
 * Known decoded balance a signed `eth_getBalance` fixture carries —
 * `0x1bc16d674ec80000` = 2 ETH (wei). 31-02 asserts a read returns this.
 */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";

/** Lowercase hex encode, no `0x` prefix. */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

export interface SignFixtureOptions {
  /** Chain id bound into the pre-image AND used for signing. Defaults to `CHAIN_ID`. */
  chainId?: bigint;
  /** Signed timestamp. Defaults to `FIXTURE_TIMESTAMP_MS`. */
  timestampMs?: bigint;
  /**
   * Chain id used ONLY for signing (to forge a chain-id-mismatch fixture whose
   * signature is valid but verifies against a different chain). Defaults to
   * `chainId`.
   */
  signingChainId?: bigint;
  /** Optional `vRPC-NodeId` header value. */
  nodeId?: string;
}

/**
 * Sign an arbitrary `(requestBytes, responseBytes)` pair with `TEST_SEED` and
 * return the matching `vRPC-*` headers. Signs over the EXACT request bytes a
 * transport actually emitted — used by the request-aware seam so a real
 * viem `readContract`/`getBalance` payload (whose key order, id counter and
 * resolved blockTag are viem-internal) verifies without the fixture having to
 * predict those bytes. The wiring under test is the transport → `verifyResponse`,
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
