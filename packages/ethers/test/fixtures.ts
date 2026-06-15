// Offline signed-response fixture synthesizer for the vrpc-ethers adapter tests
// (TEST-02, Wave 0 of Phase 30).
//
// This module PRODUCES bytes + `vRPC-*` headers that `@ankr.com/vrpc-core`
// `verifyResponse` accepts — it does NOT re-test core crypto. It mirrors the
// `signTriple` helper in core's `tests/verify.test.ts` exactly: Ed25519 over the
// canonical 80-byte pre-image built by `buildPreImage`, signed with a single
// fixed `TEST_SEED` so the matching pubkey is deterministic across runs.
//
// Plan 30-02's `provider.test.ts` consumes these fixtures to exercise
// `VrpcProvider._send` against synthesized signed bytes with NO live network.

import { buildPreImage } from "@ankr.com/vrpc-core";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";

/**
 * Fixed 32-byte Ed25519 seed — the literal seed used in core's `verify.test.ts`
 * so the derived pubkey is stable and recognizable across both test suites.
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
 * 30-02 neutralizes staleness by passing `nowMs: FIXTURE_TIMESTAMP_MS` (or a
 * wide `replayWindowMs`) to `verifyResponse`.
 */
export const FIXTURE_TIMESTAMP_MS = 1_700_000_000_000n;

/** Lowercase hex encode, no `0x` prefix. */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

export interface Fixture {
  /** Request body bytes, exactly as signed (= `buildPreImage` request input). */
  requestBytes: Uint8Array;
  /** Response body bytes, exactly as signed. */
  responseBytes: Uint8Array;
  /** Signed `vRPC-*` triple (+ `content-type`); unsigned fixture omits the triple. */
  headers: Record<string, string>;
  /** The exact `timestampMs` the triple was signed over. */
  timestampMs: bigint;
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
 * Sign a `(requestBody, responseBody)` pair with `TEST_SEED` over the canonical
 * 80-byte pre-image and emit the matching `vRPC-*` headers. Mirrors core's
 * `signTriple`. No fetch, no ethers — pure synthesis.
 */
export async function signFixture(
  requestBody: string,
  responseBody: string,
  opts: SignFixtureOptions = {},
): Promise<Fixture> {
  const chainId = opts.chainId ?? CHAIN_ID;
  const timestampMs = opts.timestampMs ?? FIXTURE_TIMESTAMP_MS;
  const requestBytes = new TextEncoder().encode(requestBody);
  const responseBytes = new TextEncoder().encode(responseBody);
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
  return { requestBytes, responseBytes, headers, timestampMs };
}

// ---------------------------------------------------------------------------
// The five static fixtures. All sign with the single fixed TEST_SEED, so the
// matching pubkey is deterministic. Synthesized eagerly at module load.
// ---------------------------------------------------------------------------

/**
 * Known decoded balance carried by SINGLE_RESULT — 30-02 asserts
 * `getBalance(...)` returns this quantity. `0x1bc16d674ec80000` = 2 ETH (wei).
 */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";

/** Single signed `eth_getBalance` result. */
export const SINGLE_RESULT: Fixture = await signFixture(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBalance",
    params: ["0x1111111111111111111111111111111111111111", "latest"],
  }),
  JSON.stringify({ jsonrpc: "2.0", id: 1, result: SINGLE_RESULT_BALANCE_HEX }),
);

/** Signed JSON-RPC batch: array of two payloads (ids 1, 2), signed once over the whole body. */
export const BATCH_ARRAY: Fixture = await signFixture(
  JSON.stringify([
    { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "eth_getBalance",
      params: ["0x2222222222222222222222222222222222222222", "latest"],
    },
  ]),
  JSON.stringify([
    { jsonrpc: "2.0", id: 1, result: "0x10d4f" },
    { jsonrpc: "2.0", id: 2, result: SINGLE_RESULT_BALANCE_HEX },
  ]),
);

/** Signed JSON-RPC error envelope (execution reverted). */
export const SIGNED_RPC_ERROR: Fixture = await signFixture(
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [] }),
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32000, message: "execution reverted" },
  }),
);

/** Signed `{result:null}` (e.g. getBlock of a missing block). */
export const SIGNED_NULL_RESULT: Fixture = await signFixture(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBlockByNumber",
    params: ["0xffffffff", false],
  }),
  JSON.stringify({ jsonrpc: "2.0", id: 1, result: null }),
);

/**
 * Unsigned response: SINGLE_RESULT's bytes, but headers carry only
 * `content-type` (the `vRPC-*` triple removed) to drive the strict-mode
 * `MissingHeader` fail-closed path in 30-02.
 */
export const UNSIGNED: Fixture = {
  requestBytes: SINGLE_RESULT.requestBytes,
  responseBytes: SINGLE_RESULT.responseBytes,
  headers: { "content-type": "application/json" },
  timestampMs: SINGLE_RESULT.timestampMs,
};
