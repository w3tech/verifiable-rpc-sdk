// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Canonical 80-byte pre-image builder. Mirrors `verifiable-rpc-sidecar/src/signing.rs::build_pre_image`.
//
// Layout (byte-exact, MUST match sidecar):
//   [0..8]   chain_id      u64 little-endian
//   [8..40]  request_hash  sha256(request_body) — 32 bytes
//   [40..72] response_hash sha256(response_body) — 32 bytes
//   [72..80] timestamp_ms  u64 little-endian
//
// If this layout ever drifts from the sidecar, signatures will be computed
// over the wrong bytes and downstream attestation guarantees collapse. Pinned
// by `tests/preimage.test.ts::preImageLayoutIsByteExact`.

import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

const PRE_IMAGE_LEN = 80;
const REQ_HASH_OFFSET = 8;
const RESP_HASH_OFFSET = 40;
const TIMESTAMP_OFFSET = 72;
const HASH_LEN = 32;

const U64_MAX = (1n << 64n) - 1n;

/**
 * Encode a u64 as 8 bytes, little-endian. Matches Rust `u64::to_le_bytes`.
 *
 * Throws `RangeError` for values outside `[0, 2^64 - 1]`. `setBigUint64`
 * otherwise SILENTLY reduces modulo 2^64 (and takes two's complement on
 * negatives), which would weaken the pre-image binding from strict equality to
 * "equality mod 2^64" — `u64LE(C)` and `u64LE(C + 2^64)` produce identical
 * bytes. Failing loud keeps the stored chainId/timestamp and the bound bytes in
 * exact agreement. Valid u64 inputs encode byte-for-byte unchanged.
 */
export function u64LE(n: bigint): Uint8Array {
  if (n < 0n || n > U64_MAX) {
    throw new RangeError(`u64 value ${n} out of range [0, 2^64 - 1]`);
  }
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, n, true);
  return buf;
}

/**
 * Thin wrapper over `@noble/hashes/sha2`'s `sha256`. Returns a fresh 32-byte
 * `Uint8Array`.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/**
 * Build the canonical 80-byte pre-image from pre-computed body hashes.
 *
 * Internal API, exported for tests only — production callers should use
 * `buildPreImage`, which hashes the raw bodies and forwards here.
 *
 * Throws `RangeError` if either hash is not exactly 32 bytes. The pre-image
 * has no domain-error failure modes a consumer would catch (any failure
 * indicates a programmer error in the SDK, not a sidecar misbehaviour).
 */
export function buildPreImageFromHashes(
  chainId: bigint,
  requestHash: Uint8Array,
  responseHash: Uint8Array,
  timestampMs: bigint,
): Uint8Array {
  if (requestHash.length !== HASH_LEN) {
    throw new RangeError(`requestHash must be ${HASH_LEN} bytes, got ${requestHash.length}`);
  }
  if (responseHash.length !== HASH_LEN) {
    throw new RangeError(`responseHash must be ${HASH_LEN} bytes, got ${responseHash.length}`);
  }
  const buf = new Uint8Array(PRE_IMAGE_LEN);
  buf.set(u64LE(chainId), 0);
  buf.set(requestHash, REQ_HASH_OFFSET);
  buf.set(responseHash, RESP_HASH_OFFSET);
  buf.set(u64LE(timestampMs), TIMESTAMP_OFFSET);
  return buf;
}

/**
 * Build the canonical 80-byte pre-image for a request/response pair.
 *
 * Hashes the raw request and response bodies with SHA-256, then assembles the
 * canonical byte layout. Returns exactly 80 bytes.
 */
export function buildPreImage(
  chainId: bigint,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
  timestampMs: bigint,
): Uint8Array {
  return buildPreImageFromHashes(chainId, sha256(requestBody), sha256(responseBody), timestampMs);
}
