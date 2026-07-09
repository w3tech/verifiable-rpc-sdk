// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Canonical 104-byte pre-image builder. Mirrors `verifiable-rpc-sidecar/src/signing.rs`
// v0.5.0 (string chain id).
//
// Layout (byte-exact, MUST match sidecar):
//   [0..32]   chain_id_hash sha256(utf8(chain_id)) — 32 bytes
//   [32..64]  request_hash  sha256(request_body) — 32 bytes
//   [64..96]  response_hash sha256(response_body) — 32 bytes
//   [96..104] timestamp_ms  u64 little-endian
//
// If this layout ever drifts from the sidecar, signatures will be computed
// over the wrong bytes and downstream attestation guarantees collapse. Pinned
// by `tests/preimage.test.ts::preImageLayoutIsByteExact` and the known-answer
// chain-id hash vectors copied verbatim from the sidecar test suite.

import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

import { InvalidChainId } from "./errors";

const PRE_IMAGE_LEN = 104;
const CHAIN_ID_HASH_OFFSET = 0;
const REQ_HASH_OFFSET = 32;
const RESP_HASH_OFFSET = 64;
const TIMESTAMP_OFFSET = 96;
const HASH_LEN = 32;

/** Maximum UTF-8 byte length accepted for a chain id. Mirrors sidecar `CHAIN_ID_MAX_LEN`. */
const CHAIN_ID_MAX_LEN = 64;

const U64_MAX = (1n << 64n) - 1n;

const textEncoder = new TextEncoder();

/**
 * Encode a u64 as 8 bytes, little-endian. Matches Rust `u64::to_le_bytes`.
 *
 * Throws `RangeError` for values outside `[0, 2^64 - 1]`. `setBigUint64`
 * otherwise SILENTLY reduces modulo 2^64 (and takes two's complement on
 * negatives), which would weaken the pre-image binding from strict equality to
 * "equality mod 2^64" — `u64LE(C)` and `u64LE(C + 2^64)` produce identical
 * bytes. Failing loud keeps the stored timestamp and the bound bytes in exact
 * agreement. Valid u64 inputs encode byte-for-byte unchanged.
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
 * Validate a chain id. Mirrors sidecar `validate_chain_id` semantics and check
 * order exactly: (1) trim; (2) reject empty after trim; (3) reject UTF-8 byte
 * length above 64; (4) reject any character outside printable ASCII excluding
 * space (codepoints 0x21–0x7E — Rust `is_ascii_graphic`), which covers internal
 * whitespace, non-ASCII, and control characters. Returns the TRIMMED string.
 *
 * Chain ids are opaque strings — a non-EVM id like TON's global id `"-239"`,
 * a CAIP-2 style id like `"stellar:pubnet"`, and numeric-looking ids like
 * `"42161"` or `"0x89"` are all just strings, never parsed numerically.
 *
 * Throws the typed `InvalidChainId` (a `VerificationError` subclass) naming the
 * failed constraint, mirroring the sidecar's boot-time fail-fast.
 */
export function validateChainId(chainId: string): string {
  const trimmed = chainId.trim();
  if (trimmed.length === 0) {
    throw new InvalidChainId(chainId, "must not be empty");
  }
  const byteLen = textEncoder.encode(trimmed).length;
  if (byteLen > CHAIN_ID_MAX_LEN) {
    throw new InvalidChainId(
      chainId,
      `is ${byteLen} bytes, exceeds the ${CHAIN_ID_MAX_LEN}-byte limit`,
    );
  }
  for (const c of trimmed) {
    const cp = c.codePointAt(0) ?? 0;
    if (cp < 0x21 || cp > 0x7e) {
      throw new InvalidChainId(
        chainId,
        `contains non-printable-ASCII or whitespace character ${JSON.stringify(c)}`,
      );
    }
  }
  return trimmed;
}

/**
 * Build the canonical 104-byte pre-image from pre-computed hashes.
 *
 * Mirrors sidecar `build_pre_image(&chain_id_hash, &req_hash, &resp_hash, ts)`.
 * Internal API, exported for tests only — production callers should use
 * `buildPreImage`, which hashes the chain id and raw bodies and forwards here.
 *
 * Throws `RangeError` if any hash is not exactly 32 bytes. The pre-image
 * has no domain-error failure modes a consumer would catch (any failure
 * indicates a programmer error in the SDK, not a sidecar misbehaviour).
 */
export function buildPreImageFromHashes(
  chainIdHash: Uint8Array,
  requestHash: Uint8Array,
  responseHash: Uint8Array,
  timestampMs: bigint,
): Uint8Array {
  if (chainIdHash.length !== HASH_LEN) {
    throw new RangeError(`chainIdHash must be ${HASH_LEN} bytes, got ${chainIdHash.length}`);
  }
  if (requestHash.length !== HASH_LEN) {
    throw new RangeError(`requestHash must be ${HASH_LEN} bytes, got ${requestHash.length}`);
  }
  if (responseHash.length !== HASH_LEN) {
    throw new RangeError(`responseHash must be ${HASH_LEN} bytes, got ${responseHash.length}`);
  }
  const buf = new Uint8Array(PRE_IMAGE_LEN);
  buf.set(chainIdHash, CHAIN_ID_HASH_OFFSET);
  buf.set(requestHash, REQ_HASH_OFFSET);
  buf.set(responseHash, RESP_HASH_OFFSET);
  buf.set(u64LE(timestampMs), TIMESTAMP_OFFSET);
  return buf;
}

/**
 * Build the canonical 104-byte pre-image for a request/response pair.
 *
 * Computes `sha256(utf8(chainId))` and the SHA-256 body hashes, then assembles
 * the canonical byte layout. Returns exactly 104 bytes.
 *
 * Does NOT validate the chain id — validation happens once at the entry
 * boundary (client construction and `verifyResponse` entry), mirroring the
 * sidecar split where `validate_chain_id` runs at boot and the sign path
 * trusts the stored id.
 */
export function buildPreImage(
  chainId: string,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
  timestampMs: bigint,
): Uint8Array {
  return buildPreImageFromHashes(
    sha256(textEncoder.encode(chainId)),
    sha256(requestBody),
    sha256(responseBody),
    timestampMs,
  );
}
