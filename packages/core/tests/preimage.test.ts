import { describe, expect, test } from "vitest";

import { InvalidChainId } from "../src/errors";
import {
  buildPreImage,
  buildPreImageFromHashes,
  sha256,
  u64LE,
  validateChainId,
} from "../src/preimage";

/**
 * Hex-encode a Uint8Array to lowercase hex (no 0x prefix).
 * Kept local to tests to avoid pulling a util into src/.
 */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("preimage", () => {
  /**
   * Mirror of sidecar `src/signing.rs::tests::pre_image_layout_is_byte_exact`.
   *
   * Inputs:
   *   chain_id_hash = [0xcc; 32]
   *   request_hash  = [0xaa; 32]
   *   response_hash = [0xbb; 32]
   *   timestamp_ms  = 0x9988776655443322
   *
   * Expected 104-byte layout:
   *   [0..32]   chain_id_hash     = cc * 32
   *   [32..64]  request_hash      = aa * 32
   *   [64..96]  response_hash     = bb * 32
   *   [96..104] timestamp_ms LE   = 22 33 44 55 66 77 88 99
   *
   * If this drifts even one byte, the SDK verifies against the wrong bytes and
   * the sidecar's signatures stop verifying. Hard fail.
   */
  test("preImageLayoutIsByteExact", () => {
    const chainIdHash = new Uint8Array(32).fill(0xcc);
    const requestHash = new Uint8Array(32).fill(0xaa);
    const responseHash = new Uint8Array(32).fill(0xbb);
    const timestampMs = 0x9988776655443322n;

    const pre = buildPreImageFromHashes(chainIdHash, requestHash, responseHash, timestampMs);

    expect(pre.length).toBe(104);

    // chain_id_hash (32B) — all 0xcc
    expect(pre.slice(0, 32).every((b) => b === 0xcc)).toBe(true);

    // request_hash (32B) — all 0xaa
    expect(pre.slice(32, 64).every((b) => b === 0xaa)).toBe(true);

    // response_hash (32B) — all 0xbb
    expect(pre.slice(64, 96).every((b) => b === 0xbb)).toBe(true);

    // timestamp_ms (8B LE)
    expect(Array.from(pre.slice(96, 104))).toEqual([
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ]);

    // Public builder: buildPreImage hashes the chain id string internally and
    // places sha256(utf8(chainId)) at [0..32].
    const req = new Uint8Array([0x01, 0x02, 0x03]);
    const resp = new Uint8Array([0x04, 0x05, 0x06]);
    const ts = 1_700_000_000_000n;
    const full = buildPreImage("42161", req, resp, ts);
    expect(full.length).toBe(104);
    expect(toHex(full.slice(0, 32))).toBe(toHex(sha256(utf8("42161"))));
    expect(toHex(full.slice(32, 64))).toBe(toHex(sha256(req)));
    expect(toHex(full.slice(64, 96))).toBe(toHex(sha256(resp)));
    expect(Array.from(full.slice(96, 104))).toEqual(Array.from(u64LE(ts)));
  });

  /**
   * Mirror of sidecar `chain_id_hash_matches_known_answer`. These three
   * vectors must match the sidecar's `src/signing.rs` known-answer vectors —
   * the verifier SDK reproduces them byte-exactly. Numeric-looking ids are
   * hashed as strings too, never parsed. Sample ids: TON global id "-239",
   * Stellar network id (sha256 of the mainnet passphrase), EVM "42161".
   */
  test("chainIdHashMatchesKnownAnswer", () => {
    expect(toHex(sha256(utf8("-239")))).toBe(
      "7d1a0b60d68a1efc2e01df13132034d669b2ce5b05c8bf6d4ae6322e810c5659",
    );
    // Stellar's chain id is its network id — SHA-256 of the mainnet network
    // passphrase — a 64-char (64-byte) hex string, at the validation limit.
    expect(
      toHex(sha256(utf8("7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"))),
    ).toBe("dd4a5b7a84a301d6a8db49bff6877b3ef17b03d7afd19302fab324d1b7b4e1f7");
    expect(toHex(sha256(utf8("42161")))).toBe(
      "936a20303015aca26be61e6782c83b1de6b4b25f3dbdf555a97d85e0477a53a9",
    );
  });

  /**
   * Mirror of sidecar `sha256_matches_known_value`. Sanity check that the
   * @noble/hashes/sha2 wrapper is wired correctly.
   * sha256("") == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   */
  test("sha256OfEmptyMatchesKnownValue", () => {
    const h = sha256(new Uint8Array(0));
    expect(toHex(h)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  /**
   * Locks the public API contract: `buildPreImage(chainId, requestBody,
   * responseBody, timestampMs)` MUST hash the bodies internally and embed
   * those hashes at offsets [32..64] and [64..96].
   *
   * Known vector pinned for byte-exact regression detection:
   *   chainId="1", request=[0x01,0x02,0x03], response=[0x04,0x05,0x06],
   *   timestampMs=0x0102030405060708n.
   *
   * Expected hashes (computed independently via @noble/hashes):
   *   sha256("1")              = 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
   *   sha256([0x01,0x02,0x03]) = 039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81
   *   sha256([0x04,0x05,0x06]) = 787c798e39a5bc1910355bae6d0cd87a36b2e10fd0202a83e3bb6b005da83472
   */
  test("buildPreImageHashesBodiesInternally", () => {
    const requestBody = new Uint8Array([0x01, 0x02, 0x03]);
    const responseBody = new Uint8Array([0x04, 0x05, 0x06]);
    const timestampMs = 0x0102030405060708n;

    const pre = buildPreImage("1", requestBody, responseBody, timestampMs);

    expect(pre.length).toBe(104);
    // chain_id_hash: sha256(utf8("1"))
    expect(toHex(pre.slice(0, 32))).toBe(
      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    );
    expect(toHex(pre.slice(32, 64))).toBe(
      "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    );
    expect(toHex(pre.slice(64, 96))).toBe(
      "787c798e39a5bc1910355bae6d0cd87a36b2e10fd0202a83e3bb6b005da83472",
    );
    // timestamp LE: 0x0102030405060708 → 08 07 06 05 04 03 02 01
    expect(Array.from(pre.slice(96, 104))).toEqual([
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ]);
  });

  test("preImageLengthIsExactly104", () => {
    const pre = buildPreImage("42", new Uint8Array([1]), new Uint8Array([2]), 0n);
    expect(pre.length).toBe(104);
  });

  /**
   * u64 little-endian encoding must byte-match Rust's `u64::to_le_bytes`.
   * Defends against an accidental big-endian regression.
   */
  test("u64LeMatchesRustToLeBytes", () => {
    expect(Array.from(u64LE(0x1122334455667788n))).toEqual([
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ]);
    expect(Array.from(u64LE(0n))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(u64LE(1n))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    // Max u64 = 2^64 - 1 = 0xffffffffffffffff
    expect(Array.from(u64LE(0xffffffffffffffffn))).toEqual([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
  });

  /**
   * `u64LE` must FAIL LOUD on out-of-u64 inputs instead of silently
   * wrapping mod 2^64. Otherwise the timestamp binding would only hold
   * "mod 2^64": `u64LE(T)` and `u64LE(T + 2^64)` would be byte-identical and
   * the stored timestamp could diverge from the bytes actually bound.
   */
  test("u64LeRejectsOutOfRange", () => {
    // 2^64 (first value past the max) → throws.
    expect(() => u64LE(1n << 64n)).toThrow(RangeError);
    // negative → throws (no two's-complement wrap).
    expect(() => u64LE(-1n)).toThrow(RangeError);
    // 2^64 - 1 (max valid) → encodes fine, all 0xff.
    expect(Array.from(u64LE((1n << 64n) - 1n))).toEqual([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    // out-of-range timestamp propagates through the pre-image builder too.
    expect(() => buildPreImage("1", new Uint8Array([1]), new Uint8Array([2]), 1n << 64n)).toThrow(
      RangeError,
    );
  });

  test("buildPreImageFromHashesRejectsNon32ByteHashes", () => {
    const ok = new Uint8Array(32);
    // chainIdHash wrong length.
    expect(() => buildPreImageFromHashes(new Uint8Array(31), ok, ok, 0n)).toThrow(RangeError);
    expect(() => buildPreImageFromHashes(new Uint8Array(33), ok, ok, 0n)).toThrow(RangeError);
    // requestHash wrong length.
    expect(() => buildPreImageFromHashes(ok, new Uint8Array(31), ok, 0n)).toThrow(RangeError);
    // responseHash wrong length.
    expect(() => buildPreImageFromHashes(ok, ok, new Uint8Array(33), 0n)).toThrow(RangeError);
  });

  /**
   * Mirror of sidecar `validate_chain_id_accepts_valid_ids`
   * (src/signing.rs). Chain ids are opaque strings — CAIP-2 style ids and
   * numeric-looking ids are all just strings, never parsed numerically.
   */
  test("validateChainIdAcceptsValidIds", () => {
    expect(validateChainId("42161")).toBe("42161");
    expect(validateChainId("0x89")).toBe("0x89");
    expect(validateChainId("-239")).toBe("-239");
    // Stellar network id — 64-byte hex, exactly at the length limit.
    const stellarId = "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979";
    expect(validateChainId(stellarId)).toBe(stellarId);
    // Surrounding whitespace is trimmed, not rejected.
    expect(validateChainId(" 137 ")).toBe("137");
    // 64-byte boundary is accepted.
    const max = "x".repeat(64);
    expect(validateChainId(max)).toBe(max);
  });

  /**
   * Mirror of sidecar `validate_chain_id_rejects_invalid_ids`
   * (src/signing.rs). Every rejection throws the typed `InvalidChainId`
   * with a message naming the failed constraint.
   */
  test("validateChainIdRejectsInvalidIds", () => {
    // Empty (before or after trim) is rejected.
    expect(() => validateChainId("")).toThrow(InvalidChainId);
    expect(() => validateChainId(" ")).toThrow(InvalidChainId);
    // Internal whitespace is rejected.
    expect(() => validateChainId("a b")).toThrow(InvalidChainId);
    expect(() => validateChainId("a\tb")).toThrow(InvalidChainId);
    // 65 bytes exceeds the limit.
    expect(() => validateChainId("x".repeat(65))).toThrow(InvalidChainId);
    // Non-ASCII is rejected.
    expect(() => validateChainId("cépas")).toThrow(InvalidChainId);
    // Non-printable control characters are rejected.
    expect(() => validateChainId("a\u007Fb")).toThrow(InvalidChainId);

    // Error messages name the failed constraint.
    expect(() => validateChainId("")).toThrow(/empty/);
    expect(() => validateChainId("x".repeat(65))).toThrow(/byte/);
    expect(() => validateChainId("cépas")).toThrow(/character/);
  });
});
