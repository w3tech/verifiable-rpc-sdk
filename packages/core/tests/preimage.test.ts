import { sha256 } from "@noble/hashes/sha2.js";
import { toHex } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import { InvalidChainId } from "../src/errors";
import { buildPreImage, u64LE, validateChainId } from "../src/preimage";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const chainIdHash = (chainId: string): string =>
  toHex(buildPreImage(chainId, new Uint8Array(0), new Uint8Array(0), 0n).slice(0, 32));

describe("preimage", () => {
  /**
   * The layout of sidecar `src/signing.rs::tests::pre_image_layout_is_byte_exact`:
   *
   *   [0..32]   sha256(utf8(chain_id))
   *   [32..64]  sha256(request_body)
   *   [64..96]  sha256(response_body)
   *   [96..104] timestamp_ms LE   = 22 33 44 55 66 77 88 99 for 0x9988776655443322
   *
   * If this drifts even one byte, the SDK verifies against the wrong bytes and
   * the sidecar's signatures stop verifying. Hard fail.
   */
  test("preImageLayoutIsByteExact", () => {
    const req = new Uint8Array([0x01, 0x02, 0x03]);
    const resp = new Uint8Array([0x04, 0x05, 0x06]);
    const pre = buildPreImage("42161", req, resp, 0x9988776655443322n);

    expect(pre.length).toBe(104);
    expect(toHex(pre.slice(0, 32))).toBe(toHex(sha256(utf8("42161"))));
    expect(toHex(pre.slice(32, 64))).toBe(toHex(sha256(req)));
    expect(toHex(pre.slice(64, 96))).toBe(toHex(sha256(resp)));
    expect(Array.from(pre.slice(96, 104))).toEqual([
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ]);
  });

  /**
   * Mirror of sidecar `chain_id_hash_matches_known_answer`. These three
   * vectors must match the sidecar's `src/signing.rs` known-answer vectors —
   * the verifier SDK reproduces them byte-exactly. Numeric-looking ids are
   * hashed as strings too, never parsed. Sample ids: TON global id "-239",
   * Stellar network id (sha256 of the mainnet passphrase), EVM "42161".
   */
  test("chainIdHashMatchesKnownAnswer", () => {
    expect(chainIdHash("-239")).toBe(
      "7d1a0b60d68a1efc2e01df13132034d669b2ce5b05c8bf6d4ae6322e810c5659",
    );
    // Stellar's chain id is its network id — SHA-256 of the mainnet network
    // passphrase — a 64-char (64-byte) hex string, at the validation limit.
    expect(chainIdHash("7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979")).toBe(
      "dd4a5b7a84a301d6a8db49bff6877b3ef17b03d7afd19302fab324d1b7b4e1f7",
    );
    expect(chainIdHash("42161")).toBe(
      "936a20303015aca26be61e6782c83b1de6b4b25f3dbdf555a97d85e0477a53a9",
    );
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
