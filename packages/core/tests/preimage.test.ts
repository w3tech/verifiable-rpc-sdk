import { describe, expect, test } from "bun:test";

import { buildPreImage, buildPreImageFromHashes, sha256, u64LE } from "../src/preimage";

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

describe("preimage", () => {
  /**
   * Mirror of sidecar `src/signing.rs::tests::pre_image_layout_is_byte_exact`.
   *
   * Inputs:
   *   chain_id     = 0x1122334455667788
   *   request_hash = [0xaa; 32]
   *   response_hash= [0xbb; 32]
   *   timestamp_ms = 0x9988776655443322
   *
   * Expected 80-byte layout:
   *   [0..8]   chain_id LE       = 88 77 66 55 44 33 22 11
   *   [8..40]  request_hash      = aa * 32
   *   [40..72] response_hash     = bb * 32
   *   [72..80] timestamp_ms LE   = 22 33 44 55 66 77 88 99
   *
   * If this drifts even one byte, the SDK signs over the wrong bytes and the
   * sidecar's signatures stop verifying. Hard fail.
   */
  test("preImageLayoutIsByteExact", () => {
    const chainId = 0x1122334455667788n;
    const requestHash = new Uint8Array(32).fill(0xaa);
    const responseHash = new Uint8Array(32).fill(0xbb);
    const timestampMs = 0x9988776655443322n;

    const pre = buildPreImageFromHashes(chainId, requestHash, responseHash, timestampMs);

    expect(pre.length).toBe(80);

    // chain_id (8B LE)
    expect(Array.from(pre.slice(0, 8))).toEqual([0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);

    // request_hash (32B) — all 0xaa
    expect(pre.slice(8, 40).every((b) => b === 0xaa)).toBe(true);

    // response_hash (32B) — all 0xbb
    expect(pre.slice(40, 72).every((b) => b === 0xbb)).toBe(true);

    // timestamp_ms (8B LE)
    expect(Array.from(pre.slice(72, 80))).toEqual([0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
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
   * those hashes at offsets [8..40] and [40..72].
   *
   * Known vector pinned for byte-exact regression detection:
   *   chainId=1n, request=[0x01,0x02,0x03], response=[0x04,0x05,0x06],
   *   timestampMs=0x0102030405060708n.
   *
   * Expected hashes (computed independently via @noble/hashes):
   *   sha256([0x01,0x02,0x03]) = 039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81
   *   sha256([0x04,0x05,0x06]) = 787c798e39a5bc1910355bae6d0cd87a36b2e10fd0202a83e3bb6b005da83472
   */
  test("buildPreImageHashesBodiesInternally", () => {
    const chainId = 1n;
    const requestBody = new Uint8Array([0x01, 0x02, 0x03]);
    const responseBody = new Uint8Array([0x04, 0x05, 0x06]);
    const timestampMs = 0x0102030405060708n;

    const pre = buildPreImage(chainId, requestBody, responseBody, timestampMs);

    expect(pre.length).toBe(80);
    expect(toHex(pre.slice(8, 40))).toBe(
      "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    );
    expect(toHex(pre.slice(40, 72))).toBe(
      "787c798e39a5bc1910355bae6d0cd87a36b2e10fd0202a83e3bb6b005da83472",
    );

    // chain_id LE: 1 → 01 00 00 00 00 00 00 00
    expect(Array.from(pre.slice(0, 8))).toEqual([0x01, 0, 0, 0, 0, 0, 0, 0]);
    // timestamp LE: 0x0102030405060708 → 08 07 06 05 04 03 02 01
    expect(Array.from(pre.slice(72, 80))).toEqual([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
  });

  test("preImageLengthIsExactly80", () => {
    const pre = buildPreImage(42n, new Uint8Array([1]), new Uint8Array([2]), 0n);
    expect(pre.length).toBe(80);
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
   * MED-01: `u64LE` must FAIL LOUD on out-of-u64 inputs instead of silently
   * wrapping mod 2^64. Otherwise the chainId binding would only hold
   * "mod 2^64": `u64LE(C)` and `u64LE(C + 2^64)` would be byte-identical and
   * the stored chainId could diverge from the bytes actually bound.
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
    // a normal EVM chain id (arbitrum = 42161) → bytes unchanged.
    expect(Array.from(u64LE(42161n))).toEqual([0xb1, 0xa4, 0, 0, 0, 0, 0, 0]);
    // out-of-range chainId propagates through the pre-image builder too.
    expect(() => buildPreImage(1n << 64n, new Uint8Array([1]), new Uint8Array([2]), 0n)).toThrow(
      RangeError,
    );
  });

  test("buildPreImageFromHashesRejectsNon32ByteHashes", () => {
    expect(() => buildPreImageFromHashes(1n, new Uint8Array(31), new Uint8Array(32), 0n)).toThrow(
      RangeError,
    );
    expect(() => buildPreImageFromHashes(1n, new Uint8Array(32), new Uint8Array(33), 0n)).toThrow(
      RangeError,
    );
  });
});
