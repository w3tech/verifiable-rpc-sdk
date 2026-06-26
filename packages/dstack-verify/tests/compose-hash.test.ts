import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vitest";

import { computeComposeHash } from "../src/verify-steps";

describe("computeComposeHash", () => {
  test("equals sha256(utf8) as bare lowercase hex", () => {
    const s = '{"manifest_version":2,"name":"demo"}';
    expect(computeComposeHash(s)).toBe(bytesToHex(sha256(new TextEncoder().encode(s))));
  });

  test("reproduces the dstack rule with no canonicalization (sha256 empty vector)", () => {
    expect(computeComposeHash("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
