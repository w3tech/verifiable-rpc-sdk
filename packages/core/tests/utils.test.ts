import { describe, expect, test } from "vitest";

import { MalformedHeader } from "../src/errors";
import { parseChainId } from "../src/utils";

const encode = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("parseChainId", () => {
  test("decodesHexResultToDecimalString", () => {
    // 0xa4b1 = 42161 (arbitrum) — the decimal string is what the node is
    // configured with, so auto-detect binds the exact string the sidecar signs.
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0xa4b1" });
    expect(parseChainId(encode(body))).toBe("42161");
  });

  test("handlesChainIdsBeyondNumberSafeInteger", () => {
    // 2^64 - 1 — must not round-trip through a lossy `number`.
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0xffffffffffffffff" });
    expect(parseChainId(encode(body))).toBe("18446744073709551615");
  });

  test("throwsMalformedHeaderOnInvalidJson", () => {
    expect(() => parseChainId(encode("not json"))).toThrow(MalformedHeader);
  });

  test("throwsMalformedHeaderOnNonHexResult", () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "42161" });
    expect(() => parseChainId(encode(body))).toThrow(MalformedHeader);
  });
});
