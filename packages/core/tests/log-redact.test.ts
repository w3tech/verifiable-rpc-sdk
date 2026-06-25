// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Unit tests for the logger seam (logger.ts) and the redaction/truncation
// helpers (log-redact.ts): truncation shape, byte-length, header allowlist
// redaction, the no-op default, and the never-throw safe wrapper.

import { describe, expect, it } from "vitest";

import { byteLen, redactHeaders, SAFE_HEADER_KEYS, truncateHex } from "../src/log-redact";
import { defaultLogger, safeLogger } from "../src/logger";
import { collectingLogger } from "./support/collecting-logger";

describe("truncateHex", () => {
  it("keeps exactly keepBytes*2 hex chars then … then a (NB) byte-count suffix", () => {
    const out = truncateHex(`0x${"ab".repeat(32)}`);
    expect(out).toBe(`0x${"ab".repeat(4)}…(32B)`);
    // 0x + 8 hex chars + the ellipsis + the suffix
    expect(out.startsWith("0xabababab…(")).toBe(true);
    expect(out.slice(2, 10)).toBe("abababab");
  });

  it("returns a value shorter-or-equal to keepBytes unchanged (with 0x)", () => {
    expect(truncateHex("0xabcd")).toBe("0xabcd");
    expect(truncateHex(`0x${"ff".repeat(4)}`)).toBe(`0x${"ff".repeat(4)}`);
  });

  it("accepts both with and without the 0x prefix", () => {
    const withPrefix = truncateHex(`0x${"ab".repeat(32)}`);
    const without = truncateHex("ab".repeat(32));
    expect(without).toBe(withPrefix);
  });

  it("honors a custom keepBytes", () => {
    expect(truncateHex(`0x${"cd".repeat(10)}`, 2)).toBe("0xcdcd…(10B)");
  });
});

describe("byteLen", () => {
  it("counts bytes of a 0x-hex string", () => {
    expect(byteLen(`0x${"ff".repeat(10)}`)).toBe("10B");
  });

  it("counts bytes of a bare-hex string", () => {
    expect(byteLen("ff".repeat(10))).toBe("10B");
  });

  it("counts the length of a Uint8Array", () => {
    expect(byteLen(new Uint8Array(10))).toBe("10B");
  });
});

describe("redactHeaders", () => {
  it("passes known-safe keys through verbatim (case-insensitive)", () => {
    const out = redactHeaders({
      "content-type": "application/json",
      "Content-Length": "123",
      "content-encoding": "gzip",
      "vrpc-pubkey": "0xdead",
      "VRPC-Timestamp": "1700000000000",
    });
    expect(out["content-type"]).toBe("application/json");
    expect(out["Content-Length"]).toBe("123");
    expect(out["content-encoding"]).toBe("gzip");
    expect(out["vrpc-pubkey"]).toBe("0xdead");
    expect(out["VRPC-Timestamp"]).toBe("1700000000000");
  });

  it("redacts every other key to the literal [redacted]", () => {
    const out = redactHeaders({
      authorization: "Bearer secret-token",
      "x-api-key": "sk-live-deadbeef",
      "vrpc-signature": "0xfeedface",
      "x-custom": "whatever",
    });
    expect(out.authorization).toBe("[redacted]");
    expect(out["x-api-key"]).toBe("[redacted]");
    expect(out["vrpc-signature"]).toBe("[redacted]");
    expect(out["x-custom"]).toBe("[redacted]");
  });

  it("never returns the original authorization / x-api-key value", () => {
    const out = redactHeaders({
      authorization: "Bearer secret-token",
      "x-api-key": "sk-live-deadbeef",
    });
    expect(out.authorization).not.toContain("secret-token");
    expect(out["x-api-key"]).not.toContain("sk-live-deadbeef");
  });

  it("does not list a credential key in the allowlist", () => {
    expect(SAFE_HEADER_KEYS.has("authorization")).toBe(false);
    expect(SAFE_HEADER_KEYS.has("x-api-key")).toBe(false);
    expect(SAFE_HEADER_KEYS.has("vrpc-signature")).toBe(false);
  });
});

describe("defaultLogger", () => {
  it("is a no-op: returns undefined and throws nothing", () => {
    expect(defaultLogger.debug("verify.start")).toBeUndefined();
    expect(() => defaultLogger.debug("verify.start", { req: "0xabcd" })).not.toThrow();
  });
});

describe("safeLogger", () => {
  it("swallows a throw from the inner logger and returns undefined", () => {
    const throwing = safeLogger({
      debug() {
        throw new Error("boom");
      },
    });
    expect(() => throwing.debug("verify.start", { x: 1 })).not.toThrow();
    expect(throwing.debug("verify.start")).toBeUndefined();
  });

  it("forwards the call when the inner logger succeeds", () => {
    const inner = collectingLogger();
    const wrapped = safeLogger(inner);
    wrapped.debug("verify.start", { req: "0xabcd" });
    expect(inner.calls).toEqual([["verify.start", { req: "0xabcd" }]]);
  });
});
