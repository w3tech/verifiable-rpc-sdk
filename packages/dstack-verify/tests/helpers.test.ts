// Helper-stub tests — VPKG-05.
//
// The four v6.0 helper signatures are frozen; their v5.0 bodies are throwing
// stubs. v6.0 replaces ONLY the body. Each must throw with a message containing
// "not implemented in v5.0" so the A/B boundary is explicit and auditable.

import { describe, expect, test } from "vitest";

import {
  AttestationError,
  computeComposeHash,
  extractKeyProvider,
  parseReportData,
  replayRtmr,
} from "../src/index";

describe("v6.0 helper stubs throw in v5.0", () => {
  test("replayRtmr throws not-implemented", () => {
    expect(() => replayRtmr([])).toThrow("not implemented in v5.0");
  });

  test("computeComposeHash throws not-implemented", () => {
    expect(() => computeComposeHash("")).toThrow("not implemented in v5.0");
  });

  // parseReportData is implemented (CHK-A1) — it no longer stubs out. Malformed
  // input throws AttestationError("CHK-A1"); the happy-path split is covered in
  // verify.test.ts.
  test("parseReportData throws AttestationError(CHK-A1) on malformed input", () => {
    try {
      parseReportData("");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });

  test("extractKeyProvider throws not-implemented", () => {
    expect(() => extractKeyProvider([])).toThrow("not implemented in v5.0");
  });
});
