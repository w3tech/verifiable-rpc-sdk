// Helper-stub tests.
//
// The four helper signatures are frozen; their current bodies are throwing
// stubs. A future release replaces ONLY the body. Each must throw with a message
// containing "not implemented" so the boundary is explicit and auditable.

import { describe, expect, test } from "vitest";

import {
  AttestationError,
  computeComposeHash,
  extractKeyProvider,
  parseReportData,
  replayRtmr,
} from "../src/index";

describe("helper stubs throw not-implemented", () => {
  test("replayRtmr throws not-implemented", () => {
    expect(() => replayRtmr([])).toThrow("not implemented");
  });

  test("computeComposeHash throws not-implemented", () => {
    expect(() => computeComposeHash("")).toThrow("not implemented");
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
    expect(() => extractKeyProvider([])).toThrow("not implemented");
  });
});
