// Helper-stub tests — VPKG-05.
//
// The four v6.0 helper signatures are frozen; their v5.0 bodies are throwing
// stubs. v6.0 replaces ONLY the body. Each must throw with a message containing
// "not implemented in v5.0" so the A/B boundary is explicit and auditable.

import { describe, expect, test } from "vitest";

import { computeComposeHash, extractKeyProvider, parseReportData, replayRtmr } from "../src/index";

describe("v6.0 helper stubs throw in v5.0", () => {
  test("replayRtmr throws not-implemented", () => {
    expect(() => replayRtmr([])).toThrow("not implemented in v5.0");
  });

  test("computeComposeHash throws not-implemented", () => {
    expect(() => computeComposeHash("")).toThrow("not implemented in v5.0");
  });

  test("parseReportData throws not-implemented", () => {
    expect(() => parseReportData("")).toThrow("not implemented in v5.0");
  });

  test("extractKeyProvider throws not-implemented", () => {
    expect(() => extractKeyProvider([])).toThrow("not implemented in v5.0");
  });
});
