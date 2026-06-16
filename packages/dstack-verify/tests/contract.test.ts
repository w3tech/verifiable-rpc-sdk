// Frozen-contract surface tests — VPKG-02/VPKG-05.
//
// Asserts: the public barrel exports every contract symbol; AttestationError
// extends the shared abstract VerificationError from @ankr.com/vrpc-core and
// carries the new "Attestation" kind + chk/name; the CHK record enumerates the
// complete CHK-A1..G3 set (+ CHK-MOCK) with non-empty meaning + valid disposition.

import { describe, expect, test } from "bun:test";
import { VerificationError } from "@ankr.com/vrpc-core";

import {
  AttestationError,
  CHK,
  computeComposeHash,
  extractKeyProvider,
  parseReportData,
  replayRtmr,
  verifyDstackAttestation,
} from "../src/index";

describe("public contract surface", () => {
  test("exports all required symbols", () => {
    expect(typeof AttestationError).toBe("function");
    expect(typeof verifyDstackAttestation).toBe("function");
    expect(typeof CHK).toBe("object");
    expect(typeof replayRtmr).toBe("function");
    expect(typeof computeComposeHash).toBe("function");
    expect(typeof parseReportData).toBe("function");
    expect(typeof extractKeyProvider).toBe("function");
  });
});

describe("AttestationError", () => {
  test("extends the shared abstract VerificationError with the new kind", () => {
    const e = new AttestationError("CHK-MOCK", "x");
    expect(e instanceof Error).toBe(true);
    expect(e instanceof VerificationError).toBe(true);
    expect(e instanceof AttestationError).toBe(true);
    // kind is statically typed as the base VerificationErrorKind union (the
    // override is assignable without editing core); the runtime value is the
    // "Attestation" literal. Read it as string to compare the runtime value.
    expect(e.kind as string).toBe("Attestation");
    expect(e.name).toBe("AttestationError");
    expect(e.chk).toBe("CHK-MOCK");
    expect(e.detail).toBe("x");
    expect(e.message).toContain("CHK-MOCK");
  });

  test("carries an optional cause", () => {
    const cause = new Error("root");
    const e = new AttestationError("CHK-A1", "binding mismatch", { cause });
    expect((e as { cause?: unknown }).cause).toBe(cause);
  });
});

describe("CHK checklist completeness", () => {
  const EXPECTED_CHK_IDS = [
    "CHK-A1",
    "CHK-A2",
    "CHK-A3",
    "CHK-A4",
    "CHK-A5",
    "CHK-A6",
    "CHK-P1",
    "CHK-P2",
    "CHK-P3",
    "CHK-P4",
    "CHK-P5",
    "CHK-P6",
    "CHK-P7",
    "CHK-P8",
    "CHK-P9",
    "CHK-N1",
    "CHK-N2",
    "CHK-N3",
    "CHK-G1",
    "CHK-G2",
    "CHK-G3",
    "CHK-MOCK",
  ] as const;

  const VALID_DISPOSITIONS = ["implement", "mock", "pinned", "out", "mock-deny"];

  test("contains the complete CHK-A1..G3 set plus CHK-MOCK", () => {
    expect(Object.keys(CHK).sort()).toEqual([...EXPECTED_CHK_IDS].sort());
  });

  test("every entry has a non-empty meaning and a valid disposition", () => {
    for (const id of EXPECTED_CHK_IDS) {
      const entry = CHK[id];
      expect(entry.meaning.length).toBeGreaterThan(0);
      expect(VALID_DISPOSITIONS).toContain(entry.disposition);
    }
  });

  test("CHK-MOCK is the mock-deny discriminant", () => {
    expect(CHK["CHK-MOCK"].disposition).toBe("mock-deny");
  });
});
