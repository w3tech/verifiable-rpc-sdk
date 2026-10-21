// Contract surface tests.
//
// Asserts: the public barrel exports every contract symbol; AttestationError is a
// standalone `Error` (deliberately NOT a core `VerificationError` — this package
// is a dependency-free leaf; core re-wraps it) carrying the "Attestation" kind +
// chk/name.

import { describe, expect, test } from "vitest";

import * as barrel from "../src/index";
import { AttestationError, parseReportData, verifyDstackAttestation } from "../src/index";

describe("public contract surface", () => {
  test("exports all required symbols", () => {
    expect(typeof AttestationError).toBe("function");
    expect(typeof verifyDstackAttestation).toBe("function");
    expect(typeof parseReportData).toBe("function");
  });

  test("exports the implemented compose-hash helper", () => {
    expect(typeof (barrel as Record<string, unknown>).computeComposeHash).toBe("function");
  });
});

describe("AttestationError", () => {
  test("is a standalone Error (not a core VerificationError) carrying the Attestation kind", () => {
    const e = new AttestationError("CHK-P1", "x");
    expect(e instanceof Error).toBe(true);
    expect(e instanceof AttestationError).toBe(true);
    // Standalone leaf error: `kind` is the literal "Attestation" (its own type, no
    // cast). core re-wraps this into its VerificationError family at the
    // verifyDstackAttestation boundary (see core's trusted-verifier).
    expect(e.kind).toBe("Attestation");
    expect(e.name).toBe("AttestationError");
    expect(e.chkId).toBe("CHK-P1");
    expect(e.detail).toBe("x");
    expect(e.message).toContain("CHK-P1");
  });

  test("carries an optional cause", () => {
    const cause = new Error("root");
    const e = new AttestationError("CHK-A1", "binding mismatch", { cause });
    expect((e as { cause?: unknown }).cause).toBe(cause);
  });
});
