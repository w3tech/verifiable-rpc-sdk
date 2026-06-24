// verifyDstackAttestation behavior — CHK-A1 binding (BIND-01..05) + the mock gate
// (VPKG-03/VPKG-04) that still covers the unimplemented DCAP/RTMR3 layers.
//
// CHK-A1 runs FIRST and is UNCONDITIONAL: it shape-gates report_data, then binds
// report_data[0:32]==expectedPubkey and report_data[32:64]==expectedNonce. A
// mismatch throws AttestationError("CHK-A1") regardless of allowInsecureMock. After
// A1 passes, the mock gate throws CHK-MOCK (default) or resolves+warns
// (allowInsecureMock===true). Fixture: tests/fixtures/attestation-sample.json.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test, vi } from "vitest";

import { AttestationError, parseReportData, verifyDstackAttestation } from "../src/index";
import type { AttestationBundle, VerifyPolicy } from "../src/types";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/attestation-sample.json", import.meta.url)),
    "utf8",
  ),
) as { pubkey: string; nonce: string; report_data: string };

// Minimal bundle/policy builders — only the fields CHK-A1 reads are populated;
// the rest is cast through `unknown` (the package never inspects them here).
function makeBundle(reportData: string): AttestationBundle {
  return { quote: { report_data: reportData } } as unknown as AttestationBundle;
}
function makePolicy(p: {
  expectedPubkey: string;
  expectedNonce: string;
  allowInsecureMock?: boolean;
}): VerifyPolicy {
  return {
    binding: { expectedPubkey: p.expectedPubkey, expectedNonce: p.expectedNonce },
    allowInsecureMock: p.allowInsecureMock,
  } as unknown as VerifyPolicy;
}

const validBundle = makeBundle(fixture.report_data);
const validBinding = { expectedPubkey: fixture.pubkey, expectedNonce: fixture.nonce };

describe("parseReportData (CHK-A1 split)", () => {
  test("splits 128-hex report_data into 0x-pubkey ‖ bare-nonce", () => {
    const parsed = parseReportData(fixture.report_data);
    expect(parsed.expectedPubkey).toBe(fixture.pubkey);
    expect(parsed.expectedNonce).toBe(fixture.nonce);
  });

  test("accepts a 0x-prefixed report_data", () => {
    const parsed = parseReportData(`0x${fixture.report_data}`);
    expect(parsed.expectedPubkey).toBe(fixture.pubkey);
    expect(parsed.expectedNonce).toBe(fixture.nonce);
  });

  test.each([
    fixture.report_data.slice(0, 126), // too short
    `${fixture.report_data}aa`, // too long
    `${fixture.report_data.slice(0, 127)}z`, // non-hex char
    "",
  ])("throws CHK-A1 on malformed length/charset %#", (bad) => {
    try {
      parseReportData(bad);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });
});

describe("verifyDstackAttestation CHK-A1 binding", () => {
  test("happy path: A1 passes, mock gate resolves with allowInsecureMock=true", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(
      verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, allowInsecureMock: true }),
      ),
    ).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  test("A1 passes then fail-closed CHK-MOCK when allowInsecureMock absent", async () => {
    try {
      await verifyDstackAttestation(validBundle, makePolicy(validBinding));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-MOCK");
    }
  });

  // BIND-04: A1 throws even with allowInsecureMock=true.
  test("tamper: wrong pubkey throws CHK-A1 even with allowInsecureMock=true", async () => {
    const wrongPubkey = `0x${"cc".repeat(32)}`;
    try {
      await verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, expectedPubkey: wrongPubkey, allowInsecureMock: true }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });

  test("tamper: wrong nonce throws CHK-A1 even with allowInsecureMock=true", async () => {
    const wrongNonce = "dd".repeat(32);
    try {
      await verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, expectedNonce: wrongNonce, allowInsecureMock: true }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });

  test("tamper: wrong-length report_data throws CHK-A1 even with allowInsecureMock=true", async () => {
    const shortRd = fixture.report_data.slice(0, 126);
    try {
      await verifyDstackAttestation(
        makeBundle(shortRd),
        makePolicy({ ...validBinding, allowInsecureMock: true }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });

  test("malformed expectedPubkey (missing 0x / wrong len) throws CHK-A1", async () => {
    try {
      await verifyDstackAttestation(
        validBundle,
        makePolicy({
          ...validBinding,
          expectedPubkey: fixture.pubkey.slice(2),
          allowInsecureMock: true,
        }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A1");
    }
  });
});

describe("verifyDstackAttestation mock gate (post-A1)", () => {
  test("throws CHK-MOCK when allowInsecureMock is false (A1 passed)", async () => {
    try {
      await verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, allowInsecureMock: false }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-MOCK");
    }
  });

  // Security boundary: only the literal boolean `true` resolves. Every
  // truthy-but-not-true / falsy value still throws CHK-MOCK once A1 passes — a
  // regression to `==`/`Boolean(...)` would fail loudly.
  test.each([
    1,
    "true",
    {},
    undefined,
    null,
  ])("throws CHK-MOCK for truthy-but-not-true / absent allowInsecureMock=%p", async (v) => {
    try {
      await verifyDstackAttestation(validBundle, {
        binding: validBinding,
        allowInsecureMock: v,
      } as unknown as VerifyPolicy);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-MOCK");
    }
  });

  test("resolves with allowInsecureMock=true and warns on EVERY call (not memoized)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await verifyDstackAttestation(
      validBundle,
      makePolicy({ ...validBinding, allowInsecureMock: true }),
    );
    await verifyDstackAttestation(
      validBundle,
      makePolicy({ ...validBinding, allowInsecureMock: true }),
    );
    expect(warn).toHaveBeenCalledTimes(2);
    warn.mockRestore();
  });
});
