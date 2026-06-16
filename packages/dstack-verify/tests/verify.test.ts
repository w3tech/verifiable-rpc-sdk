// Mock verifier behavior — VPKG-03/VPKG-04/TEST-01.
//
// Fail-closed contract: verifyDstackAttestation throws AttestationError("CHK-MOCK")
// unless policy.allowInsecureMock === true, in which case it resolves void and
// emits a LOUD console.warn on EVERY call (not memoized). Mirrors the bun:test
// idiom in core/tests/errors.test.ts.

import { describe, expect, spyOn, test } from "bun:test";

import { AttestationError, verifyDstackAttestation } from "../src/index";
import type { VerifyPolicy } from "../src/types";

// The mock body never inspects the bundle — it branches only on
// policy.allowInsecureMock, so a minimal cast is sufficient.
const bundle = {} as never;

describe("verifyDstackAttestation mock", () => {
  test("throws AttestationError(CHK-MOCK) when allowInsecureMock is false", async () => {
    await expect(
      verifyDstackAttestation(bundle, { allowInsecureMock: false } as never),
    ).rejects.toBeInstanceOf(AttestationError);
    try {
      await verifyDstackAttestation(bundle, { allowInsecureMock: false } as never);
      throw new Error("expected rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chk).toBe("CHK-MOCK");
    }
  });

  test("throws by default when allowInsecureMock is absent (default-deny)", async () => {
    await expect(verifyDstackAttestation(bundle, {} as never)).rejects.toBeInstanceOf(
      AttestationError,
    );
  });

  // Security boundary: only the literal boolean `true` may resolve. Pin that
  // every truthy-but-not-true and falsy value still throws, so a regression to
  // `==`/`Boolean(...)` (instead of strict `=== true`) fails loudly.
  test.each([
    1,
    "true",
    {},
    undefined,
    null,
  ])("rejects (AttestationError) for truthy-but-not-true / absent allowInsecureMock=%p", async (v) => {
    await expect(
      verifyDstackAttestation(bundle, {
        allowInsecureMock: v,
      } as unknown as VerifyPolicy),
    ).rejects.toBeInstanceOf(AttestationError);
  });

  test("resolves with allowInsecureMock=true and warns on EVERY call (not memoized)", async () => {
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    await verifyDstackAttestation(bundle, { allowInsecureMock: true } as never);
    await verifyDstackAttestation(bundle, { allowInsecureMock: true } as never);
    expect(warn).toHaveBeenCalledTimes(2);
    warn.mockRestore();
  });
});
