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
// computeComposeHash from core's leaf subpath — the local dstack-verify
// re-export (verify-steps.ts) is still a v5.0 throwing stub, so the test
// synthesizes self-consistent compose pairs with the SAME hashing the verifier
// uses (raw sha256, no canonicalization).
import { computeComposeHash } from "@ankr.com/vrpc-core/compose";
import { describe, expect, test, vi } from "vitest";

import { AttestationError, parseReportData, verifyDstackAttestation } from "../src/index";
import type { AttestationBundle, TcbInfo, VerifyPolicy } from "../src/types";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/attestation-sample.json", import.meta.url)),
    "utf8",
  ),
) as { pubkey: string; nonce: string; report_data: string };

// Minimal bundle/policy builders — only the fields CHK-A1 (and, when provided,
// CHK-A2) read are populated; the rest is cast through `unknown` (the package
// never inspects them here). `tcbInfo` is optional so existing CHK-A1 callers
// stay unchanged and CHK-A2 dormant-skips for them (no tcbInfo → undefined →
// empty app_compose/compose_hash).
function makeBundle(reportData: string, tcbInfo?: Partial<TcbInfo>): AttestationBundle {
  return {
    quote: { report_data: reportData },
    ...(tcbInfo === undefined ? {} : { tcbInfo }),
  } as unknown as AttestationBundle;
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

// CHK-A2: compose-hash self-consistency (CMP-01/02/05). app_compose +
// compose_hash are both self-reported by the node — A2 proves internal
// consistency only (forgeable, NOT a trust anchor). It runs after CHK-A1 and
// before the mock gate, so it throws even under allowInsecureMock=true.
describe("verifyDstackAttestation CHK-A2 compose-hash self-consistency", () => {
  // A real-ish app-compose blob; compose_hash is the raw sha256 of its utf8 bytes
  // (NO canonicalization) — exactly the relationship the sidecar/dstack enforces.
  const appCompose = JSON.stringify({
    manifest_version: 2,
    name: "vrpc-arbitrum",
    runner: "docker-compose",
    docker_compose_file:
      "services:\n  rpc:\n    image: ankrnetwork/ankr-snapshot@sha256:deadbeef\n",
  });
  const selfConsistentHash = computeComposeHash(appCompose);

  test("CMP-01 hash-match: self-consistent pair passes, falls through to mock gate", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: selfConsistentHash,
    });
    // A2 passes (no throw) → mock gate resolves with allowInsecureMock=true.
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
    warn.mockRestore();
  });

  test("CMP-01 hash-match: also accepts a 0x-prefixed compose_hash (normalized)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: `0x${selfConsistentHash.toUpperCase()}`,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
    warn.mockRestore();
  });

  test("CMP-01 mismatch: wrong compose_hash throws CHK-A2 even with allowInsecureMock=true", async () => {
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: "00".repeat(32), // not the hash of appCompose
    });
    try {
      await verifyDstackAttestation(
        bundle,
        makePolicy({ ...validBinding, allowInsecureMock: true }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A2");
    }
  });

  test("CMP-01 mismatch: tampered app_compose (hash no longer matches) throws CHK-A2", async () => {
    const bundle = makeBundle(fixture.report_data, {
      app_compose: `${appCompose} `, // one trailing space → different sha256
      compose_hash: selfConsistentHash,
    });
    try {
      await verifyDstackAttestation(
        bundle,
        makePolicy({ ...validBinding, allowInsecureMock: true }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-A2");
    }
  });

  test("CMP-02 dormant-skip: empty app_compose → A2 skips, mock gate resolves", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    // Non-empty compose_hash but EMPTY app_compose (older node / no /info) — A2
    // must NOT throw; verify completes through to the mock gate.
    const bundle = makeBundle(fixture.report_data, {
      app_compose: "",
      compose_hash: selfConsistentHash,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
    warn.mockRestore();
  });

  test("CMP-02 dormant-skip: empty compose_hash (simulator) → A2 skips, no throw", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    // Non-empty app_compose but EMPTY compose_hash — the dstack simulator's
    // --allow-empty-compose-hash posture. A2 must dormant-skip, NOT throw.
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: "",
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
    warn.mockRestore();
  });

  test("CMP-02 dormant-skip: absent compose_hash (undefined) → A2 skips, no throw", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    // Non-empty app_compose, compose_hash field entirely absent — A2 dormant-skips.
    const bundle = makeBundle(fixture.report_data, { app_compose: appCompose });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
    warn.mockRestore();
  });

  test("ordering: CHK-A1 still throws BEFORE CHK-A2 even when compose is self-inconsistent", async () => {
    // Wrong nonce (A1 fail) + inconsistent compose (A2 would fail) → A1 wins.
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: "00".repeat(32),
    });
    try {
      await verifyDstackAttestation(
        bundle,
        makePolicy({
          expectedPubkey: fixture.pubkey,
          expectedNonce: "dd".repeat(32),
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
