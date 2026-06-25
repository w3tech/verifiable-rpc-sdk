// verifyDstackAttestation behavior — CHK-A1 binding + the MANDATORY hardware
// verifier step (→ CHK-P1) that supersedes the old mock gate.
//
// CHK-A1 runs FIRST and is UNCONDITIONAL: it shape-gates report_data, then binds
// report_data[0:32]==expectedPubkey and report_data[32:64]==expectedNonce. A
// mismatch throws AttestationError("CHK-A1") regardless of any other policy
// field. After A1 (and CHK-A2) pass, the hardware verifier step is MANDATORY:
//   - no policy.hardwareVerifier → throws CHK-P1 ("required").
//   - with a (no-network) hardware verifier → resolves.
//   - a failing hardware verifier → its error propagates.
// Fixture: tests/fixtures/attestation-sample.json.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
// computeComposeHash from core's leaf subpath — the local dstack-verify
// re-export (verify-steps.ts) is still a throwing stub, so the test
// synthesizes self-consistent compose pairs with the SAME hashing the verifier
// uses (raw sha256, no canonicalization).
import { computeComposeHash } from "@ankr.com/vrpc-core/compose";
import { describe, expect, test } from "vitest";
import type { HardwareVerifier } from "../src/hardware-verifier";
import { AttestationError, parseReportData, verifyDstackAttestation } from "../src/index";
import type { AttestationBundle, TcbInfo, VerifyPolicy } from "../src/types";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

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
// The hardware verifier is now MANDATORY. By default makePolicy injects a
// no-network passing mock so CHK-A1/A2 happy paths resolve; pass `noVerifier`
// to omit it (exercise the CHK-P1 "required" throw) or `hardwareVerifier` to
// supply a specific (e.g. failing) mock. `allowInsecureMock` is accepted but
// INERT (legacy field; it no longer gates anything).
function makePolicy(p: {
  expectedPubkey: string;
  expectedNonce: string;
  allowInsecureMock?: boolean;
  hardwareVerifier?: HardwareVerifier;
  noVerifier?: boolean;
}): VerifyPolicy {
  const hv = p.noVerifier ? undefined : (p.hardwareVerifier ?? mockHardwareVerifier());
  return {
    binding: { expectedPubkey: p.expectedPubkey, expectedNonce: p.expectedNonce },
    ...(hv === undefined ? {} : { hardwareVerifier: hv }),
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
  test("happy path: A1 passes, mandatory verifier resolves", async () => {
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("A1 passes then fail-closed CHK-P1 when no hardwareVerifier", async () => {
    try {
      await verifyDstackAttestation(validBundle, makePolicy({ ...validBinding, noVerifier: true }));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-P1");
    }
  });

  // A1 throws even with allowInsecureMock=true.
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

describe("verifyDstackAttestation hardware verifier (post-A2) — MANDATORY", () => {
  test("throws CHK-P1 when no hardwareVerifier is configured (A1+A2 passed)", async () => {
    try {
      await verifyDstackAttestation(validBundle, makePolicy({ ...validBinding, noVerifier: true }));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(AttestationError);
      expect((e as AttestationError).chkId).toBe("CHK-P1");
    }
  });

  test("runs the configured verifier and resolves on success", async () => {
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("propagates the verifier's failure (fail-closed)", async () => {
    const boom = new AttestationError("CHK-P1", "hardware verify failed");
    try {
      await verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, hardwareVerifier: mockHardwareVerifier({ fail: boom }) }),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBe(boom);
    }
  });

  test("invokes the verifier with the bundle under test", async () => {
    let seenBundle: unknown;
    const recording: HardwareVerifier = {
      async verifyHardware(b) {
        seenBundle = b;
      },
    };
    await verifyDstackAttestation(
      validBundle,
      makePolicy({ ...validBinding, hardwareVerifier: recording }),
    );
    expect(seenBundle).toBe(validBundle);
  });

  test("resolves on every call with a configured verifier", async () => {
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });
});

// CHK-A2: compose-hash self-consistency. app_compose +
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

  test("hash-match: self-consistent pair passes, falls through to mock gate", async () => {
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: selfConsistentHash,
    });
    // A2 passes (no throw) → mock gate resolves with allowInsecureMock=true.
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
  });

  test("hash-match: also accepts a 0x-prefixed compose_hash (normalized)", async () => {
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: `0x${selfConsistentHash.toUpperCase()}`,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
  });

  test("mismatch: wrong compose_hash throws CHK-A2 even with allowInsecureMock=true", async () => {
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

  test("mismatch: tampered app_compose (hash no longer matches) throws CHK-A2", async () => {
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

  test("dormant-skip: empty app_compose → A2 skips, mock gate resolves", async () => {
    // Non-empty compose_hash but EMPTY app_compose (older node / no /info) — A2
    // must NOT throw; verify completes through to the mock gate.
    const bundle = makeBundle(fixture.report_data, {
      app_compose: "",
      compose_hash: selfConsistentHash,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
  });

  test("dormant-skip: empty compose_hash (simulator) → A2 skips, no throw", async () => {
    // Non-empty app_compose but EMPTY compose_hash — the dstack simulator's
    // --allow-empty-compose-hash posture. A2 must dormant-skip, NOT throw.
    const bundle = makeBundle(fixture.report_data, {
      app_compose: appCompose,
      compose_hash: "",
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
  });

  test("dormant-skip: absent compose_hash (undefined) → A2 skips, no throw", async () => {
    // Non-empty app_compose, compose_hash field entirely absent — A2 dormant-skips.
    const bundle = makeBundle(fixture.report_data, { app_compose: appCompose });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding, allowInsecureMock: true })),
    ).resolves.toBeUndefined();
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
