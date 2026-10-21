// verifyDstackAttestation: CHK-A1 binding, CHK-A2 compose self-consistency and the
// mandatory hardware verifier (CHK-P1 without one).
// Fixture: tests/fixtures/attestation-sample.json.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  collectingLogger,
  mockHardwareVerifier,
  rejectionOf,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import { AttestationError, parseReportData, verifyDstackAttestation } from "../src/index";
import type { AttestationBundle, HardwareVerifier, Logger, VerifyPolicy } from "../src/types";
// computeComposeHash (verify-steps.ts) — the SAME hashing the verifier uses
// (raw sha256, no canonicalization), so the test can synthesize self-consistent
// app_compose/compose_hash pairs.
import { computeComposeHash } from "../src/verify-steps";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/attestation-sample.json", import.meta.url)),
    "utf8",
  ),
) as { pubkey: string; nonce: string; report_data: string };

function makeBundle(
  reportData: string,
  compose: { appCompose?: string; composeHash?: string } = {},
): AttestationBundle {
  return { quote: "", reportData, appCompose: "", composeHash: "", ...compose };
}
function makePolicy(p: {
  expectedPubkey: string;
  expectedNonce: string;
  hardwareVerifier?: HardwareVerifier;
  logger?: Logger;
}): VerifyPolicy {
  return {
    binding: { expectedPubkey: p.expectedPubkey, expectedNonce: p.expectedNonce },
    hardwareVerifier: p.hardwareVerifier ?? mockHardwareVerifier(),
    ...(p.logger === undefined ? {} : { logger: p.logger }),
  };
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
    const err = thrownBy(() => parseReportData(bad));
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });
});

describe("verifyDstackAttestation CHK-A1 binding", () => {
  test("happy path: A1 passes, mandatory verifier resolves", async () => {
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("hardwareVerifier is required: a type error, and CHK-P1 at runtime", async () => {
    // @ts-expect-error hardwareVerifier is required
    const policy: VerifyPolicy = { binding: validBinding };
    await expect(verifyDstackAttestation(validBundle, policy)).rejects.toMatchObject({
      chkId: "CHK-P1",
    });
  });

  test("tamper: wrong pubkey throws CHK-A1", async () => {
    const wrongPubkey = `0x${"cc".repeat(32)}`;
    const err = await rejectionOf(
      verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, expectedPubkey: wrongPubkey }),
      ),
    );
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });

  test("tamper: wrong nonce throws CHK-A1", async () => {
    const wrongNonce = "dd".repeat(32);
    const err = await rejectionOf(
      verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, expectedNonce: wrongNonce }),
      ),
    );
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });

  test("tamper: wrong-length report_data throws CHK-A1", async () => {
    const shortRd = fixture.report_data.slice(0, 126);
    const err = await rejectionOf(
      verifyDstackAttestation(makeBundle(shortRd), makePolicy({ ...validBinding })),
    );
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });

  test("malformed expectedPubkey (missing 0x / wrong len) throws CHK-A1", async () => {
    const err = await rejectionOf(
      verifyDstackAttestation(
        validBundle,
        makePolicy({
          ...validBinding,
          expectedPubkey: fixture.pubkey.slice(2),
        }),
      ),
    );
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });
});

describe("verifyDstackAttestation hardware verifier (post-A2) — MANDATORY", () => {
  test("runs the configured verifier and resolves on success", async () => {
    await expect(
      verifyDstackAttestation(validBundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("propagates the verifier's failure (fail-closed)", async () => {
    const boom = new AttestationError("CHK-P1", "hardware verify failed");
    const err = await rejectionOf(
      verifyDstackAttestation(
        validBundle,
        makePolicy({ ...validBinding, hardwareVerifier: mockHardwareVerifier({ fail: boom }) }),
      ),
    );
    expect(err).toBe(boom);
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
// consistency only (forgeable, NOT a trust anchor). It runs after CHK-A1.
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

  test("hash-match: self-consistent pair passes", async () => {
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: selfConsistentHash,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("hash-match: also accepts a 0x-prefixed compose_hash (normalized)", async () => {
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: `0x${selfConsistentHash.toUpperCase()}`,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("mismatch: wrong compose_hash throws CHK-A2", async () => {
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: "00".repeat(32), // not the hash of appCompose
    });
    const err = await rejectionOf(verifyDstackAttestation(bundle, makePolicy({ ...validBinding })));
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A2");
  });

  test("mismatch: tampered app_compose (hash no longer matches) throws CHK-A2", async () => {
    const bundle = makeBundle(fixture.report_data, {
      appCompose: `${appCompose} `, // one trailing space → different sha256
      composeHash: selfConsistentHash,
    });
    const err = await rejectionOf(verifyDstackAttestation(bundle, makePolicy({ ...validBinding })));
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A2");
  });

  test("dormant-skip: empty app_compose → A2 skips, resolves", async () => {
    // Non-empty compose_hash but EMPTY app_compose (older node / no /info) — A2
    // must NOT throw.
    const bundle = makeBundle(fixture.report_data, {
      appCompose: "",
      composeHash: selfConsistentHash,
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("dormant-skip: empty compose_hash (simulator) → A2 skips, no throw", async () => {
    // Non-empty app_compose but EMPTY compose_hash — the dstack simulator's
    // --allow-empty-compose-hash posture. A2 must dormant-skip, NOT throw.
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: "",
    });
    await expect(
      verifyDstackAttestation(bundle, makePolicy({ ...validBinding })),
    ).resolves.toBeUndefined();
  });

  test("ordering: CHK-A1 still throws BEFORE CHK-A2 even when compose is self-inconsistent", async () => {
    // Wrong nonce (A1 fail) + inconsistent compose (A2 would fail) → A1 wins.
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: "00".repeat(32),
    });
    const err = await rejectionOf(
      verifyDstackAttestation(
        bundle,
        makePolicy({
          expectedPubkey: fixture.pubkey,
          expectedNonce: "dd".repeat(32),
        }),
      ),
    );
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as AttestationError).chkId).toBe("CHK-A1");
  });
});

// Opt-in logger narration (Plan 02): verifyDstackAttestation emits points 9-10
// ONLY when policy.logger is injected. Field-check + hardware-verify events
// fire; chkA2 reports dormant-skip when the compose pair is incomplete.
describe("verifyDstackAttestation logger narration (points 9-10)", () => {
  const appCompose = JSON.stringify({
    manifest_version: 2,
    name: "vrpc-arbitrum",
    runner: "docker-compose",
    docker_compose_file:
      "services:\n  rpc:\n    image: ankrnetwork/ankr-snapshot@sha256:deadbeef\n",
  });
  const selfConsistentHash = computeComposeHash(appCompose);

  test("emits attestation.fieldChecks and hardware.verify on the happy path", async () => {
    const log = collectingLogger();
    await verifyDstackAttestation(validBundle, makePolicy({ ...validBinding, logger: log }));

    const names = log.calls.map((c) => c[0]);
    expect(names).toContain("attestation.fieldChecks");
    expect(names).toContain("hardware.verify");
  });

  test("fieldChecks reports chkA2 ok when the compose pair is self-consistent", async () => {
    const bundle = makeBundle(fixture.report_data, {
      appCompose,
      composeHash: selfConsistentHash,
    });
    const log = collectingLogger();
    await verifyDstackAttestation(bundle, makePolicy({ ...validBinding, logger: log }));

    const fc = log.calls.find((c) => c[0] === "attestation.fieldChecks")?.[1] as Record<
      string,
      unknown
    >;
    expect(fc).toBeDefined();
    expect(fc.chkA1).toBe("reportData-binding ok");
    expect(fc.chkA2).toBe("ok");
  });

  test("fieldChecks reports chkA2 dormant-skip when compose is incomplete", async () => {
    // validBundle has empty appCompose/composeHash → A2 dormant.
    const log = collectingLogger();
    await verifyDstackAttestation(validBundle, makePolicy({ ...validBinding, logger: log }));

    const fc = log.calls.find((c) => c[0] === "attestation.fieldChecks")?.[1] as Record<
      string,
      unknown
    >;
    expect(fc).toBeDefined();
    expect(fc.chkA2).toBe("dormant-skip");
  });

  test("emits nothing when no logger is injected", async () => {
    const log = collectingLogger();
    // Policy WITHOUT a logger — the collecting logger is never wired in.
    await verifyDstackAttestation(validBundle, makePolicy({ ...validBinding }));
    expect(log.calls).toHaveLength(0);
  });
});
