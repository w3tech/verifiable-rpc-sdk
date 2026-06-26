// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// verifyDstackAttestation — the public attestation-verifier entrypoint. Its
// signature is frozen in the contract; this file holds its body.
//
// CHK-A1 (key/nonce binding) runs FIRST and is UNCONDITIONAL: it shape-gates the
// quote's report_data, then proves report_data[0:32] == policy.binding.expectedPubkey
// (the Ed25519 key the SDK verifies vRPC-Signature against — swapped-key/wrong-node
// defence) and report_data[32:64] == policy.binding.expectedNonce (freshness /
// anti-replay). A mismatch ALWAYS throws AttestationError("CHK-A1"), regardless of
// allowInsecureMock. This is local + collateral-free: it proves "signed + bound +
// fresh", NOT "attested to hardware" (a fabricated quote can carry arbitrary
// report_data — A1 is only meaningful together with the deferred DCAP/RTMR layers).
//
// CHK-A2 (compose-hash self-consistency) runs AFTER A1, BEFORE the mock gate. It
// is BEST-EFFORT / DORMANT-BY-DEFAULT: only when bundle.tcbInfo.app_compose is
// non-empty AND tcbInfo.compose_hash is present + non-empty does it assert
// computeComposeHash(app_compose) === normalize(compose_hash) (raw sha256, no
// canonicalization); otherwise it SKIPS (no throw). It throws CHK-A2 on mismatch
// even under allowInsecureMock (it precedes the mock gate).
//
// ⚠️ TRUST BOUNDARY — CHK-A2 is SELF-CONSISTENCY ONLY, NOT a trust anchor.
// Both `app_compose` and `compose_hash` come from the SAME node (its own
// /attestation response). The check only proves the node is internally
// consistent: a malicious node simply reports an app_compose that hashes to its
// own forged compose_hash and passes A2 trivially. It is attacker-forgeable and
// raises the bar against accidental config drift ONLY. Real compose trust needs
// (a) an INDEPENDENT compose source the node cannot forge, (b) the compose_hash
// anchored into RTMR3 via event-log replay, and (c) a DCAP-verified quote — all
// deferred to a future release.
//
// After A2, step-4 hardware-signature verification runs and is MANDATORY:
// policy.hardwareVerifier IS the hardware root of trust for the call. If no
// verifier is configured the function throws AttestationError (fail-closed — an
// unattested response must never pass). On success it resolves; any verifier
// failure throws. In the live SDK path core's buildVerifyPolicy always wires the
// Phala CloudVerifier here. (`allowInsecureMock` / `CHK-MOCK` are a separate,
// now-unused legacy gate — the mandatory verifier supersedes them.)

import { AttestationError } from "./errors";
import type { AttestationBundle, VerifyPolicy } from "./types";
// computeComposeHash lives in this package (verify-steps.ts) — compose-hash is a
// dstack/TDX concept used only by CHK-A2, so it has no reason to live in core.
import { computeComposeHash, parseReportData } from "./verify-steps";

/** Bare lowercase hex for comparison (strip optional `0x`, lowercase). */
function normHex(s: string): string {
  return s.replace(/^0x/i, "").toLowerCase();
}

export async function verifyDstackAttestation(
  bundle: AttestationBundle,
  policy: VerifyPolicy,
): Promise<void> {
  // --- CHK-A1: report_data → pubkey/nonce binding (unconditional, fail-closed) ---
  if (!/^0x[0-9a-fA-F]{64}$/.test(policy.binding.expectedPubkey)) {
    throw new AttestationError(
      "CHK-A1",
      "policy.binding.expectedPubkey must be 0x + 64 hex chars (32-byte Ed25519 key)",
    );
  }
  // parseReportData also shape-gates report_data to exactly 128 hex chars.
  const parsed = parseReportData(bundle.quote.report_data);
  if (normHex(parsed.expectedPubkey) !== normHex(policy.binding.expectedPubkey)) {
    throw new AttestationError(
      "CHK-A1",
      "report_data[0:32] does not match expected signing pubkey (swapped-key / wrong-node)",
    );
  }
  if (normHex(parsed.expectedNonce) !== normHex(policy.binding.expectedNonce)) {
    throw new AttestationError(
      "CHK-A1",
      "report_data[32:64] does not match expected nonce (possible replay)",
    );
  }

  // --- CHK-A2: compose-hash self-consistency (best-effort, dormant by default) ---
  // SELF-CONSISTENCY ONLY — see the trust-boundary note at the top of this file.
  // app_compose + compose_hash are BOTH self-reported by the node, so a pass
  // proves only internal consistency (forgeable); it is NOT a hardware/trust
  // anchor. Anchoring (independent compose source + RTMR3 replay + DCAP) is future work.
  const appCompose = bundle.tcbInfo?.app_compose ?? "";
  const reportedComposeHash = bundle.tcbInfo?.compose_hash ?? "";
  // Dormant-skip when EITHER side is empty/absent (older nodes / the simulator's
  // empty composeHash). Both empties are handled explicitly here — no silent pass.
  if (appCompose !== "" && reportedComposeHash !== "") {
    // computeComposeHash returns bare lowercase hex; normHex strips any 0x +
    // lowercases the reported hash so the comparison is canonical on both sides.
    if (computeComposeHash(appCompose) !== normHex(reportedComposeHash)) {
      throw new AttestationError(
        "CHK-A2",
        "sha256(utf8(app_compose)) does not match the reported compose_hash (config self-inconsistency)",
      );
    }
  }

  // Narrate the field-check outcomes (point 9). Built only when a logger is
  // injected (policy.logger is undefined on the silent path). chkA2 reports
  // dormant-skip when EITHER side of the compose pair was empty — the same
  // condition the CHK-A2 block above gated on.
  if (policy.logger) {
    const chkA2 = appCompose !== "" && reportedComposeHash !== "" ? "ok" : "dormant-skip";
    policy.logger.debug("attestation.fieldChecks", {
      chkA1: "reportData-binding ok",
      chkA2,
    });
  }

  // --- Step-4: hardware-signature verifier (→ CHK-P1) — MANDATORY ---
  // policy.hardwareVerifier IS the hardware root of trust for this call. It is
  // REQUIRED: a policy without one cannot establish hardware trust, so fail
  // closed rather than return an unattested "pass". On success the function
  // resolves; any verifier failure throws AttestationError. The live SDK path
  // (core buildVerifyPolicy) always wires the Phala CloudVerifier.
  if (!policy.hardwareVerifier) {
    throw new AttestationError(
      "CHK-P1",
      "no hardware verifier configured: policy.hardwareVerifier is required (hardware-signature verification cannot be skipped)",
    );
  }
  // Pre-call narration (point 10): the hardware verifier is about to run. The
  // verifier itself (e.g. CloudVerifier) emits its own hardware.verify with the
  // verdict + binds; this records the invocation regardless of verifier kind.
  if (policy.logger) {
    policy.logger.debug("hardware.verify", { verifier: "hardware-verifier", invoking: true });
  }
  await policy.hardwareVerifier.verifyHardware(bundle, policy);
}
