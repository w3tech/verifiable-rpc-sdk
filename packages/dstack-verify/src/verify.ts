// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// verifyDstackAttestation: CHK-A1, CHK-A2, then the mandatory hardware verifier.
//
// CHK-A1 proves report_data == expectedPubkey ‖ expectedNonce (signed, bound,
// fresh); it does not prove hardware attestation on its own.
//
// CHK-A2 runs only when both appCompose and composeHash are non-empty and
// asserts sha256(appCompose) == composeHash. Both values are self-reported by
// the node, so a pass proves internal consistency only, never compose trust.
//
// The hardware verifier is the root of trust: without one the call throws
// CHK-P1, so an unattested response never passes.

import { AttestationError } from "./errors";
import type { AttestationBundle, VerifyPolicy } from "./types";
// computeComposeHash lives in this package (verify-steps.ts) — compose-hash is a
// dstack/TDX concept used only by CHK-A2, so it has no reason to live in core.
import { computeComposeHash, normHex, parseReportData } from "./verify-steps";

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
  const parsed = parseReportData(bundle.reportData);
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
  const appCompose = bundle.appCompose;
  const reportedComposeHash = bundle.composeHash;
  // Dormant-skip when EITHER side is empty/absent (older nodes / the simulator's
  // empty composeHash). Both empties are handled explicitly here — no silent pass.
  const composeChecked = appCompose !== "" && reportedComposeHash !== "";
  if (composeChecked) {
    // computeComposeHash returns bare lowercase hex; normHex strips any 0x +
    // lowercases the reported hash so the comparison is canonical on both sides.
    if (computeComposeHash(appCompose) !== normHex(reportedComposeHash)) {
      throw new AttestationError(
        "CHK-A2",
        "sha256(utf8(app_compose)) does not match the reported compose_hash (config self-inconsistency)",
      );
    }
  }

  // Narrate the field-check outcomes. Built only when a logger is
  // injected (policy.logger is undefined on the silent path).
  policy.logger?.debug("attestation.fieldChecks", {
    chkA1: "reportData-binding ok",
    chkA2: composeChecked ? "ok" : "dormant-skip",
  });

  // --- Hardware-signature verifier (→ CHK-P1) — MANDATORY ---
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
  // Pre-call narration: the hardware verifier is about to run. The
  // verifier itself (e.g. CloudVerifier) emits its own hardware.verify with the
  // verdict + binds; this records the invocation regardless of verifier kind.
  policy.logger?.debug("hardware.verify", { verifier: "hardware-verifier", invoking: true });
  await policy.hardwareVerifier.verifyHardware(bundle, policy);
}
