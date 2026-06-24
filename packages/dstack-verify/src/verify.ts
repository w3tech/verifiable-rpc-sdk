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
// Both `app_compose` and `compose_hash` come from the SAME node (its own GET
// /info + /attestation). The check only proves the node is internally
// consistent: a malicious node simply reports an app_compose that hashes to its
// own forged compose_hash and passes A2 trivially. It is attacker-forgeable and
// raises the bar against accidental config drift ONLY. Real compose trust needs
// (a) an INDEPENDENT compose source the node cannot forge, (b) the compose_hash
// anchored into RTMR3 via event-log replay, and (c) a DCAP-verified quote — all
// deferred to a future release.
//
// After A2, the mock gate still governs the NOT-yet-built DCAP quote-signature +
// RTMR3-replay layers: default (allowInsecureMock absent/false) throws
// AttestationError("CHK-MOCK"); allowInsecureMock === true resolves void
// silently (the SDK never prints; bypassing the hardware root of trust is the
// caller's explicit opt-in).

// computeComposeHash is imported from core's `./compose` LEAF subpath (not the
// main barrel): the barrel re-exports trusted-verifier.ts which imports
// @ankr.com/dstack-verify, re-opening the ESM init cycle. compose.ts is
// cycle-free. (The local verify-steps.ts `computeComposeHash` is still a
// throwing stub — do NOT use it.) This keeps @noble/hashes out of dstack-verify.
import { computeComposeHash } from "@ankr.com/vrpc-core/compose";

import { AttestationError } from "./errors";
import type { AttestationBundle, VerifyPolicy } from "./types";
import { parseReportData } from "./verify-steps";

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

  // --- Mock gate: covers the unimplemented DCAP/RTMR3 layers only ---
  if (policy.allowInsecureMock === true) {
    return;
  }
  throw new AttestationError(
    "CHK-MOCK",
    "DCAP quote-signature / RTMR3 verification is not implemented; set allowInsecureMock=true to bypass the hardware root of trust (INSECURE)",
  );
}
