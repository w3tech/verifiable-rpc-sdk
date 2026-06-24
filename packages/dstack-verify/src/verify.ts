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
// After A1, the mock gate still governs the NOT-yet-built DCAP quote-signature +
// RTMR3-replay layers (VPKG-03/VPKG-04): default (allowInsecureMock absent/false)
// throws AttestationError("CHK-MOCK"); allowInsecureMock === true resolves void with
// a prominent console.warn banner on EVERY call (not memoized — a mock must never
// silently masquerade as real verification in prod logs).

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
  // parseReportData also shape-gates report_data to exactly 128 hex chars (BIND-01).
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

  // --- Mock gate: covers the unimplemented DCAP/RTMR3 layers only ---
  if (policy.allowInsecureMock === true) {
    console.warn(
      "[dstack-verify] PARTIAL VERIFICATION: CHK-A1 (report_data key/nonce binding) " +
        "WAS verified, but the DCAP quote-signature and RTMR3 replay were NOT. " +
        "allowInsecureMock=true bypasses the hardware root of trust — this proves " +
        '"signed + bound + fresh", NOT "attested to hardware" (lands in v7.0).',
    );
    return;
  }
  throw new AttestationError(
    "CHK-MOCK",
    "DCAP quote-signature / RTMR3 verification is not implemented; set allowInsecureMock=true to bypass the hardware root of trust (INSECURE)",
  );
}
