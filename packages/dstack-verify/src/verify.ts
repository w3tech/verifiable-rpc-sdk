// verifyDstackAttestation — the public attestation-verifier entrypoint. Its
// signature is frozen in the contract; this file holds its body. In v5.0 the
// body is a fail-closed MOCK; v6.0 replaces it IN PLACE with real
// DCAP/RTMR/compose-hash/reportData verification, touching nothing outside this
// package.
//
// Fail-closed (VPKG-03/VPKG-04): the default path (allowInsecureMock absent or
// false) THROWS AttestationError("CHK-MOCK"). The verifier resolves void ONLY
// when policy.allowInsecureMock === true, and then it emits a prominent
// console.warn banner on EVERY call (not memoized — the adapters' "fire once"
// pattern is deliberately NOT copied here; a mock must never silently masquerade
// as real verification in prod logs). The body never inspects `bundle` in v5.0 —
// it branches solely on policy.allowInsecureMock.

import { AttestationError } from "./errors";
import type { AttestationBundle, VerifyPolicy } from "./types";

export async function verifyDstackAttestation(
  bundle: AttestationBundle,
  policy: VerifyPolicy,
): Promise<void> {
  void bundle;
  if (policy.allowInsecureMock === true) {
    console.warn(
      "[dstack-verify] INSECURE MOCK: attestation was NOT verified. " +
        "allowInsecureMock=true bypasses all chain-of-trust checks. " +
        "v5.0 provides NO real attestation security (real verification lands in v6.0).",
    );
    return;
  }
  throw new AttestationError(
    "CHK-MOCK",
    "real attestation verification is not implemented in v5.0; set allowInsecureMock=true to bypass (INSECURE)",
  );
}
