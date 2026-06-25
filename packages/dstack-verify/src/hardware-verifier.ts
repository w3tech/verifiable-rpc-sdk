// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// HardwareVerifier — the pluggable step-4 hardware-signature seam.
//
// verifyDstackAttestation runs CHK-A1 (pubkey/nonce binding) and CHK-A2
// (compose-hash self-consistency) locally, then — when a HardwareVerifier is
// configured on the policy — delegates the hardware root-of-trust verdict to it
// (after CHK-A2, before the CHK-MOCK gate). The seam is deliberately minimal so
// that multiple implementations share ONE contract and ONE call site:
//
//   - CloudVerifier (this release, ./cloud-verifier) — POSTs the raw DCAP quote
//     to a hosted Phala-compatible verify endpoint and binds the verdict to OUR
//     pubkey/nonce/composeHash (B+ binding).
//   - LocalDcapVerifier (a future release, dcap-qvl) — verifies the quote
//     locally with no network egress. It implements THIS SAME interface and
//     drops into the SAME VerifyPolicy.hardwareVerifier field with no call-site
//     change.
//
// Contract: same throw-on-fail / resolve-on-success shape as
// verifyDstackAttestation — `verifyHardware` resolves `void` when the hardware
// signature (and any binding the implementation enforces) holds, and throws
// AttestationError (never prints) when it does not. Fail-closed by design.

import type { AttestationBundle, VerifyPolicy } from "./types";

/**
 * Pluggable hardware-signature verifier. A configured implementation IS the
 * hardware root of trust for a verifyDstackAttestation call: on success the
 * verifier resolves `void` and the CHK-MOCK gate is bypassed; on any failure it
 * throws `AttestationError` (fail-closed). Implementations MUST NOT print.
 */
export interface HardwareVerifier {
  /**
   * Verify the hardware signature of `bundle.quote.quote` and (optionally) bind
   * the verified quote body to `policy` values. Resolves on success, throws
   * `AttestationError` on failure.
   */
  verifyHardware(bundle: AttestationBundle, policy: VerifyPolicy): Promise<void>;
}
