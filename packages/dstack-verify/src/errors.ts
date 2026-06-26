// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The single error type this package throws.
//
// AttestationError extends the built-in `Error` directly — it deliberately does
// NOT extend core's `VerificationError`. That keeps @ankr.com/dstack-verify a
// dependency-free LEAF (no import of @ankr.com/vrpc-core, in any form), so the
// package graph is strictly one-way: core → dstack-verify, with no cycle.
//
// core catches this at the `verifyDstackAttestation` call boundary and re-wraps
// it into its own `VerificationError` family (preserving `chkId`/`detail` and
// attaching the original as `cause`), so the SDK's public error contract —
// callers catch `VerificationError` — is unchanged.
import type { ChkId } from "./checklist";

/** The discriminant literal this package's error reports. */
export type AttestationErrorKind = "Attestation";

/**
 * Thrown when dstack/TDX attestation verification fails (or is mock-denied in
 * the current release). Carries which `CHK-*` item failed plus a human-readable
 * detail. The fail-closed contract means callers catch this rather than inspect a
 * boolean. Standalone (not a core `VerificationError`) to keep this package a
 * leaf; core re-wraps it into its `VerificationError` family at the call boundary.
 */
export class AttestationError extends Error {
  readonly kind: AttestationErrorKind = "Attestation";

  constructor(
    public readonly chkId: ChkId,
    public readonly detail: string,
    options?: { cause?: unknown },
  ) {
    super(`Attestation verification failed [${chkId}]: ${detail}`);
    // The built-in Error base leaves `name` as "Error"; set it from the concrete
    // constructor so logs / serialisation report "AttestationError".
    this.name = this.constructor.name;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
