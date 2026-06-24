// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The single error type this package throws. Mirrors the abstract
// `VerificationError` base in @ankr.com/vrpc-core: `name` is auto-set by the
// base from `this.constructor.name`, and `kind` is a readonly string-literal.
//
// NOTE: core's `VerificationErrorKind` is a CLOSED union that does NOT include
// "Attestation". The abstract base types `kind: VerificationErrorKind`, so under
// strict TS an override literal MUST be assignable to that union — a bare
// `readonly kind = "Attestation" as const` does NOT type-check (TS2416). To keep
// core's union byte-untouched (T-33-01) while still exposing the "Attestation"
// discriminant at runtime, we declare the override with the base union type and
// initialize it via a cast. Consumers narrow via `instanceof AttestationError`
// (the established idiom) — never via core's union — and `error.kind` reads back
// as the literal "Attestation" at runtime. Do NOT edit core's union.

// Import the base from the leaf `/errors` subpath (not the full barrel) so we
// don't pull all of @ankr.com/vrpc-core back in — that closes the
// core<->dstack-verify ESM init cycle (otherwise VerificationError is undefined
// at class-extends time under Node's bundled-ESM load order).
import { VerificationError, type VerificationErrorKind } from "@ankr.com/vrpc-core/errors";
import type { ChkId } from "./checklist";

/** The discriminant literal this package's error reports, outside core's closed union. */
export type AttestationErrorKind = "Attestation";

/**
 * Thrown when dstack/TDX attestation verification fails (or is mock-denied in
 * the current release). Carries which `CHK-*` item failed plus a human-readable detail. The
 * fail-closed contract means callers catch this rather than inspect a boolean.
 */
export class AttestationError extends VerificationError {
  // Runtime value is the "Attestation" literal; static type stays the base union
  // so the abstract `kind` override is assignable without editing core (T-33-01).
  readonly kind: VerificationErrorKind = "Attestation" as VerificationErrorKind;

  constructor(
    public readonly chkId: ChkId,
    public readonly detail: string,
    options?: { cause?: unknown },
  ) {
    super(`Attestation verification failed [${chkId}]: ${detail}`);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
