// The single error type this package throws. Mirrors the abstract
// `VerificationError` base in @ankr.com/vrpc-core: `name` is auto-set by the
// base from `this.constructor.name`, and `kind` is a readonly string-literal.
//
// NOTE: core's `VerificationErrorKind` is a CLOSED union that does NOT include
// "Attestation". `AttestationError.kind = "Attestation"` satisfies the abstract
// member as a string-literal without widening core's union. Consumers narrow via
// `instanceof AttestationError` — do NOT edit core's union (T-33-01).

import { VerificationError } from "@ankr.com/vrpc-core";
import type { ChkId } from "./checklist";

/**
 * Thrown when dstack/TDX attestation verification fails (or is mock-denied in
 * v5.0). Carries which `CHK-*` item failed plus a human-readable detail. The
 * fail-closed contract means callers catch this rather than inspect a boolean.
 */
export class AttestationError extends VerificationError {
  readonly kind = "Attestation" as const;

  constructor(
    public readonly chk: ChkId,
    public readonly detail: string,
    options?: { cause?: unknown },
  ) {
    super(`Attestation verification failed [${chk}]: ${detail}`);
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
