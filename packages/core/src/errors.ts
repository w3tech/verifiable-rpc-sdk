// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Typed verification errors thrown by `VerifierClient.call`.
//
// Discriminated union via the `kind` field plus a class hierarchy:
//   try { ... } catch (err: unknown) {
//     if (err instanceof BadSignature) { /* err.signatureHex, err.pubkeyHex, ... */ }
//     // OR
//     if (err instanceof VerificationError && err.kind === "BadSignature") { ... }
//   }
//
// Subclass-specific context (header name, hex values, replay skew) is captured
// on instance fields for programmatic inspection; the human-readable `message`
// is derived from those fields and intended for logs / Sentry / etc.

export type VerificationErrorKind =
  | "MissingHeader"
  | "MalformedHeader"
  | "BadSignature"
  | "StaleTimestamp"
  | "InvalidNonce"
  | "MalformedAttestationResponse"
  | "MalformedInfoResponse"
  | "ComposeSourceNotImplemented"
  | "AttestationNodeNotFound"
  | "AttestationCorrelation";

/**
 * Abstract base for all verification errors. The `kind` discriminator is set
 * by each concrete subclass to a literal type, so consumers can narrow via
 * `if (err.kind === "BadSignature") { ... }` without `instanceof` chains.
 */
export abstract class VerificationError extends Error {
  abstract readonly kind: VerificationErrorKind;

  constructor(message: string) {
    super(message);
    // `this.constructor.name` reflects the concrete subclass at runtime, so
    // `JSON.stringify`-style serialisation and logging report e.g. "BadSignature"
    // rather than the abstract "VerificationError" or the v8 default "Error".
    this.name = this.constructor.name;
  }
}

/** Required `vRPC-*` response header was absent from the signed response. */
export class MissingHeader extends VerificationError {
  readonly kind = "MissingHeader" as const;

  constructor(public readonly headerName: string) {
    super(`Missing required header: ${headerName}`);
  }
}

/** `vRPC-*` response header was present but failed shape validation. */
export class MalformedHeader extends VerificationError {
  readonly kind = "MalformedHeader" as const;

  constructor(
    public readonly headerName: string,
    public readonly value: string,
    public readonly reason: string,
  ) {
    super(`Malformed header ${headerName}=${JSON.stringify(value)}: ${reason}`);
  }
}

export interface BadSignatureContext {
  /** `0x` + 128 lowercase hex chars (64-byte Ed25519 signature). */
  signatureHex: string;
  /** `0x` + 64 lowercase hex chars (32-byte Ed25519 pubkey). */
  pubkeyHex: string;
  /** sha256 of the 80-byte canonical pre-image, for diagnostics. */
  preImageSha256: Uint8Array;
}

/**
 * Ed25519 signature verification failed against the canonical pre-image.
 *
 * Carries the full signing context (signature, pubkey, pre-image digest) so
 * the caller can correlate the failure with sidecar-side logs. These values
 * are public — the signature was emitted in a response header, the pubkey
 * is bound into the TDX attestation quote — so logging them is safe.
 */
export class BadSignature extends VerificationError {
  readonly kind = "BadSignature" as const;
  readonly signatureHex: string;
  readonly pubkeyHex: string;
  readonly preImageSha256: Uint8Array;

  constructor(ctx: BadSignatureContext) {
    super(
      `Ed25519 signature verification failed (sig=${ctx.signatureHex}, pubkey=${ctx.pubkeyHex})`,
    );
    this.signatureHex = ctx.signatureHex;
    this.pubkeyHex = ctx.pubkeyHex;
    this.preImageSha256 = ctx.preImageSha256;
  }
}

export interface StaleTimestampContext {
  /** Timestamp the sidecar emitted in `vRPC-Timestamp` (unix ms). */
  observedMs: bigint;
  /** Client wall clock at the moment of the verify check (unix ms). */
  nowMs: bigint;
  /** `observedMs - nowMs` — may be negative (server clock behind) or positive (ahead). */
  skewMs: bigint;
  /** Replay-window threshold the client was configured with (`replayWindowMs`). */
  allowedWindowMs: number;
}

/**
 * Signed timestamp fell outside the replay window. The signature itself was
 * valid — the response is just too old (or too far in the future) to accept.
 */
export class StaleTimestamp extends VerificationError {
  readonly kind = "StaleTimestamp" as const;
  readonly observedMs: bigint;
  readonly nowMs: bigint;
  readonly skewMs: bigint;
  readonly allowedWindowMs: number;

  constructor(ctx: StaleTimestampContext) {
    super(
      `Timestamp outside replay window: observed=${ctx.observedMs}ms now=${ctx.nowMs}ms ` +
        `skew=${ctx.skewMs}ms window=±${ctx.allowedWindowMs}ms`,
    );
    this.observedMs = ctx.observedMs;
    this.nowMs = ctx.nowMs;
    this.skewMs = ctx.skewMs;
    this.allowedWindowMs = ctx.allowedWindowMs;
  }
}

/** Attestation nonce failed synchronous shape validation (must be exactly 32 bytes). */
export class InvalidNonce extends VerificationError {
  readonly kind = "InvalidNonce" as const;

  constructor(public readonly reason: string) {
    super(`Invalid attestation nonce: ${reason}`);
  }
}

/** The sidecar returned a body that does not match the documented attestation wire shape. */
export class MalformedAttestationResponse extends VerificationError {
  readonly kind = "MalformedAttestationResponse" as const;

  constructor(public readonly reason: string) {
    super(`Malformed attestation response: ${reason}`);
  }
}

/** The sidecar `GET /info` body did not match the documented shape (missing/typed `tcb_info.app_compose`). */
export class MalformedInfoResponse extends VerificationError {
  readonly kind = "MalformedInfoResponse" as const;

  constructor(public readonly reason: string) {
    super(`Malformed /info response: ${reason}`);
  }
}

/**
 * The RPC proxy could not route attestation to the requested `node_id` (HTTP
 * 404). The node id is stale or unknown; the SDK does NOT retry or fall back to
 * another node — a targeted attestation request that misses is terminal.
 */
export class AttestationNodeNotFoundError extends VerificationError {
  readonly kind = "AttestationNodeNotFound" as const;

  constructor(public readonly nodeId: string) {
    super(`Attestation node not found: ${nodeId}`);
  }
}

/**
 * The fetched attestation's `pubkey` did not match the pubkey that signed the
 * RPC response (`vRPC-Pubkey`). The attestation belongs to a different node than
 * the one that served the verified response — correlation failed.
 */
export class AttestationCorrelationError extends VerificationError {
  readonly kind = "AttestationCorrelation" as const;

  constructor(
    public readonly expectedPubkey: string,
    public readonly actualPubkey: string,
  ) {
    super(
      `Attestation pubkey mismatch: expected ${expectedPubkey} (RPC response), ` +
        `got ${actualPubkey} (attestation)`,
    );
  }
}

/**
 * A {@link ComposeSource} implementation is not yet available — currently the
 * external `RegistryComposeSource` (the real Layer A trust anchor), pending the
 * compose-hash registry. Use `InfoEndpointComposeSource` for dev.
 */
export class ComposeSourceNotImplemented extends VerificationError {
  readonly kind = "ComposeSourceNotImplemented" as const;

  constructor(public readonly reason: string) {
    super(`ComposeSource not implemented: ${reason}`);
  }
}
