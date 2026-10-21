// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Typed errors thrown by vrpc-core; every class extends the root `VrpcError`.
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
  | "InvalidChainId"
  | "BadSignature"
  | "StaleTimestamp"
  | "InvalidNonce"
  | "MalformedAttestationResponse"
  | "AttestationNodeNotFound"
  | "AttestationCorrelation"
  | "Attestation"
  | "ConfidentialSignerMismatch"
  | "ConfidentialDecryptFailed"
  | "MalformedConfidentialResponse";

/** Root of every error class in vrpc-core. */
export abstract class VrpcError extends Error {
  abstract readonly kind: string;
  /**
   * `"no"`: the gateway or node did not run this attempt; an edge proxy retry may have run an earlier attempt of the same call.
   * `"unknown"`: the call may or may not have run; check state before resending a state-changing call.
   */
  executed: "no" | "unknown" = "unknown";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    // `this.constructor.name` reflects the concrete subclass at runtime, so
    // `JSON.stringify`-style serialisation and logging report e.g. "BadSignature"
    // rather than the abstract "VerificationError" or the v8 default "Error".
    this.name = this.constructor.name;
  }
}

/**
 * Abstract base for all verification errors. The `kind` discriminator is set
 * by each concrete subclass to a literal type, so consumers can narrow via
 * `if (err.kind === "BadSignature") { ... }` without `instanceof` chains.
 */
export abstract class VerificationError extends VrpcError {
  abstract override readonly kind: VerificationErrorKind;
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

/**
 * Configured chain id failed validation (`validateChainId`). Chain ids are
 * opaque strings that must be non-empty after trimming, at most 64 UTF-8
 * bytes, and printable ASCII with no whitespace — mirroring the sidecar's
 * `validate_chain_id` boot check. Thrown synchronously from client
 * construction and from `verifyResponse` entry; the `reason` names the failed
 * constraint.
 */
export class InvalidChainId extends VerificationError {
  readonly kind = "InvalidChainId" as const;

  constructor(
    public readonly chainId: string,
    public readonly reason: string,
  ) {
    super(`Invalid chain id ${JSON.stringify(chainId)}: ${reason}`);
  }
}

export interface BadSignatureContext {
  /** `0x` + 128 lowercase hex chars (64-byte Ed25519 signature). */
  signatureHex: string;
  /** `0x` + 64 lowercase hex chars (32-byte Ed25519 pubkey). */
  pubkeyHex: string;
  /** sha256 of the 104-byte canonical pre-image, for diagnostics. */
  preImageSha256: Uint8Array;
}

/**
 * Ed25519 signature verification failed against the canonical pre-image.
 *
 * Carries the full signing context (signature, pubkey, pre-image digest) so
 * the caller can correlate the failure with sidecar-side logs. These values
 * are public — the signature was emitted in a response header, the pubkey
 * is bound into the TDX attestation quote — so logging them is safe.
 *
 * In Ankr Confidential RPC mode, a response cut in transit after its status was sent also fails this way.
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
 *
 * In Ankr Confidential RPC mode, the call ran and its response was rejected.
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
 * dstack/TDX attestation verification failed. This is core's wrapper around the
 * leaf `@w3tech.io/dstack-verify` `AttestationError`: that package is a standalone
 * leaf (its error does NOT extend `VerificationError`), so the trust seam catches
 * it at the `verifyDstackAttestation` boundary and re-throws it as this member of
 * the `VerificationError` family — keeping the SDK's public error contract
 * (callers catch `VerificationError`) intact. The original leaf error is attached
 * as `cause`; `chkId` records which `CHK-*` item failed.
 * A `CHK-P1` failure can also mean the hardware verifier service was unreachable.
 */
export class AttestationFailed extends VerificationError {
  readonly kind = "Attestation" as const;

  constructor(
    public readonly chkId: string,
    public readonly detail: string,
    options?: { cause?: unknown },
  ) {
    super(`Attestation verification failed [${chkId}]: ${detail}`, options);
  }
}

/** A confidential response was signed by a key other than the pinned node key. */
export class ConfidentialSignerMismatch extends VerificationError {
  readonly kind = "ConfidentialSignerMismatch" as const;

  constructor(
    public readonly expectedPubkey: string,
    public readonly actualPubkey: string,
  ) {
    super(`Response signer ${actualPubkey} is not the pinned node key ${expectedPubkey}`);
  }
}

export type InvalidInnerRequestReason =
  | "method"
  | "path"
  | "header"
  | "content-type-required"
  | "encode-failed";

/** The caller's inner request cannot be sent; rejected before any network call. */
export class InvalidInnerRequest extends VrpcError {
  readonly kind = "InvalidInnerRequest" as const;

  constructor(public readonly reason: InvalidInnerRequestReason) {
    super(`Inner request rejected: ${reason}`);
  }
}

/** A confidential response carried a valid signature but could not be decrypted. */
export class ConfidentialDecryptFailed extends VerificationError {
  readonly kind = "ConfidentialDecryptFailed" as const;

  constructor() {
    super("Signed confidential response could not be decrypted");
  }
}

export type MalformedConfidentialResponseReason =
  | "too-short"
  | "framing"
  | "informational"
  | "decode-failed";

/** A validly signed confidential response is too short to open or its inner response does not decode. */
export class MalformedConfidentialResponse extends VerificationError {
  readonly kind = "MalformedConfidentialResponse" as const;

  constructor(public readonly reason: MalformedConfidentialResponseReason) {
    super(`Malformed confidential response: ${reason}`);
  }
}

export type UnavailableErrorKind =
  | "AttestationUnavailable"
  | "RequestRejected"
  | "UnexpectedResponse"
  | "TransportFailed"
  | "InternalError";

/** Base of the errors raised when a confidential call got no verifiable answer. */
export abstract class UnavailableError extends VrpcError {
  abstract override readonly kind: UnavailableErrorKind;
}

export type AttestationUnavailableReason = "status" | "transport" | "node-id-missing" | "timeout";

/**
 * The node could not be attested, so the call was not sent.
 * A browser calling another origin cannot read `vRPC-NodeId` and gets `node-id-missing`.
 */
export class AttestationUnavailable extends UnavailableError {
  readonly kind = "AttestationUnavailable" as const;
  declare readonly status?: number;

  constructor(
    public readonly reason: AttestationUnavailableReason,
    options?: { status?: number; cause?: unknown },
  ) {
    super(
      reason === "status"
        ? `Attestation unavailable: HTTP ${options?.status}`
        : `Attestation unavailable: ${reason}`,
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    if (options?.status !== undefined) {
      this.status = options.status;
    }
  }
}

/** The confidential endpoint answered with something other than a sealed response. */
export class UnexpectedResponse extends UnavailableError {
  readonly kind = "UnexpectedResponse" as const;
  declare readonly contentType?: string;

  constructor(
    public readonly status: number,
    public readonly nodeId: string,
    contentType?: string,
  ) {
    super(`Unexpected confidential response: HTTP ${status}`);
    if (contentType !== undefined) {
      this.contentType = contentType;
    }
  }
}

/** A 4xx that is not an encrypted answer: the gateway or node refused this attempt. */
export class RequestRejected extends UnavailableError {
  readonly kind = "RequestRejected" as const;
  declare readonly contentType?: string;

  constructor(
    public readonly status: number,
    public readonly nodeId: string,
    contentType?: string,
  ) {
    super(`Confidential request rejected: HTTP ${status}`);
    this.executed = "no";
    if (contentType !== undefined) {
      this.contentType = contentType;
    }
  }
}

export type TransportFailedReason = "network" | "too-large";

/** The confidential request failed in transport, or its answer exceeded the response size cap. */
export class TransportFailed extends UnavailableError {
  readonly kind = "TransportFailed" as const;

  constructor(
    public readonly reason: TransportFailedReason,
    public readonly nodeId: string,
    options?: { cause?: unknown },
  ) {
    super(`Confidential request failed in transport: ${reason}`, options);
  }
}

/** An unexpected failure in the client or an injected seam; `cause` holds the original value. */
export class InternalError extends UnavailableError {
  readonly kind = "InternalError" as const;

  constructor(options: { cause: unknown }) {
    super("Internal error in the Ankr Confidential RPC client", options);
  }
}
