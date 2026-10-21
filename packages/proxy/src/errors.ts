// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Typed transport errors thrown by the proxy pipeline.
//
// Mirrors the core `VerificationError` style: discriminated union via the
// `kind` field plus a class hierarchy. Verification failures themselves are
// core's `VerificationError` subclasses — this file adds only the transport
// and config kinds the proxy itself produces.

import type { AttestationUnavailable } from "@w3tech.io/vrpc-core";

export type ProxyErrorKind =
  | "Config"
  | "BodyTooLarge"
  | "UnsupportedMediaType"
  | "UpstreamTimeout"
  | "UpstreamConnect"
  | "UpstreamBodyTooLarge"
  | "UnsignedUpstream"
  | "DecodeFailed"
  | "Internal";

/**
 * Abstract base for all proxy transport errors. `kind` is the stable string
 * discriminator serialized into the JSON error body; `httpStatus` is the
 * status code the error path responds with.
 */
export abstract class ProxyError extends Error {
  abstract readonly kind: ProxyErrorKind;
  readonly httpStatus: number;

  constructor(message: string, httpStatus: number) {
    super(message);
    this.name = this.constructor.name;
    this.httpStatus = httpStatus;
  }
}

/**
 * Invalid or missing startup configuration. Startup-only: the CLI prints the
 * message and exits before the listen socket binds, so the httpStatus is
 * never rendered to a client.
 */
export class ConfigError extends ProxyError {
  readonly kind = "Config" as const;

  constructor(message: string) {
    super(message, 500);
  }
}

/** Inbound request body exceeded the configured cap. */
export class BodyTooLargeError extends ProxyError {
  readonly kind = "BodyTooLarge" as const;

  constructor(public readonly maxBodyBytes: number) {
    super(`Request body exceeds the ${maxBodyBytes}-byte limit`, 413);
  }
}

/** Client request the Ankr Confidential RPC path cannot carry: a content coding, or a body without a media type. */
export class UnsupportedMediaTypeError extends ProxyError {
  readonly kind = "UnsupportedMediaType" as const;

  constructor(message: string) {
    super(message, 415);
  }
}

/** Upstream did not answer (headers or body) within the configured timeout. */
export class UpstreamTimeoutError extends ProxyError {
  readonly kind = "UpstreamTimeout" as const;

  constructor(message: string) {
    super(message, 504);
  }
}

/** Upstream connection or dispatch failed (DNS, refused, reset, TLS, ...). */
export class UpstreamConnectError extends ProxyError {
  readonly kind = "UpstreamConnect" as const;

  constructor(message: string) {
    super(message, 502);
  }
}

/** Upstream response body exceeded the cap — cannot be safely verified. */
export class UpstreamBodyTooLargeError extends ProxyError {
  readonly kind = "UpstreamBodyTooLarge" as const;
  readonly code = "UPSTREAM_BODY_TOO_LARGE" as const;

  constructor(public readonly maxBodyBytes: number) {
    super(`Upstream response body exceeds the ${maxBodyBytes}-byte limit`, 502);
  }
}

/**
 * Upstream answered without vRPC signature headers — not a vRPC endpoint, or
 * an unsigned gateway error. Fails closed regardless of the upstream status.
 */
export class UnsignedUpstreamError extends ProxyError {
  readonly kind = "UnsignedUpstream" as const;

  constructor(public readonly upstreamStatus: number) {
    super(
      `Upstream responded with HTTP ${upstreamStatus} and no vRPC signature headers; refusing to relay an unverified body`,
      502,
    );
  }
}

/** Upstream body failed to decode under its declared Content-Encoding (unknown coding or corrupt stream). */
export class DecodeFailedError extends ProxyError {
  readonly kind = "DecodeFailed" as const;
  readonly code = "DECODE_FAILED" as const;

  constructor(message: string) {
    super(message, 502);
  }
}

/** Unexpected internal failure — generic message, no details leaked. */
export class InternalProxyError extends ProxyError {
  readonly kind = "Internal" as const;

  constructor(message: string) {
    super(message, 502);
  }
}

const UNDICI_TIMEOUT_CODES = new Set([
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

/** True for an undici connect, headers or body timeout. */
export function isUndiciTimeout(err: unknown): boolean {
  return UNDICI_TIMEOUT_CODES.has((err as { code?: string } | null | undefined)?.code ?? "");
}

/** The HTTP status for an attestation that could not be obtained, in both proxy modes. */
export function attestationUnavailableStatus(err: AttestationUnavailable): number {
  if (err.status === 429) return 429;
  return err.reason === "timeout" || isUndiciTimeout(err.cause) ? 504 : 503;
}

/**
 * Serialize an error into the typed JSON error body. Only `kind` and
 * `message` are serialized — core's StaleTimestamp carries bigint fields, so
 * stringifying an error object raw would throw.
 */
export function errorResponseBody(
  kind: string,
  message: string,
  traceId?: string,
  executed?: "no" | "unknown",
): string {
  return JSON.stringify({
    error: {
      kind,
      message,
      ...(traceId ? { traceId } : {}),
      ...(executed ? { executed } : {}),
    },
  });
}
