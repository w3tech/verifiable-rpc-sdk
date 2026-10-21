// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The proxy's own error kinds, and the one error path of both modes: map, describe, render.

import type http from "node:http";

import {
  AttestationUnavailable,
  InvalidInnerRequest,
  RequestRejected,
  TransportFailed,
  VrpcError,
} from "@w3tech.io/vrpc-core";

import type { ProxyLogger } from "./logger";

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

  constructor() {
    super("Upstream response body exceeds the size limit", 502);
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

const UNDICI_TIMEOUT_CODES = new Set<unknown>([
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

/** The `code` of an error-like value, if any. */
export function codeOf(err: unknown): unknown {
  return (err as { code?: unknown } | null | undefined)?.code;
}

/** True for an undici connect, headers or body timeout. */
function isUndiciTimeout(err: unknown): boolean {
  return UNDICI_TIMEOUT_CODES.has(codeOf(err));
}

/** The HTTP status for an attestation that could not be obtained, in both proxy modes. */
function attestationUnavailableStatus(err: AttestationUnavailable): number {
  if (err.status === 429) return 429;
  return err.reason === "timeout" || isUndiciTimeout(err.cause) ? 504 : 503;
}

/** The one map of an upstream failure, by its `code`; the original error stays the `cause`. */
export function upstreamError(cause: unknown): ProxyError {
  const code = codeOf(cause);
  let err: ProxyError;
  if (isUndiciTimeout(cause)) {
    err = new UpstreamTimeoutError("Upstream did not respond within the configured timeout");
  } else if (code === "UPSTREAM_BODY_TOO_LARGE") {
    err = new UpstreamBodyTooLargeError();
  } else if (code === "DECODE_FAILED") {
    err = new DecodeFailedError("Upstream response could not be decoded");
  } else {
    err = new UpstreamConnectError("Upstream request failed");
  }
  err.cause = cause;
  return err;
}

function statusOf(err: VrpcError): number {
  if (err instanceof InvalidInnerRequest) return 400;
  if (err instanceof AttestationUnavailable) return attestationUnavailableStatus(err);
  // Other 4xx would collide with the node's own relayed statuses.
  if (err instanceof RequestRejected && (err.status === 413 || err.status === 429)) {
    return err.status;
  }
  return 502;
}

/** Status, kind and message of the JSON error for any failure in either mode; `code` is for the log only. */
export function describeError(err: unknown): {
  status: number;
  kind: string;
  message: string;
  executed?: "no" | "unknown";
  code?: string;
  traceId?: string;
} {
  if (err instanceof TransportFailed && err.reason === "network") {
    return { ...describeError(upstreamError(err.cause)), executed: err.executed };
  }
  let described: { status: number; kind: string; message: string; executed?: "no" | "unknown" };
  if (err instanceof ProxyError) {
    described = { status: err.httpStatus, kind: err.kind, message: err.message };
  } else if (err instanceof VrpcError) {
    described = {
      status: statusOf(err),
      kind: err.kind,
      message: err.message,
      executed: err.executed,
    };
  } else {
    return { status: 502, kind: "Internal", message: "Internal proxy error" };
  }
  const code = codeOf(err.cause);
  const traceId = (err as { traceId?: unknown }).traceId;
  return {
    ...described,
    ...(typeof code === "string" ? { code } : {}),
    ...(typeof traceId === "string" && traceId !== "" ? { traceId } : {}),
  };
}

/** Log the failure and answer with the JSON error, or drop the socket once the status line is out. */
export function renderError(res: http.ServerResponse, err: unknown, log: ProxyLogger): void {
  const { status, kind, message, executed, code, traceId } = describeError(err);
  log.error("proxy.error", {
    kind,
    status,
    message,
    ...(executed ? { executed } : {}),
    ...(code ? { code } : {}),
    ...(traceId ? { traceId } : {}),
  });
  if (res.headersSent) {
    res.destroy();
    return;
  }
  // Only the strings: core's StaleTimestamp carries bigint fields that JSON.stringify rejects.
  const body = JSON.stringify({
    error: { kind, message, ...(traceId ? { traceId } : {}), ...(executed ? { executed } : {}) },
  });
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  });
  res.end(body);
}
