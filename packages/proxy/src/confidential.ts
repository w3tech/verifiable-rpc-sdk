// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: plain client requests go to the attested node sealed, and its verified, decrypted answers are relayed.

import type http from "node:http";

import {
  AttestationUnavailable,
  InvalidInnerRequest,
  RequestRejected,
  TransportFailed,
  VrpcError,
} from "@w3tech.io/vrpc-core";
import type {
  ConfidentialClient,
  ConfidentialResponse,
  ConfidentialTransport,
  InnerRequest,
} from "@w3tech.io/vrpc-core/confidential";
import type { Dispatcher } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import {
  attestationUnavailableStatus,
  BodyTooLargeError,
  errorResponseBody,
  isUndiciTimeout,
  ProxyError,
  UnsupportedMediaTypeError,
} from "./errors";
import type { ProxyLogger } from "./logger";
import { bufferStream, sendUpstream } from "./upstream";

/** Per-process context shared by every confidential request. */
export interface ConfidentialHandlerContext {
  config: ProxyConfig;
  client: ConfidentialClient;
  logger: ProxyLogger;
}

/** Outer HTTP leg for the core client: undici with the proxy's timeouts, size cap and decoding. */
export function createConfidentialTransport(
  config: ProxyConfig,
  dispatcher: Dispatcher,
): ConfidentialTransport {
  return async (outer) => {
    const cap = Math.min(config.maxBodyBytes, outer.maxBytes ?? Infinity);
    const res = await sendUpstream(dispatcher, cap, {
      url: outer.url,
      method: outer.method,
      headers: { ...outer.headers, "accept-encoding": "identity" },
      body: outer.body,
      signal: outer.signal,
    });
    const body = await decodeBody(res.body, res.headers.get("content-encoding") ?? undefined, cap);
    return { status: res.status, headers: res.headers, body };
  };
}

/** Status, kind and message of the typed JSON error for a failed confidential request. */
export function describeConfidentialError(err: unknown): {
  status: number;
  kind: string;
  message: string;
  executed?: "no" | "unknown";
  code?: string;
} {
  if (err instanceof ProxyError) {
    return { status: err.httpStatus, kind: err.kind, message: err.message };
  }
  if (!(err instanceof VrpcError)) {
    return { status: 502, kind: "Internal", message: "Internal proxy error" };
  }
  const code = (err.cause as { code?: unknown } | undefined)?.code;
  const coded = { executed: err.executed, ...(typeof code === "string" ? { code } : {}) };
  if (err instanceof TransportFailed && err.reason === "network") {
    const [status, kind, message] = upstreamFailure(code);
    return { status, kind, message, ...coded };
  }
  return { status: statusOf(err), kind: err.kind, message: err.message, ...coded };
}

type Rendered = [status: number, kind: string, message: string];

const UPSTREAM_FAILURES = new Map<unknown, Rendered>([
  [
    "UPSTREAM_BODY_TOO_LARGE",
    [502, "UpstreamBodyTooLarge", "Upstream response body exceeds the size limit"],
  ],
  ["DECODE_FAILED", [502, "DecodeFailed", "Upstream response could not be decoded"]],
]);

function upstreamFailure(code: unknown): Rendered {
  if (isUndiciTimeout({ code })) {
    return [504, "UpstreamTimeout", "Upstream did not respond within the configured timeout"];
  }
  return UPSTREAM_FAILURES.get(code) ?? [502, "UpstreamConnect", "Upstream request failed"];
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

// Built from scratch: nothing from the outer answer reaches the client.
function relayHeaders(method: string, out: ConfidentialResponse): Record<string, string> {
  const headers: Record<string, string> = {};
  if (out.contentType !== undefined) headers["content-type"] = out.contentType;
  if (out.status === 205) {
    // Without a length Node chunk-frames an empty 205.
    headers["content-length"] = "0";
  } else if (method !== "HEAD" && out.status !== 204 && out.status !== 304) {
    headers["content-length"] = String(out.body.byteLength);
  }
  return headers;
}

function renderError(res: http.ServerResponse, err: unknown, log: ProxyLogger): void {
  const { status, kind, message, executed, code } = describeConfidentialError(err);
  log.error("proxy.error", {
    kind,
    status,
    message,
    ...(executed ? { executed } : {}),
    ...(code ? { code } : {}),
  });
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const body = errorResponseBody(kind, message, undefined, executed);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  });
  res.end(body);
}

/** Request listener for Ankr Confidential RPC mode; nothing reaches the upstream unsealed. */
export function createConfidentialHandler(
  ctx: ConfidentialHandlerContext,
): (req: http.IncomingMessage, res: http.ServerResponse, signal: AbortSignal) => void {
  const { config, client, logger: log } = ctx;

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    signal: AbortSignal,
  ): Promise<void> {
    const started = performance.now();
    const bytes = await bufferStream(
      req,
      config.maxBodyBytes,
      () => new BodyTooLargeError(config.maxBodyBytes),
    );
    if (req.headers["content-encoding"] !== undefined) {
      throw new UnsupportedMediaTypeError("Request content-encoding is not supported");
    }
    const contentType = req.headers["content-type"]?.trim() || undefined;
    if (bytes.length > 0 && contentType === undefined) {
      throw new UnsupportedMediaTypeError("Request body requires a content-type");
    }
    const accept = req.headers.accept;
    // The raw request-target goes in as received, so the encoder rejects what it must.
    const inner: InnerRequest = {
      method: req.method ?? "GET",
      path: req.url ?? "/",
      ...(contentType === undefined ? {} : { contentType }),
      ...(accept === undefined ? {} : { accept }),
      ...(bytes.length === 0 ? {} : { body: bytes }),
    };
    const out = await client.request(inner, { signal });
    res.writeHead(out.status, relayHeaders(inner.method, out));
    res.end(out.body);
    log.debug("proxy.relay", {
      status: out.status,
      requestBytes: bytes.length,
      responseBytes: out.body.byteLength,
      durationMs: Math.round(performance.now() - started),
      nodeId: client.getConfidentialInfo()?.nodeId,
    });
  }

  return (req, res, signal) => {
    handle(req, res, signal).catch((err: unknown) => {
      if (res.destroyed || (err as { code?: string } | null | undefined)?.code === "ECONNRESET") {
        log.debug("proxy.clientAborted");
        res.destroy();
        return;
      }
      renderError(res, err, log);
      // Unread body bytes would otherwise be parsed as the next keep-alive request.
      if (err instanceof BodyTooLargeError) {
        if (res.writableFinished) {
          req.destroy();
        } else {
          res.once("finish", () => req.destroy());
        }
      }
    });
  };
}
