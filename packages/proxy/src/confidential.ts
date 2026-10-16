// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: plain client requests go to the attested node sealed, and its verified, decrypted answers are relayed.

import type http from "node:http";

import { ConfidentialSealFailed, UnavailableError, VerificationError } from "@w3tech.io/vrpc-core";
import type {
  ConfidentialClient,
  ConfidentialTransport,
  InnerRequest,
} from "@w3tech.io/vrpc-core/confidential";
import { type Dispatcher, request } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import {
  BodyTooLargeError,
  errorResponseBody,
  ProxyError,
  UpstreamBodyTooLargeError,
} from "./errors";
import type { ProxyLogger } from "./logger";
import { bufferStream, mapUndiciError } from "./pipeline";

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
    let res: Dispatcher.ResponseData;
    try {
      res = await request(outer.url, {
        method: outer.method,
        headers: { ...outer.headers, "accept-encoding": "identity" },
        body: outer.body ?? null,
        dispatcher,
        headersTimeout: config.upstreamTimeoutMs,
        bodyTimeout: config.upstreamTimeoutMs,
        ...(outer.signal === undefined ? {} : { signal: outer.signal }),
      });
    } catch (err) {
      throw mapUndiciError(err);
    }
    // Every value is appended so core sees repeated fields and classifies them itself.
    const headers = new Headers();
    for (const [name, value] of Object.entries(res.headers)) {
      if (value === undefined) continue;
      for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
    }
    let raw: Buffer;
    try {
      raw = await bufferStream(
        res.body,
        config.maxBodyBytes,
        () => new UpstreamBodyTooLargeError(config.maxBodyBytes),
      );
    } catch (err) {
      throw err instanceof ProxyError ? err : mapUndiciError(err);
    }
    const body = await decodeBody(
      raw,
      headers.get("content-encoding") ?? undefined,
      config.maxBodyBytes,
    );
    return { status: res.statusCode, headers, body };
  };
}

/** Status, kind and message of the typed JSON error for a failed confidential request. */
export function describeConfidentialError(err: unknown): {
  status: number;
  kind: string;
  message: string;
  executed?: "no" | "unknown";
} {
  if (err instanceof ProxyError) {
    return { status: err.httpStatus, kind: err.kind, message: err.message };
  }
  if (err instanceof ConfidentialSealFailed) {
    return { status: 500, kind: err.kind, message: err.message, executed: err.executed };
  }
  if (err instanceof UnavailableError) {
    return { status: 502, kind: err.kind, message: err.message, executed: err.executed };
  }
  if (err instanceof VerificationError) {
    return { status: 502, kind: err.kind, message: err.message };
  }
  return { status: 502, kind: "Internal", message: "Internal proxy error" };
}

function renderError(res: http.ServerResponse, err: unknown, log: ProxyLogger): void {
  const { status, kind, message, executed } = describeConfidentialError(err);
  log.error("proxy.error", { kind, status, message, ...(executed ? { executed } : {}) });
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const body = errorResponseBody(kind, message);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  });
  res.end(body);
}

/** Request listener for Ankr Confidential RPC mode; nothing reaches the upstream unsealed. */
export function createConfidentialHandler(ctx: ConfidentialHandlerContext): http.RequestListener {
  const { config, client, logger: log } = ctx;

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const started = performance.now();
    const bytes = await bufferStream(
      req,
      config.maxBodyBytes,
      () => new BodyTooLargeError(config.maxBodyBytes),
    );
    const contentType = req.headers["content-type"];
    const accept = req.headers.accept;
    // The raw request-target goes in as received, so the encoder rejects what it must.
    const inner: InnerRequest = {
      method: req.method ?? "GET",
      path: req.url ?? "/",
      ...(contentType === undefined ? {} : { contentType }),
      ...(accept === undefined ? {} : { accept }),
      ...(bytes.length === 0 ? {} : { body: bytes }),
    };
    const out = await client.request(inner);
    const headers: Record<string, string> = {};
    if (out.contentType !== undefined) headers["content-type"] = out.contentType;
    headers["content-length"] = String(out.body.byteLength);
    res.writeHead(out.status, headers);
    res.end(out.body);
    log.debug("proxy.relay", {
      status: out.status,
      requestBytes: bytes.length,
      responseBytes: out.body.byteLength,
      durationMs: Math.round(performance.now() - started),
      nodeId: client.getConfidentialInfo()?.nodeId,
    });
  }

  return (req, res) => {
    handle(req, res).catch((err: unknown) => {
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
