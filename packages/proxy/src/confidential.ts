// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: plain client requests go to the attested node sealed, and its verified, decrypted answers are relayed.

import type http from "node:http";

import type {
  ConfidentialClient,
  ConfidentialResponse,
  ConfidentialTransport,
  InnerRequest,
} from "@w3tech.io/vrpc-core/confidential";
import type { Dispatcher } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import { BodyTooLargeError, UnsupportedMediaTypeError } from "./errors";
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

/** Request listener for Ankr Confidential RPC mode; nothing reaches the upstream unsealed. */
export function createConfidentialHandler(
  ctx: ConfidentialHandlerContext,
): (req: http.IncomingMessage, res: http.ServerResponse, signal: AbortSignal) => Promise<void> {
  const { config, client, logger: log } = ctx;
  // The relay event's fields cost time per request; gather them only when they are logged.
  const debug = config.logLevel === "debug";

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    signal: AbortSignal,
  ): Promise<void> {
    const started = debug ? performance.now() : 0;
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
    if (debug) {
      log.debug("proxy.relay", {
        status: out.status,
        requestBytes: bytes.length,
        responseBytes: out.body.byteLength,
        durationMs: Math.round(performance.now() - started),
      });
    }
  }

  return handle;
}
