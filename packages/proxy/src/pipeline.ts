// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Open mode: forward the request verbatim, verify the signed answer fail-closed, relay the original bytes.
// Bodies are opaque Buffers end to end — no JSON parsing anywhere.

import type http from "node:http";

import { isSignedVrpcResponse, type TrustedVerifier } from "@w3tech.io/vrpc-core";
import type { Dispatcher } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import { UnsignedUpstreamError, upstreamError } from "./errors";
import { buildForwardHeaders, buildRelayHeaders } from "./headers";
import type { ProxyLogger } from "./logger";
import { sendUpstream, type UpstreamResponse } from "./upstream";

/**
 * Resolves `.`/`..` segments, percent-encoded ones too, so the client path cannot climb above the
 * upstream base path. A placeholder authority keeps a `//host/...` request-target a path.
 */
function normalizeClientPath(clientPath: string): string {
  const rawPath = clientPath.startsWith("/") ? clientPath : `/${clientPath}`;
  return new URL(`http://vrpc-proxy.invalid${rawPath}`).pathname;
}

/**
 * Upstream path + normalized client path; the upstream query goes before the client's.
 * The upstream URL is parsed once; only the client request-target varies.
 */
export function targetUrlFor(upstreamUrl: string): (clientUrl: string) => string {
  const upstream = new URL(upstreamUrl);
  const basePath = upstream.pathname.replace(/\/+$/, "");
  const upstreamQuery = upstream.search.slice(1);
  return (clientUrl) => {
    if (clientUrl === "/") return upstreamUrl;
    const qIdx = clientUrl.indexOf("?");
    const clientPath = qIdx === -1 ? clientUrl : clientUrl.slice(0, qIdx);
    const clientQuery = qIdx === -1 ? "" : clientUrl.slice(qIdx + 1);
    // No trailing slash for a root client path: key-in-path upstreams can reject it.
    const mergedPath =
      clientPath === "/" || clientPath === ""
        ? upstream.pathname
        : basePath + normalizeClientPath(clientPath);
    const mergedQuery =
      upstreamQuery !== "" && clientQuery !== ""
        ? `${upstreamQuery}&${clientQuery}`
        : upstreamQuery || clientQuery;
    return `${upstream.origin}${mergedPath}${mergedQuery === "" ? "" : `?${mergedQuery}`}`;
  };
}

const TRACE_ID_HEADER = "x-shark-trace-id";
function attachUpstreamTraceId(err: unknown, headers: Headers): unknown {
  const traceId = headers.get(TRACE_ID_HEADER);
  if (traceId !== null && traceId !== "" && err instanceof Error) {
    (err as { traceId?: string }).traceId = traceId;
  }
  return err;
}

/**
 * Open-mode request handler. The sidecar hashes the bytes it receives: the same request Buffer goes
 * upstream and to verify.
 */
export function openHandler(
  config: ProxyConfig,
  verifier: TrustedVerifier,
  log: ProxyLogger,
  dispatcher: Dispatcher,
) {
  const target = targetUrlFor(config.upstreamUrl);

  return async (
    req: http.IncomingMessage,
    requestBytes: Buffer,
    res: http.ServerResponse,
    signal: AbortSignal,
  ): Promise<void> => {
    const targetUrl = target(req.url ?? "/");
    const forwardHeaders = buildForwardHeaders(req.headers);
    if (config.apiKey !== undefined) {
      // Convenience injection; a client-supplied x-api-key is forwarded verbatim instead.
      forwardHeaders["x-api-key"] ??= config.apiKey;
    }
    // No URL: a client key may sit in the path or query.
    log.debug("proxy.forward", { method: req.method, bodyBytes: requestBytes.length });

    let upstreamRes: UpstreamResponse;
    try {
      upstreamRes = await sendUpstream(dispatcher, config.maxBodyBytes, {
        url: targetUrl,
        method: req.method ?? "GET",
        headers: forwardHeaders,
        body: requestBytes,
        signal,
      });
    } catch (err) {
      throw upstreamError(err);
    }

    const headers = upstreamRes.headers;
    try {
      if (!isSignedVrpcResponse(headers)) {
        throw new UnsignedUpstreamError(upstreamRes.status);
      }

      // The signature covers the decoded body; the client gets the original bytes.
      const decodedCopy = await decodeBody(
        upstreamRes.body,
        headers.get("content-encoding") ?? undefined,
        config.maxBodyBytes,
      );
      await verifier.verify(requestBytes, decodedCopy, headers);
      log.debug("proxy.verified", {
        status: upstreamRes.status,
        bodyBytes: decodedCopy.length,
      });

      res.writeHead(
        upstreamRes.status,
        buildRelayHeaders(upstreamRes.rawHeaders, upstreamRes.body.length),
      );
      res.end(upstreamRes.body);
    } catch (err) {
      throw attachUpstreamTraceId(err, headers);
    }
  };
}
