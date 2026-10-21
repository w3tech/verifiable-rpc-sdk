// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Open mode: forward the request verbatim, verify the signed answer fail-closed, relay the original bytes.
// Bodies are opaque Buffers end to end — no JSON parsing anywhere.

import type http from "node:http";

import {
  byteLen,
  isSignedVrpcResponse,
  pickVrpcHeaders,
  type TrustedVerifier,
} from "@w3tech.io/vrpc-core";
import type { Dispatcher } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import { BodyTooLargeError, UnsignedUpstreamError, upstreamError } from "./errors";
import { buildForwardHeaders, buildRelayHeaders, flattenForVerify } from "./headers";
import type { ProxyLogger } from "./logger";
import { bufferStream, sendUpstream, type UpstreamResponse } from "./upstream";

/** Per-process context shared by every request. */
export interface RequestContext {
  config: ProxyConfig;
  verifier: TrustedVerifier;
  logger: ProxyLogger;
  /**
   * The undici dispatcher for upstream requests. The server factory supplies
   * an Agent that bounds connect, headers and body by `config.upstreamTimeoutMs`.
   */
  dispatcher: Dispatcher;
}

/**
 * Normalize a client request path via WHATWG URL semantics: resolves `.`/`..`
 * segments (including their percent-encoded forms) so the result is an
 * absolute path with no dot segments. Appending it to the upstream base path
 * therefore cannot climb above the base. The path is embedded after a
 * placeholder authority (not resolved as a relative URL) so a `//host/...`
 * request-target stays a path instead of being parsed as an authority.
 */
function normalizeClientPath(clientPath: string): string {
  const rawPath = clientPath.startsWith("/") ? clientPath : `/${clientPath}`;
  return new URL(`http://vrpc-proxy.invalid${rawPath}`).pathname;
}

/**
 * Build the upstream target URL from the configured upstream and the client's
 * request URL. A bare `/` (no query) forwards to the upstream URL unchanged —
 * the plain JSON-RPC POST case, avoiding a trailing slash on key-in-path
 * upstreams. Otherwise the client path is dot-segment-normalized (so it cannot
 * traverse above the configured upstream base path — the one deliberate
 * deviation from verbatim request-line forwarding), appended to the upstream
 * path (upstream trailing slash removed), and query strings are merged with
 * the upstream's own query first.
 */
export function buildTargetUrl(upstreamUrl: string, clientUrl: string): string {
  if (clientUrl === "/") return upstreamUrl;
  const upstream = new URL(upstreamUrl);
  const qIdx = clientUrl.indexOf("?");
  const clientPath = qIdx === -1 ? clientUrl : clientUrl.slice(0, qIdx);
  const clientQuery = qIdx === -1 ? "" : clientUrl.slice(qIdx + 1);
  const basePath = upstream.pathname.replace(/\/+$/, "");
  // A root client path ("/?query" — the bare "/" case fast-paths above) maps
  // to the upstream path as configured, not basePath + "/": a trailing slash
  // can be rejected by key-in-path upstreams.
  const mergedPath =
    clientPath === "/" || clientPath === ""
      ? upstream.pathname
      : basePath + normalizeClientPath(clientPath);
  const upstreamQuery = upstream.search.startsWith("?") ? upstream.search.slice(1) : "";
  const mergedQuery =
    upstreamQuery !== "" && clientQuery !== ""
      ? `${upstreamQuery}&${clientQuery}`
      : upstreamQuery || clientQuery;
  return `${upstream.origin}${mergedPath}${mergedQuery === "" ? "" : `?${mergedQuery}`}`;
}

/**
 * The upstream gateway (and any front returning it) tags every response with a trace id
 * header. Attach it to the error as a `traceId` property so a fail-closed 502
 * can be correlated with the upstream's own logs — surfaced as a separate key
 * in the error body and the log line, not glued into the message. No-op when
 * the header is absent.
 */
const TRACE_ID_HEADER = "x-shark-trace-id";
function attachUpstreamTraceId(err: unknown, headers: Record<string, string>): unknown {
  const traceId = headers[TRACE_ID_HEADER];
  if (traceId !== undefined && traceId !== "" && err instanceof Error) {
    (err as { traceId?: string }).traceId = traceId;
  }
  return err;
}

/**
 * Create the node:http request listener implementing the verifying pipeline:
 *
 * 1. Buffer the inbound request body (cap → 413). The resulting Buffer is
 *    NEVER decoded, parsed, or mutated — the sidecar hashes exactly the bytes
 *    it receives, so the SAME object goes to undici and to verify.
 * 2. Forward verbatim via undici.request (hop-by-hop + Host stripped).
 * 3. Buffer the upstream response (cap → 502).
 * 4. Missing vRPC headers → 502 fail-closed regardless of upstream status.
 * 5. Decode a THROWAWAY copy per Content-Encoding (signature is over the
 *    plaintext) and verify fail-closed.
 * 6. Relay the ORIGINAL upstream bytes and headers verbatim.
 */
export function createRequestHandler(
  ctx: RequestContext,
): (req: http.IncomingMessage, res: http.ServerResponse, signal: AbortSignal) => Promise<void> {
  const log = ctx.logger;
  const { config, verifier } = ctx;

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    signal: AbortSignal,
  ): Promise<void> {
    // 1. Buffer the inbound request body — raw bytes, never transformed.
    const requestBytes = await bufferStream(
      req,
      config.maxBodyBytes,
      () => new BodyTooLargeError(config.maxBodyBytes),
    );

    // 2. Forward verbatim to the upstream.
    const targetUrl = buildTargetUrl(config.upstreamUrl, req.url ?? "/");
    const forwardHeaders = buildForwardHeaders(req.headers);
    if (config.apiKey !== undefined) {
      // Convenience injection; a client-supplied x-api-key is forwarded verbatim instead.
      forwardHeaders["x-api-key"] ??= config.apiKey;
    }
    log.debug("proxy.forward", {
      method: req.method,
      url: req.url,
      bodyBytes: requestBytes.length,
    });

    let upstreamRes: UpstreamResponse;
    try {
      upstreamRes = await sendUpstream(ctx.dispatcher, config.maxBodyBytes, {
        url: targetUrl,
        method: req.method ?? "GET",
        headers: forwardHeaders,
        body: requestBytes,
        signal,
      });
    } catch (err) {
      throw upstreamError(err);
    }

    // From here the upstream has answered — any failure below carries its
    // trace id (when present) for correlation with upstream logs.
    const flatHeaders = flattenForVerify(upstreamRes.rawHeaders);
    try {
      // 4. No vRPC headers → fail closed whether the upstream answered 200 or 5xx.
      if (!isSignedVrpcResponse(flatHeaders)) {
        throw new UnsignedUpstreamError(upstreamRes.status);
      }

      // 5. Decode the throwaway copy and verify — the SAME requestBytes Buffer
      //    from step 1; the signature covers the content-decoded response body.
      const decodedCopy = await decodeBody(
        upstreamRes.body,
        flatHeaders["content-encoding"],
        config.maxBodyBytes,
      );
      await verifier.verify(requestBytes, decodedCopy, flatHeaders);
      log.debug("proxy.verified", {
        status: upstreamRes.status,
        headers: pickVrpcHeaders(flatHeaders),
        bodyBytes: byteLen(decodedCopy),
      });

      // 6. Relay the original upstream bytes and headers verbatim.
      res.writeHead(
        upstreamRes.status,
        buildRelayHeaders(upstreamRes.rawHeaders, upstreamRes.body.length),
      );
      res.end(upstreamRes.body);
    } catch (err) {
      throw attachUpstreamTraceId(err, flatHeaders);
    }
  }

  return handle;
}
