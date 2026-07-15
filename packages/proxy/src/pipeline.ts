// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The verifying proxy pipeline: buffer the inbound request, forward verbatim
// via undici, buffer the upstream response, decode a throwaway copy for
// verification, verify fail-closed, relay the ORIGINAL bytes on success.
// Bodies are opaque Buffers end to end — no JSON parsing anywhere.

import type http from "node:http";

import {
  byteLen,
  isSignedVrpcResponse,
  type Logger,
  pickVrpcHeaders,
  safeLogger,
  type TrustedVerifier,
  VerificationError,
} from "@w3tech.io/vrpc-core";
import { type Dispatcher, request } from "undici";

import type { ProxyConfig } from "./config";
import { decodeBody } from "./decode";
import {
  BodyTooLargeError,
  errorResponseBody,
  ProxyError,
  UnsignedUpstreamError,
  UpstreamBodyTooLargeError,
  UpstreamConnectError,
  UpstreamTimeoutError,
} from "./errors";
import {
  buildForwardHeaders,
  buildRelayHeaders,
  flattenForVerify,
  isEncodingAcceptable,
} from "./headers";

/** Per-process context shared by every request. */
export interface RequestContext {
  config: ProxyConfig;
  verifier: TrustedVerifier;
  logger: Logger;
  /**
   * The undici dispatcher for upstream requests. The server factory supplies
   * an Agent whose connect timeout is bound to `config.upstreamTimeoutMs` —
   * undici's per-request options cover only headers/body timeouts, so without
   * this the connect phase would run on the global dispatcher's default.
   */
  dispatcher: Dispatcher;
}

/**
 * Buffer a readable stream into a single Buffer, enforcing `maxBytes`.
 * Exceeding the cap throws the error produced by `overflow()`.
 */
async function bufferStream(
  stream: AsyncIterable<Buffer | Uint8Array>,
  maxBytes: number,
  overflow: () => ProxyError,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > maxBytes) {
      throw overflow();
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
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
 * Map an undici dispatch error onto the proxy's transport taxonomy. All three
 * timeout phases (connect, headers, body) are timeouts → 504; everything else
 * (DNS, refused, reset, TLS, ...) is a connect failure → 502.
 */
export function mapUndiciError(err: unknown): ProxyError {
  const code = (err as { code?: string }).code;
  if (
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT" ||
    code === "UND_ERR_BODY_TIMEOUT"
  ) {
    return new UpstreamTimeoutError("Upstream did not respond within the configured timeout");
  }
  const detail = err instanceof Error ? err.message : String(err);
  return new UpstreamConnectError(`Upstream request failed: ${detail}`);
}

/**
 * Render an error as the typed JSON error response. Only `kind` and `message`
 * are serialized; upstream body bytes and stack traces are never written —
 * unexpected errors collapse to a generic `Internal` kind.
 */
function renderError(res: http.ServerResponse, err: unknown, log: Logger): void {
  let status: number;
  let kind: string;
  let message: string;
  if (err instanceof ProxyError) {
    status = err.httpStatus;
    kind = err.kind;
    message = err.message;
  } else if (err instanceof VerificationError) {
    status = 502;
    kind = err.kind;
    message = err.message;
  } else {
    status = 502;
    kind = "Internal";
    message = "Internal proxy error";
  }
  log.debug("proxy.error", { kind, status, message });
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
 * 6. Relay the ORIGINAL upstream bytes and headers verbatim; when the
 *    upstream encoding is not client-acceptable, serve the already-verified
 *    decoded plaintext instead (still carrying the vRPC-* headers — the
 *    signature is over the plaintext, so the fallback stays re-verifiable).
 */
export function createRequestHandler(ctx: RequestContext): http.RequestListener {
  const log = safeLogger(ctx.logger);
  const { config, verifier } = ctx;

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
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

    let upstreamRes: Dispatcher.ResponseData;
    try {
      upstreamRes = await request(targetUrl, {
        method: (req.method ?? "GET") as Dispatcher.HttpMethod,
        headers: forwardHeaders,
        body: requestBytes.length > 0 ? requestBytes : null,
        dispatcher: ctx.dispatcher,
        headersTimeout: config.upstreamTimeoutMs,
        bodyTimeout: config.upstreamTimeoutMs,
      });
    } catch (err) {
      throw mapUndiciError(err);
    }

    // 3. Buffer the upstream response body under the same cap.
    let responseBytes: Buffer;
    try {
      responseBytes = await bufferStream(
        upstreamRes.body,
        config.maxBodyBytes,
        () => new UpstreamBodyTooLargeError(config.maxBodyBytes),
      );
    } catch (err) {
      if (err instanceof ProxyError) throw err;
      throw mapUndiciError(err);
    }

    // 4. No vRPC headers → fail closed whether the upstream answered 200 or 5xx.
    const flatHeaders = flattenForVerify(upstreamRes.headers);
    if (!isSignedVrpcResponse(flatHeaders)) {
      throw new UnsignedUpstreamError(upstreamRes.statusCode);
    }

    // 5. Decode the throwaway copy and verify — the SAME requestBytes Buffer
    //    from step 1; the signature covers the content-decoded response body.
    const decodedCopy = await decodeBody(
      responseBytes,
      flatHeaders["content-encoding"],
      config.maxBodyBytes,
    );
    await verifier.verify(requestBytes, decodedCopy, flatHeaders);
    log.debug("proxy.verified", {
      status: upstreamRes.statusCode,
      headers: pickVrpcHeaders(flatHeaders),
      bodyBytes: byteLen(decodedCopy),
    });

    // 6. Relay. Verbatim when the client can accept the upstream's encoding;
    //    otherwise fall back to the already-verified decoded plaintext.
    const acceptRaw = req.headers["accept-encoding"];
    const acceptHeader = Array.isArray(acceptRaw) ? acceptRaw.join(", ") : acceptRaw;
    const contentEncoding = flatHeaders["content-encoding"];
    if (isEncodingAcceptable(contentEncoding, acceptHeader)) {
      res.writeHead(
        upstreamRes.statusCode,
        buildRelayHeaders(upstreamRes.headers, responseBytes.length),
      );
      res.end(responseBytes);
    } else {
      const relayHeaders = buildRelayHeaders(upstreamRes.headers, decodedCopy.length);
      delete relayHeaders["content-encoding"];
      res.writeHead(upstreamRes.statusCode, relayHeaders);
      res.end(decodedCopy);
    }
  }

  return (req, res) => {
    handle(req, res).catch((err: unknown) => {
      renderError(res, err, log);
      // An over-cap inbound body leaves unread data on the socket; destroy the
      // request once the error response has flushed so keep-alive reuse cannot
      // see the tail as a new request.
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
