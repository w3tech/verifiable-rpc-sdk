// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Header utilities for the two proxy legs: hop-by-hop stripping (RFC 7230
// §6.1), undici header flattening for verification, and relay header
// construction. Bodies are always fully buffered, so transfer-encoding is
// never forwarded in either direction.

import type { IncomingHttpHeaders } from "node:http";

import { MalformedHeader } from "@w3tech.io/vrpc-core";

/** RFC 7230 §6.1 hop-by-hop headers (lowercase), stripped on both legs. */
export const HOP_BY_HOP: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/** Header value shape shared by node:http and undici response headers. */
export type RawHeaders = Record<string, string | string[] | undefined>;

/**
 * Build the header set forwarded to the upstream: the inbound request headers
 * minus hop-by-hop, `host` (undici derives it from the target URL), and
 * `content-length` (undici recomputes it from the Buffer body). Everything
 * else — including `accept-encoding`, `content-encoding`, `content-type` —
 * passes verbatim.
 */
export function buildForwardHeaders(
  reqHeaders: IncomingHttpHeaders,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(reqHeaders)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === "host" || lower === "content-length") continue;
    out[lower] = value;
  }
  return out;
}

/**
 * Flatten undici response headers (`string | string[]`) into the
 * `Record<string, string>` shape core's verify expects. A repeated header the
 * verify path READS is ambiguous (the relay would carry both values while
 * verification saw one): repeated `vRPC-*` is ambiguous signing material, a
 * repeated `content-encoding` would make the proxy decode under a different
 * coding chain than the relayed declaration — both fail closed with
 * `MalformedHeader`. Other repeated headers take the first element — verify
 * does not read them.
 */
export function flattenForVerify(headers: RawHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (Array.isArray(value)) {
      if (lower.startsWith("vrpc-") || lower === "content-encoding") {
        throw new MalformedHeader(lower, value.join(", "), "repeated header");
      }
      if (value[0] !== undefined) out[lower] = value[0];
      continue;
    }
    out[lower] = value;
  }
  return out;
}

/**
 * Build the header set relayed to the client: upstream headers minus
 * hop-by-hop and `content-length`, with `content-length` set from the actual
 * outgoing buffer. Multi-value headers (e.g. `set-cookie`) stay arrays —
 * node:http `writeHead` accepts `string[]` values.
 */
export function buildRelayHeaders(
  headers: RawHeaders,
  bodyLength: number,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === "content-length") continue;
    out[lower] = value;
  }
  out["content-length"] = String(bodyLength);
  return out;
}
