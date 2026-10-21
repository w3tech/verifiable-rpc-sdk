// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Header utilities for the two proxy legs: hop-by-hop stripping (RFC 7230
// §6.1) and relay header construction. Bodies are always fully buffered, so
// transfer-encoding is never forwarded in either direction.

import type { IncomingHttpHeaders } from "node:http";

/** RFC 7230 §6.1 hop-by-hop headers (lowercase), stripped on both legs. */
const HOP_BY_HOP: ReadonlySet<string> = new Set([
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

/** Lowercased copy without hop-by-hop headers and `drop`; multi-value headers stay arrays. */
function strip(headers: RawHeaders, drop: string[]): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (value !== undefined && !HOP_BY_HOP.has(lower) && !drop.includes(lower)) out[lower] = value;
  }
  return out;
}

/** Upstream request headers: undici derives `host` from the URL and `content-length` from the body. */
export function buildForwardHeaders(
  reqHeaders: IncomingHttpHeaders,
): Record<string, string | string[]> {
  return strip(reqHeaders, ["host", "content-length"]);
}

/** Client response headers, with `content-length` set from the outgoing buffer. */
export function buildRelayHeaders(
  headers: RawHeaders,
  bodyLength: number,
): Record<string, string | string[]> {
  return { ...strip(headers, ["content-length"]), "content-length": String(bodyLength) };
}
