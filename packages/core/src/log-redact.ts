// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Pure truncation + redaction helpers for the opt-in debug logger.
//
// These functions are the SINGLE point where logged field values are shortened
// or sanitized, so the leak surface is auditable in one place. They are pure,
// dependency-free, and shared by core + dstack-verify. Header logging keeps ONLY
// vrpc-* headers (public protocol data) and drops everything else, so a credential
// header (authorization / x-api-key) can never leak by omission.

/**
 * Keep the first `keepBytes` of a hex blob and append `…(NB)` (byte count) when
 * truncated. Accepts the value with or without a leading `0x`; always returns a
 * `0x`-prefixed string. A value already at-or-below `keepBytes` is returned in
 * full. Default keep = 4 bytes (8 hex chars) — enough to recognize a prefix, too
 * little to reconstruct anything.
 */
export function truncateHex(hex: string, keepBytes = 4): string {
  const body = hex.replace(/^0x/i, "");
  const keep = keepBytes * 2;
  return body.length <= keep
    ? `0x${body}`
    : `0x${body.slice(0, keep)}…(${Math.floor(body.length / 2)}B)`;
}

/**
 * Length-only descriptor (`"<n>B"`) for large byte blobs (event_log, app_compose,
 * vm_config) where the contents add noise but the size is useful narration.
 */
export function byteLen(value: string | Uint8Array): string {
  const n =
    typeof value === "string" ? Math.floor(value.replace(/^0x/i, "").length / 2) : value.length;
  return `${n}B`;
}

/**
 * Keep ONLY `vrpc-*` headers (case-insensitive) with their values verbatim, and
 * drop every other header entirely. The vRPC headers (`vrpc-pubkey`,
 * `vrpc-timestamp`, `vrpc-nodeid`, `vrpc-signature`) are public wire data — part
 * of the signed/verified protocol, never credentials — so no value returned here
 * can be a secret. Stricter than allowlist-redaction: non-vrpc headers (including
 * any future credential header like `authorization` / `x-api-key`) are not even
 * emitted, so a secret cannot leak by omission and the log stays uncluttered.
 */
export function pickVrpcHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase().startsWith("vrpc-")) {
      out[k] = v;
    }
  }
  return out;
}
