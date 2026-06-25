// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Pure truncation + redaction helpers for the opt-in debug logger.
//
// These functions are the SINGLE point where logged field values are shortened
// or sanitized, so the leak surface is auditable in one place. They are pure,
// dependency-free, and shared by core + dstack-verify. Header sanitization uses an
// ALLOWLIST (not a denylist) so a future header can never leak by omission.

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
  return body.length <= keep ? `0x${body}` : `0x${body.slice(0, keep)}…(${body.length / 2}B)`;
}

/**
 * Length-only descriptor (`"<n>B"`) for large byte blobs (event_log, app_compose,
 * vm_config) where the contents add noise but the size is useful narration.
 */
export function byteLen(value: string | Uint8Array): string {
  const n = typeof value === "string" ? value.replace(/^0x/i, "").length / 2 : value.length;
  return `${n}B`;
}

/**
 * Lowercased allowlist of header keys that are safe to log verbatim. Everything
 * NOT in this set (authorization, x-api-key, vrpc-signature, any unknown key) is
 * redacted by {@link redactHeaders}.
 */
export const SAFE_HEADER_KEYS: ReadonlySet<string> = new Set([
  "content-type",
  "content-length",
  "content-encoding",
  "vrpc-pubkey",
  "vrpc-timestamp",
]);

/** Redaction marker substituted for every non-allowlisted header value. */
const REDACTION_MARKER = "[redacted]";

/**
 * ALLOWLIST header redaction: keep only {@link SAFE_HEADER_KEYS} (case-insensitive)
 * verbatim; replace every other value with `[redacted]`. Allowlisting means a
 * future header key never leaks by accident — only explicitly-known-safe keys pass.
 */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SAFE_HEADER_KEYS.has(k.toLowerCase()) ? v : REDACTION_MARKER;
  }
  return out;
}
