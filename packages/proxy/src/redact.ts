// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// URL secret redaction for the startup banner: mask any path segment that
// looks like an API key (shark's key shape) and every query-string value, so
// neither a key-in-path nor a key-in-query secret ever reaches logs.

/** Shark API key shape: 64 hex chars or 32 alphanumerics. */
const KEY_SEGMENT = /^([a-fA-F0-9]{64}|[a-zA-Z0-9]{32})$/;

/** Mask key-shaped path segments and all query values in `url` for logging. */
export function redactUrl(url: string): string {
  const u = new URL(url);
  u.pathname = u.pathname
    .split("/")
    .map((seg) => (KEY_SEGMENT.test(seg) ? "***" : seg))
    .join("/");
  for (const key of u.searchParams.keys()) {
    u.searchParams.set(key, "***");
  }
  return u.toString();
}
