// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.

/** Upstream gateway API key shape: 64 hex chars or 32 alphanumerics. */
const KEY_SEGMENT = /^([a-fA-F0-9]{64}|[a-zA-Z0-9]{32})$/;

/** Mask key-shaped path segments and all query values, so no key reaches the banner. */
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
