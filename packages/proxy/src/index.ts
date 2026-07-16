// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Public barrel — re-exports the @w3tech.io/vrpc-proxy public surface only.
//
// Implementation lives in:
//   - ./server   — createProxyServer factory + test-override seam
//   - ./config   — parseConfig (CLI flags + VRPC_PROXY_* env)
//   - ./errors   — ProxyError transport taxonomy
// (cli/pipeline/headers are internal modules.)

export type { ProxyConfig } from "./config";
export { parseConfig } from "./config";
export type { ProxyErrorKind } from "./errors";
export {
  BodyTooLargeError,
  ConfigError,
  DecodeFailedError,
  errorResponseBody,
  InternalProxyError,
  ProxyError,
  UnsignedUpstreamError,
  UpstreamBodyTooLargeError,
  UpstreamConnectError,
  UpstreamTimeoutError,
} from "./errors";
export type { ProxyTestOverrides } from "./server";
export { createProxyServer } from "./server";
