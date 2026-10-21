// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Public barrel — re-exports the @w3tech.io/vrpc-proxy public surface only.

export type { ProxyConfig } from "./config";
export { parseConfig } from "./config";
export type { ProxyErrorKind } from "./errors";
export {
  BodyTooLargeError,
  ConfigError,
  DecodeFailedError,
  ProxyError,
  UnsignedUpstreamError,
  UnsupportedMediaTypeError,
  UpstreamBodyTooLargeError,
  UpstreamConnectError,
  UpstreamTimeoutError,
} from "./errors";
export { createProxyServer } from "./server";
