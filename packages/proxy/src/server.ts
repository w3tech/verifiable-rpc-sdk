// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Server factory: builds the logger, constructs exactly ONE TrustedVerifier
// for the process lifetime (its LRU pubkey cache makes verification
// network-free on cache hits), and returns an http.Server. The verifier
// constructor is synchronous fail-fast — an invalid chain id throws
// InvalidChainId here, before any listen socket binds.

import http from "node:http";

import {
  createConsoleLogger,
  defaultLogger,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@w3tech.io/vrpc-core";
import { Agent } from "undici";

import type { ProxyConfig } from "./config";
import { createRequestHandler } from "./pipeline";

/**
 * Test seam: TrustedVerifier injectables unit tests use to keep verification
 * deterministic and offline (attestation fetch mock, hardware-verifier mock,
 * pinned nonce, attestation stub, log capture).
 */
export type ProxyTestOverrides = Pick<
  TrustedVerifierOptions,
  "fetch" | "hardwareVerifier" | "nonceSource" | "verifyAttestation" | "logger"
>;

/**
 * Create the verifying proxy server. `listen()` is the caller's job — the CLI
 * binds the configured host:port; tests bind an ephemeral port.
 */
export function createProxyServer(
  config: ProxyConfig,
  overrides: ProxyTestOverrides = {},
): http.Server {
  const logger =
    overrides.logger ?? (config.logLevel === "debug" ? createConsoleLogger() : defaultLogger);

  // Optional keys are set conditionally rather than spread as `key: undefined`
  // (exactOptionalPropertyTypes).
  const options: TrustedVerifierOptions = {
    chainId: config.chainId,
    attestationUrl: config.attestationUrl,
    headers: config.attestationHeaders,
    logger,
  };
  if (config.replayWindowMs !== undefined) options.replayWindowMs = config.replayWindowMs;
  if (overrides.fetch !== undefined) options.fetch = overrides.fetch;
  if (overrides.hardwareVerifier !== undefined)
    options.hardwareVerifier = overrides.hardwareVerifier;
  if (overrides.nonceSource !== undefined) options.nonceSource = overrides.nonceSource;
  if (overrides.verifyAttestation !== undefined)
    options.verifyAttestation = overrides.verifyAttestation;

  const verifier = new TrustedVerifier(options);

  // Dedicated upstream Agent so the TCP/TLS connect phase is bound by the
  // configured --timeout too — per-request undici options cover only the
  // headers/body phases. Closed with the server to release keep-alive sockets.
  const dispatcher = new Agent({ connect: { timeout: config.upstreamTimeoutMs } });

  const server = http.createServer(createRequestHandler({ config, verifier, logger, dispatcher }));
  server.on("close", () => {
    void dispatcher.close();
  });
  return server;
}
