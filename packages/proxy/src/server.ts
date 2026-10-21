// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Server factory: builds the logger, constructs exactly ONE TrustedVerifier
// for the process lifetime (its LRU pubkey cache makes verification
// network-free on cache hits), or one ConfidentialClient in Ankr Confidential
// RPC mode, and returns an http.Server. Both constructors are synchronous
// fail-fast — an invalid chain id throws InvalidChainId here, before any
// listen socket binds.

import http from "node:http";

import {
  createCloudVerifier,
  createConsoleLogger,
  defaultLogger,
  type Logger,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@w3tech.io/vrpc-core";
import {
  ConfidentialClient,
  type ConfidentialClientOptions,
} from "@w3tech.io/vrpc-core/confidential";
import { Agent, type RequestInit, fetch as undiciFetch } from "undici";
import {
  createConfidentialHandler,
  createConfidentialTransport,
  describeConfidentialError,
} from "./confidential";
import type { ProxyConfig } from "./config";
import { createProxyLogger, type ProxyLogger } from "./logger";
import { createRequestHandler } from "./pipeline";

/**
 * Test seam: TrustedVerifier injectables unit tests use to keep verification
 * deterministic and offline (attestation fetch mock, hardware-verifier mock,
 * pinned nonce, attestation stub, log capture). In confidential mode only
 * `hardwareVerifier` and `logger` apply.
 */
export type ProxyTestOverrides = Pick<
  TrustedVerifierOptions,
  "fetch" | "hardwareVerifier" | "nonceSource" | "verifyAttestation" | "logger"
>;

// Core calls fetch with a string URL only; the cast bridges undici's and the DOM's fetch types.
function agentFetch(dispatcher: Agent): typeof fetch {
  return ((url: string, init?: RequestInit) =>
    undiciFetch(url, { ...init, dispatcher })) as unknown as typeof fetch;
}

/**
 * Create the verifying proxy server. `listen()` is the caller's job — the CLI
 * binds the configured host:port; tests bind an ephemeral port.
 */
export function createProxyServer(
  config: ProxyConfig,
  overrides: ProxyTestOverrides = {},
): http.Server {
  // Core verifier logger (debug-only trace) — separate from the proxy's own
  // leveled logger. Tests may inject `overrides.logger` to capture verify logs.
  const verifierLogger =
    overrides.logger ?? (config.logLevel === "debug" ? createConsoleLogger() : defaultLogger);
  const proxyLogger = createProxyLogger(config.logLevel);

  // One Agent bounds connect, headers and body of upstream requests and of the
  // attestation fetches by --timeout. Closed with the server.
  const dispatcher = new Agent({
    connect: { timeout: config.upstreamTimeoutMs },
    headersTimeout: config.upstreamTimeoutMs,
    bodyTimeout: config.upstreamTimeoutMs,
  });

  if (config.confidential === true) {
    return createConfidentialServer(config, overrides, verifierLogger, proxyLogger, dispatcher);
  }

  // Optional keys are set conditionally rather than spread as `key: undefined`
  // (exactOptionalPropertyTypes).
  const options: TrustedVerifierOptions = {
    chainId: config.chainId,
    attestationUrl: config.attestationUrl,
    headers: config.attestationHeaders,
    logger: verifierLogger,
    fetch: overrides.fetch ?? agentFetch(dispatcher),
  };
  if (config.replayWindowMs !== undefined) options.replayWindowMs = config.replayWindowMs;
  if (config.pubkeyCacheTtlMs !== undefined) options.pubkeyCacheTtlMs = config.pubkeyCacheTtlMs;
  if (overrides.hardwareVerifier !== undefined)
    options.hardwareVerifier = overrides.hardwareVerifier;
  if (overrides.nonceSource !== undefined) options.nonceSource = overrides.nonceSource;
  if (overrides.verifyAttestation !== undefined)
    options.verifyAttestation = overrides.verifyAttestation;

  const verifier = new TrustedVerifier(options);

  const server = http.createServer(
    createRequestHandler({ config, verifier, logger: proxyLogger, dispatcher }),
  );
  server.on("close", () => {
    void dispatcher.close();
  });
  return server;
}

function createConfidentialServer(
  config: ProxyConfig,
  overrides: ProxyTestOverrides,
  verifierLogger: Logger,
  proxyLogger: ProxyLogger,
  dispatcher: Agent,
): http.Server {
  const options: ConfidentialClientOptions = {
    url: config.upstreamUrl,
    chainId: config.chainId,
    headers: config.attestationHeaders,
    transport: createConfidentialTransport(config, dispatcher),
    logger: verifierLogger,
    hardwareVerifier:
      overrides.hardwareVerifier ?? createCloudVerifier({ fetch: agentFetch(dispatcher) }),
  };
  if (config.replayWindowMs !== undefined) options.replayWindowMs = config.replayWindowMs;
  if (config.pubkeyCacheTtlMs !== undefined) options.pubkeyCacheTtlMs = config.pubkeyCacheTtlMs;

  let client: ConfidentialClient;
  try {
    client = new ConfidentialClient(options);
  } catch (err) {
    void dispatcher.close();
    throw err;
  }

  const server = http.createServer(
    createConfidentialHandler({ config, client, logger: proxyLogger }),
  );
  // Attest after the port is open; a failure is logged and the next request attests again.
  server.once("listening", () => {
    const started = performance.now();
    client
      .ready()
      .then(
        (info) =>
          proxyLogger.debug("proxy.attested", {
            nodeId: info.nodeId,
            durationMs: Math.round(performance.now() - started),
          }),
        (err: unknown) => {
          const { kind, message } = describeConfidentialError(err);
          proxyLogger.error("proxy.attestFailed", { kind, message });
        },
      )
      // A failing log sink must not end the process.
      .catch(() => {});
  });
  server.on("close", () => {
    void dispatcher.close();
  });
  return server;
}
