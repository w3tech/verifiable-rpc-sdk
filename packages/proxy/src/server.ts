// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Server factory: one Agent, one TrustedVerifier (or one ConfidentialClient) per process, one listener for every
// request. Both constructors throw InvalidOption here, before any listen socket binds.

import http from "node:http";

import {
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
import { createConfidentialHandler, createConfidentialTransport } from "./confidential";
import type { ProxyConfig } from "./config";
import { BodyTooLargeError, describeError, renderError } from "./errors";
import { createProxyLogger, type ProxyLogger } from "./logger";
import { createRequestHandler } from "./pipeline";

/** Test seam keeping verification offline; confidential mode uses only `hardwareVerifier` and `logger`. */
export type ProxyTestOverrides = Pick<
  TrustedVerifierOptions,
  "fetch" | "hardwareVerifier" | "logger"
>;

type Handler = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  signal: AbortSignal,
) => Promise<void>;

// One abort signal and one error path per request, for both modes.
function createServer(handler: Handler, log: ProxyLogger): http.Server {
  return http.createServer((req, res) => {
    const disconnected = new AbortController();
    res.once("close", () => {
      if (!res.writableFinished) disconnected.abort();
    });
    handler(req, res, disconnected.signal).catch((err: unknown) => {
      if (res.destroyed || (err as { code?: string } | null | undefined)?.code === "ECONNRESET") {
        log.debug("proxy.clientAborted");
        res.destroy();
        return;
      }
      renderError(res, err, log);
      // Unread body bytes would otherwise be parsed as the next keep-alive request.
      if (err instanceof BodyTooLargeError) {
        if (res.writableFinished) req.destroy();
        else res.once("finish", () => req.destroy());
      }
    });
  });
}

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

  const verifier = new TrustedVerifier(options);

  const server = createServer(
    createRequestHandler({ config, verifier, logger: proxyLogger, dispatcher }),
    proxyLogger,
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
    hardwareVerifier: overrides.hardwareVerifier,
    fetch: agentFetch(dispatcher),
    replayWindowMs: config.replayWindowMs,
    pubkeyCacheTtlMs: config.pubkeyCacheTtlMs,
  };

  let client: ConfidentialClient;
  try {
    client = new ConfidentialClient(options);
  } catch (err) {
    void dispatcher.close();
    throw err;
  }

  const server = createServer(
    createConfidentialHandler({ config, client, logger: proxyLogger }),
    proxyLogger,
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
          const { kind, message } = describeError(err);
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
