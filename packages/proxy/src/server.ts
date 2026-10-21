// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Server factory: one Agent, one TrustedVerifier (or one ConfidentialClient) per process, one listener for every
// request. Both constructors throw InvalidOption here, before any listen socket binds.

import http from "node:http";

import { type Logger, TrustedVerifier, type TrustedVerifierOptions } from "@w3tech.io/vrpc-core";
import {
  ConfidentialClient,
  type ConfidentialClientOptions,
} from "@w3tech.io/vrpc-core/confidential";
import { Agent, type RequestInit, fetch as undiciFetch } from "undici";
import { confidentialHandler, createConfidentialTransport } from "./confidential";
import type { ProxyConfig } from "./config";
import { BodyTooLargeError, codeOf, describeError, renderError } from "./errors";
import { createProxyLogger, type ProxyLogger } from "./logger";
import { openHandler } from "./pipeline";
import { bufferStream } from "./upstream";

/** Test seam keeping verification offline; confidential mode uses only `hardwareVerifier` and `logger`. */
export type ProxyTestOverrides = Pick<
  TrustedVerifierOptions,
  "fetch" | "hardwareVerifier" | "logger"
>;

type Handler = (
  req: http.IncomingMessage,
  body: Buffer,
  res: http.ServerResponse,
  signal: AbortSignal,
) => Promise<void>;

// One body cap, one abort signal and one error path per request, for both modes. The Agent closes with the server.
function createServer(
  handler: Handler,
  maxBodyBytes: number,
  log: ProxyLogger,
  dispatcher: Agent,
): http.Server {
  const server = http.createServer((req, res) => {
    const disconnected = new AbortController();
    res.once("close", () => {
      if (!res.writableFinished) disconnected.abort();
    });
    bufferStream(req, maxBodyBytes, () => new BodyTooLargeError(maxBodyBytes))
      .then((body) => handler(req, body, res, disconnected.signal))
      .catch((err: unknown) => {
        if (res.destroyed || codeOf(err) === "ECONNRESET") {
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
  server.on("close", () => void dispatcher.close());
  return server;
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
export function createProxyServer(config: ProxyConfig): http.Server {
  return createServerWith(config, {});
}

/** `createProxyServer` with the test seams; the package barrel does not export it. */
export function createServerWith(config: ProxyConfig, overrides: ProxyTestOverrides): http.Server {
  const proxyLogger = createProxyLogger(config.logLevel);
  // One sink: core events go to the proxy log at debug; below it core keeps its silent path.
  const coreLogger = overrides.logger ?? (config.logLevel === "debug" ? proxyLogger : undefined);

  // One Agent bounds connect, headers and body of upstream requests and of the
  // attestation fetches by --timeout.
  const dispatcher = new Agent({
    connect: { timeout: config.upstreamTimeoutMs },
    headersTimeout: config.upstreamTimeoutMs,
    bodyTimeout: config.upstreamTimeoutMs,
  });

  try {
    if (config.confidential === true) {
      return createConfidentialServer(config, overrides, coreLogger, proxyLogger, dispatcher);
    }
    const verifier = new TrustedVerifier({
      chainId: config.chainId,
      attestationUrl: config.attestationUrl,
      headers: config.attestationHeaders,
      logger: coreLogger,
      fetch: overrides.fetch ?? agentFetch(dispatcher),
      hardwareVerifier: overrides.hardwareVerifier,
      replayWindowMs: config.replayWindowMs,
      pubkeyCacheTtlMs: config.pubkeyCacheTtlMs,
    });
    const handler = openHandler(config, verifier, proxyLogger, dispatcher);
    return createServer(handler, config.maxBodyBytes, proxyLogger, dispatcher);
  } catch (err) {
    void dispatcher.close();
    throw err;
  }
}

function createConfidentialServer(
  config: ProxyConfig,
  overrides: ProxyTestOverrides,
  coreLogger: Logger | undefined,
  proxyLogger: ProxyLogger,
  dispatcher: Agent,
): http.Server {
  const options: ConfidentialClientOptions = {
    url: config.upstreamUrl,
    chainId: config.chainId,
    headers: config.attestationHeaders,
    transport: createConfidentialTransport(config, dispatcher),
    logger: coreLogger,
    hardwareVerifier: overrides.hardwareVerifier,
    fetch: agentFetch(dispatcher),
    replayWindowMs: config.replayWindowMs,
    pubkeyCacheTtlMs: config.pubkeyCacheTtlMs,
  };

  const client = new ConfidentialClient(options);
  const server = createServer(
    confidentialHandler(config, client, proxyLogger),
    config.maxBodyBytes,
    proxyLogger,
    dispatcher,
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
  return server;
}
