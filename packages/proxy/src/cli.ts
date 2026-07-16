#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Runnable entry (via tsx): parse + validate config, construct the server
// (which fail-fast constructs the verifier), bind, print the startup banner.
// Any config or chain-id error exits 1 BEFORE the listen socket binds.

import type http from "node:http";

import {
  DEFAULT_PUBKEY_CACHE_TTL_MS,
  DEFAULT_REPLAY_WINDOW_MS,
  VerificationError,
} from "@w3tech.io/vrpc-core";

import { type ProxyConfig, parseConfig } from "./config";
import { ProxyError } from "./errors";
import { createProxyServer } from "./server";

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

// Mask any path segment that looks like an API key (shark's key shape) and
// every query-string value so the startup banner never leaks a key-in-path or
// key-in-query secret to logs.
const KEY_SEGMENT = /^([a-fA-F0-9]{64}|[a-zA-Z0-9]{32})$/;
function redactUrl(url: string): string {
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

function startupBanner(config: ProxyConfig): string {
  // Unset optional knobs fall back to core's own default — show that value so
  // the banner reflects the effective config, sourced from core's constants.
  const ms = (v: number | undefined, dflt: number) =>
    v === undefined ? `default (${dflt}ms)` : `${v}ms`;
  return [
    `vrpc-proxy listening on http://${config.listenHost}:${config.listenPort}`,
    `  upstream:              ${redactUrl(config.upstreamUrl)}`,
    `  attestation:           ${redactUrl(config.attestationUrl)}`,
    `  chain-id:              ${config.chainId}`,
    `  api-key:               ${config.apiKey === undefined ? "unset" : "set"}`,
    `  timeout:               ${config.upstreamTimeoutMs}ms`,
    `  replay-window:         ${ms(config.replayWindowMs, DEFAULT_REPLAY_WINDOW_MS)}`,
    `  attestation-cache-ttl: ${ms(config.pubkeyCacheTtlMs, DEFAULT_PUBKEY_CACHE_TTL_MS)}`,
    `  max-body-bytes:        ${config.maxBodyBytes}`,
    `  log-level:             ${config.logLevel}`,
    "",
  ].join("\n");
}

function loadConfig(): ProxyConfig {
  // pnpm passes the `--` separator through to the script verbatim
  // (`pnpm run proxy -- --upstream ...`); drop it before flag parsing.
  const argv = process.argv.slice(2);
  if (argv[0] === "--") {
    argv.shift();
  }
  try {
    return parseConfig(argv, process.env);
  } catch (err) {
    if (err instanceof ProxyError || err instanceof VerificationError) {
      fail(err.message);
    }
    throw err;
  }
}

function buildServer(config: ProxyConfig): http.Server {
  try {
    return createProxyServer(config);
  } catch (err) {
    if (err instanceof ProxyError || err instanceof VerificationError) {
      fail(err.message);
    }
    throw err;
  }
}

const config = loadConfig();
for (const warning of config.warnings ?? []) {
  process.stderr.write(`warning: ${warning}\n`);
}

const server = buildServer(config);

// Bind failures (EADDRINUSE, EADDRNOTAVAIL, ...) exit cleanly like config
// errors instead of surfacing as an uncaught exception with a stack trace.
server.on("error", (err) => {
  fail(err instanceof Error ? err.message : String(err));
});

server.listen(config.listenPort, config.listenHost, () => {
  // Startup banner on stderr: the launch config, with any key-in-path segment
  // and the API key value redacted so secrets never reach container logs.
  process.stderr.write(startupBanner(config));
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.closeAllConnections();
    server.close(() => process.exit(0));
  });
}
