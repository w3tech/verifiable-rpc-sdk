#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Runnable entry (via tsx): parse + validate config, construct the server
// (which fail-fast constructs the verifier), bind, print the startup banner.
// Any config or chain-id error exits 1 BEFORE the listen socket binds.

import type http from "node:http";

import { VerificationError } from "@w3tech.io/vrpc-core";

import { type ProxyConfig, parseConfig } from "./config";
import { ProxyError } from "./errors";
import { createProxyServer } from "./server";

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
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

server.listen(config.listenPort, config.listenHost, () => {
  // The only unconditional output: one banner line on stderr.
  process.stderr.write(
    `vrpc-proxy listening on http://${config.listenHost}:${config.listenPort} -> ${config.upstreamUrl} (chain ${config.chainId})\n`,
  );
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.closeAllConnections();
    server.close(() => process.exit(0));
  });
}
