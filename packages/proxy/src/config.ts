// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Config surface: CLI flags via node:util parseArgs plus VRPC_PROXY_* env
// mirrors. Pure — parseConfig never touches process.exit; cli.ts owns exit
// codes. Precedence per flag: CLI value > env var > default.

import { parseArgs } from "node:util";

import { deriveVrpcUrls, validateChainId } from "@w3tech.io/vrpc-core";

import { ConfigError } from "./errors";

/** Resolved, validated proxy configuration. */
export interface ProxyConfig {
  upstreamUrl: string;
  chainId: string;
  attestationUrl: string;
  attestationHeaders: Record<string, string>;
  listenHost: string;
  listenPort: number;
  upstreamTimeoutMs: number;
  replayWindowMs?: number;
  maxBodyBytes: number;
  logLevel: "silent" | "debug";
  /** Non-fatal startup warnings; cli.ts prints them to stderr. */
  warnings?: string[];
}

const DEFAULT_LISTEN = "127.0.0.1:8969";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 33_554_432; // 32 MiB

const PARSE_OPTIONS = {
  upstream: { type: "string" },
  chain: { type: "string" },
  "attestation-url": { type: "string" },
  "attestation-header": { type: "string", multiple: true },
  listen: { type: "string" },
  timeout: { type: "string" },
  "replay-window": { type: "string" },
  "log-level": { type: "string" },
  "max-body-bytes": { type: "string" },
} as const;

function parsePositiveInt(value: string, flag: string): number {
  if (!/^\d+$/.test(value)) {
    throw new ConfigError(`${flag} must be a positive integer, got ${JSON.stringify(value)}`);
  }
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new ConfigError(`${flag} must be a positive integer, got ${JSON.stringify(value)}`);
  }
  return n;
}

function parseListen(value: string): { host: string; port: number } {
  const idx = value.lastIndexOf(":");
  if (idx <= 0 || idx === value.length - 1) {
    throw new ConfigError(`--listen must be host:port, got ${JSON.stringify(value)}`);
  }
  const host = value.slice(0, idx);
  const portRaw = value.slice(idx + 1);
  if (!/^\d+$/.test(portRaw)) {
    throw new ConfigError(`--listen port must be an integer, got ${JSON.stringify(portRaw)}`);
  }
  const port = Number(portRaw);
  if (port < 1 || port > 65535) {
    throw new ConfigError(`--listen port must be in 1-65535, got ${portRaw}`);
  }
  return { host, port };
}

function parseHeaderPair(pair: string, source: string): [string, string] {
  const idx = pair.indexOf(":");
  if (idx <= 0) {
    throw new ConfigError(`${source} must be "Name: value", got ${JSON.stringify(pair)}`);
  }
  const name = pair.slice(0, idx).trim();
  const value = pair.slice(idx + 1).trim();
  if (name === "") {
    throw new ConfigError(`${source} has an empty header name: ${JSON.stringify(pair)}`);
  }
  return [name, value];
}

/**
 * Parse and validate the proxy configuration from CLI argv and environment.
 * Throws ConfigError for any transport/config problem and lets core's
 * InvalidChainId propagate from validateChainId — cli.ts catches both
 * families and exits non-zero before the listen socket binds.
 */
export function parseConfig(argv: string[], env: NodeJS.ProcessEnv): ProxyConfig {
  let values: {
    upstream?: string;
    chain?: string;
    "attestation-url"?: string;
    "attestation-header"?: string[];
    listen?: string;
    timeout?: string;
    "replay-window"?: string;
    "log-level"?: string;
    "max-body-bytes"?: string;
  };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: PARSE_OPTIONS,
      strict: true,
      allowPositionals: false,
    }));
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new ConfigError(detail);
  }

  const upstream = values.upstream ?? env.VRPC_PROXY_UPSTREAM;
  if (upstream === undefined || upstream === "") {
    throw new ConfigError("Missing required --upstream flag (env: VRPC_PROXY_UPSTREAM)");
  }
  const chain = values.chain ?? env.VRPC_PROXY_CHAIN;
  if (chain === undefined || chain === "") {
    throw new ConfigError("Missing required --chain flag (env: VRPC_PROXY_CHAIN)");
  }

  let upstreamParsed: URL;
  try {
    upstreamParsed = new URL(upstream);
  } catch {
    throw new ConfigError(`--upstream is not a valid URL: ${JSON.stringify(upstream)}`);
  }

  // Throws core's typed InvalidChainId on a bad chain id — propagates.
  const chainId = validateChainId(chain);

  const timeoutRaw = values.timeout ?? env.VRPC_PROXY_TIMEOUT;
  const upstreamTimeoutMs =
    timeoutRaw === undefined ? DEFAULT_TIMEOUT_MS : parsePositiveInt(timeoutRaw, "--timeout");

  const replayRaw = values["replay-window"] ?? env.VRPC_PROXY_REPLAY_WINDOW;
  const replayWindowMs =
    replayRaw === undefined ? undefined : parsePositiveInt(replayRaw, "--replay-window");

  const maxBodyRaw = values["max-body-bytes"] ?? env.VRPC_PROXY_MAX_BODY_BYTES;
  const maxBodyBytes =
    maxBodyRaw === undefined
      ? DEFAULT_MAX_BODY_BYTES
      : parsePositiveInt(maxBodyRaw, "--max-body-bytes");

  const listenRaw = values.listen ?? env.VRPC_PROXY_LISTEN ?? DEFAULT_LISTEN;
  const { host: listenHost, port: listenPort } = parseListen(listenRaw);

  const logLevelRaw = values["log-level"] ?? env.VRPC_PROXY_LOG_LEVEL ?? "silent";
  if (logLevelRaw !== "silent" && logLevelRaw !== "debug") {
    throw new ConfigError(
      `--log-level must be "silent" or "debug", got ${JSON.stringify(logLevelRaw)}`,
    );
  }

  const attestationHeaders: Record<string, string> = {};
  const headerPairs =
    values["attestation-header"] ??
    (env.VRPC_PROXY_ATTESTATION_HEADER === undefined
      ? []
      : env.VRPC_PROXY_ATTESTATION_HEADER.split("\n").filter((line) => line.trim() !== ""));
  const headerSource =
    values["attestation-header"] !== undefined
      ? "--attestation-header"
      : "VRPC_PROXY_ATTESTATION_HEADER";
  for (const pair of headerPairs) {
    const [name, value] = parseHeaderPair(pair, headerSource);
    attestationHeaders[name] = value;
  }

  const explicitAttestationUrl = values["attestation-url"] ?? env.VRPC_PROXY_ATTESTATION_URL;
  const attestationUrl = explicitAttestationUrl ?? deriveVrpcUrls(upstream).attestationUrl;

  const config: ProxyConfig = {
    upstreamUrl: upstream,
    chainId,
    attestationUrl,
    attestationHeaders,
    listenHost,
    listenPort,
    upstreamTimeoutMs,
    maxBodyBytes,
    logLevel: logLevelRaw,
  };
  if (replayWindowMs !== undefined) {
    config.replayWindowMs = replayWindowMs;
  }
  if (explicitAttestationUrl === undefined && upstreamParsed.search !== "") {
    config.warnings = [
      "The upstream URL carries query parameters, which the derived attestation URL drops; pass --attestation-url explicitly if the attestation endpoint needs them.",
    ];
  }
  return config;
}
