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
  /** Optional API key sent as `x-api-key` to both the upstream and the attestation endpoint. */
  apiKey?: string;
  attestationUrl: string;
  attestationHeaders: Record<string, string>;
  listenHost: string;
  listenPort: number;
  upstreamTimeoutMs: number;
  replayWindowMs?: number;
  /**
   * How long a verified attestation (keyed by the node's signing pubkey) is
   * reused before re-attestation — the `--attestation-cache-ttl` flag. Maps to
   * core's `pubkeyCacheTtlMs`; when unset core's default applies.
   */
  pubkeyCacheTtlMs?: number;
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
  "chain-id": { type: "string" },
  "api-key": { type: "string" },
  listen: { type: "string" },
  timeout: { type: "string" },
  "replay-window": { type: "string" },
  "attestation-cache-ttl": { type: "string" },
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

/**
 * Parse and validate the proxy configuration from CLI argv and environment.
 * Throws ConfigError for any transport/config problem and lets core's
 * InvalidChainId propagate from validateChainId — cli.ts catches both
 * families and exits non-zero before the listen socket binds.
 */
export function parseConfig(argv: string[], env: NodeJS.ProcessEnv): ProxyConfig {
  let values: {
    upstream?: string;
    "chain-id"?: string;
    "api-key"?: string;
    listen?: string;
    timeout?: string;
    "replay-window"?: string;
    "attestation-cache-ttl"?: string;
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
  const chain = values["chain-id"] ?? env.VRPC_PROXY_CHAIN_ID;
  if (chain === undefined || chain === "") {
    throw new ConfigError("Missing required --chain-id flag (env: VRPC_PROXY_CHAIN_ID)");
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

  const attestationCacheTtlRaw =
    values["attestation-cache-ttl"] ?? env.VRPC_PROXY_ATTESTATION_CACHE_TTL;
  const pubkeyCacheTtlMs =
    attestationCacheTtlRaw === undefined
      ? undefined
      : parsePositiveInt(attestationCacheTtlRaw, "--attestation-cache-ttl");

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

  // Same single-URL model as the SDK adapters: both legs derive from the
  // upstream URL; the API key rides as an `x-api-key` header on both.
  const apiKey = values["api-key"] ?? env.VRPC_PROXY_API_KEY;
  const attestationHeaders: Record<string, string> =
    apiKey !== undefined && apiKey !== "" ? { "x-api-key": apiKey } : {};
  // Both legs derive from the one user URL (same as the SDK adapters): the RPC
  // route gets `_vrpc`, the attestation route drops any REST prefix. So a bare
  // `/arbitrum` resolves to the vRPC endpoint without the user spelling it out.
  const { rpcUrl, attestationUrl } = deriveVrpcUrls(upstream);

  const config: ProxyConfig = {
    upstreamUrl: rpcUrl,
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
  if (pubkeyCacheTtlMs !== undefined) {
    config.pubkeyCacheTtlMs = pubkeyCacheTtlMs;
  }
  if (apiKey !== undefined && apiKey !== "") {
    config.apiKey = apiKey;
  }
  if (upstreamParsed.search !== "") {
    config.warnings = [
      "The upstream URL carries query parameters, which the derived attestation URL drops; prefer --api-key or a key-in-path upstream URL.",
    ];
  }
  return config;
}
