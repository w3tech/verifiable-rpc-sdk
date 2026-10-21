// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The one log sink of the proxy, on stderr, for its own events and, at debug, for core's.
// Levels silent < error < debug; a field JSON cannot encode or a throwing sink never breaks a request.

export type LogLevel = "silent" | "error" | "debug";

export interface ProxyLogger {
  error(event: string, fields?: Record<string, unknown>): void;
  debug(event: string, fields?: Record<string, unknown>): void;
}

const RANK: Record<LogLevel, number> = { silent: 0, error: 1, debug: 2 };

/**
 * Build a leveled logger. `write` defaults to stderr; tests inject a capture.
 * An event is emitted only when the configured level ranks at or above it.
 */
export function createProxyLogger(
  level: LogLevel,
  write: (line: string) => void = (line) => void process.stderr.write(line),
): ProxyLogger {
  const emit = (severity: "error" | "debug", event: string, fields?: Record<string, unknown>) => {
    if (RANK[level] < RANK[severity]) return;
    try {
      const suffix = fields && Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : "";
      write(`[vrpc-proxy] ${severity} ${event}${suffix}\n`);
    } catch {
      // A throwing sink must never break request handling.
    }
  };
  return {
    error: (event, fields) => emit("error", event, fields),
    debug: (event, fields) => emit("debug", event, fields),
  };
}
