// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Proxy-local leveled logger → stderr. Levels are ordered silent < error <
// debug: `error` surfaces fail-closed reasons on a running daemon, `debug`
// adds per-request forward/verify traces. The core TrustedVerifier takes its
// own `{ debug }` logger separately (server.ts) — this one carries the proxy's
// own events only. Writes are guarded so a throwing sink never breaks a request.

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
    const suffix = fields && Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : "";
    try {
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
