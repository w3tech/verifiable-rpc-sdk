// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The opt-in debug-logger seam for the vRPC SDK.
//
// The SDK is SILENT by default: nothing is emitted unless a caller injects a
// Logger. The seam is a single `debug` method (one narration level); errors keep
// throwing typed errors (the throw path is never replaced by a log). No external
// dependency is taken — the interface is our own and the convenience helper uses
// only the built-in `console`.

/** Minimal opt-in debug logger. Inject to narrate the verify flow; default is a no-op (silent). */
export interface Logger {
  /**
   * Debug-level narration. MUST NOT throw and MUST NOT be relied upon for
   * control flow — it is observability only, never part of the verify decision.
   * `event` is a stable dotted name (e.g. "verify.start"); `data` is a flat,
   * already-redacted/truncated field bag — callers never pass raw secrets.
   */
  debug(event: string, data?: Record<string, unknown>): void;
}

/**
 * Default no-op logger: a frozen singleton, referenced by identity for the
 * silent-path guard (`logger !== defaultLogger`). The SDK uses this whenever no
 * logger is injected, so the default path stays silent and allocation-free.
 */
export const defaultLogger: Logger = Object.freeze({ debug: () => {} });

/**
 * Convenience console logger — prefixes `[vrpc]` and writes to `console.debug`.
 * NEVER wired by default: callers opt in by passing it as `logger`. `data` is
 * omitted from the console call when undefined so single-arg events stay clean.
 */
export function createConsoleLogger(): Logger {
  return {
    debug(event, data) {
      if (data === undefined) {
        console.debug(`[vrpc] ${event}`);
      } else {
        console.debug(`[vrpc] ${event}`, data);
      }
    },
  };
}

/**
 * Wrap an injected logger so a throwing `debug()` can never break verification.
 * Applied ONCE at construction (not per call): the wrapper swallows any throw
 * from `inner.debug`, upholding the never-throw contract even for a buggy logger.
 */
export function safeLogger(inner: Logger): Logger {
  return {
    debug(event, data) {
      try {
        inner.debug(event, data);
      } catch {
        // Swallow — logging must never break verification.
      }
    },
  };
}
