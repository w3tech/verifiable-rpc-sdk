// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Reusable collecting Logger test helper.
//
// Records every `debug(event, data)` call into `calls` so tests can assert which
// events fired and inspect their (already-redacted/truncated) payloads. Pure and
// network-free; mirrors the support-file style of mock-hardware-verifier.ts.

import type { Logger } from "../../src/logger";

/** A {@link Logger} that records each `debug` call alongside its captured payload. */
export interface CollectingLogger extends Logger {
  /** Ordered (event, data) tuples for every `debug` call. */
  readonly calls: Array<[string, Record<string, unknown> | undefined]>;
}

/**
 * Build a {@link CollectingLogger}. Inject it where a `Logger` is expected, run
 * the flow, then assert over `calls` (e.g. `calls.map((c) => c[0])`).
 */
export function collectingLogger(): CollectingLogger {
  const calls: Array<[string, Record<string, unknown> | undefined]> = [];
  return {
    calls,
    debug(event, data) {
      calls.push([event, data]);
    },
  };
}
