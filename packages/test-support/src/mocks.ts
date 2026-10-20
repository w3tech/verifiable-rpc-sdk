// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Test doubles for SDK interfaces, typed structurally so the kit imports no SDK package.

// No-network verifier for tests: resolves, or rejects with `fail`.
export function mockHardwareVerifier(options: { fail?: Error } = {}): {
  verifyHardware(): Promise<void>;
} {
  return {
    async verifyHardware() {
      if (options.fail !== undefined) throw options.fail;
    },
  };
}

export interface CollectingLogger {
  readonly calls: Array<[string, Record<string, unknown> | undefined]>;
  debug(event: string, data?: Record<string, unknown>): void;
}

// Records each debug call.
export function collectingLogger(): CollectingLogger {
  const calls: Array<[string, Record<string, unknown> | undefined]> = [];
  return {
    calls,
    debug(event, data) {
      calls.push([event, data]);
    },
  };
}
