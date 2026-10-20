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
