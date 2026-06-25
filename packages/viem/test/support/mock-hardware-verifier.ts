// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Reusable no-network HardwareVerifier test mock.
//
// The hardware-signature verifier is now MANDATORY and always-on — the live SDK
// path defaults to the Phala CloudVerifier, which POSTs the raw quote to a
// network endpoint. Unit tests must NEVER hit that endpoint, so they inject this
// mock into the adapter options instead. It makes ZERO network calls:
//   - default → `verifyHardware` resolves (the hardware step "passes").
//   - `{ fail: <Error> }` → `verifyHardware` rejects with that error.
//
// Local copy of packages/dstack-verify/tests/support/mock-hardware-verifier.ts
// (cross-package test import is awkward under this package's tsconfig/vitest
// resolver). Keep byte-identical with the canonical copy aside from the import.

import type { HardwareVerifier } from "@ankr.com/vrpc-core";

/**
 * Build a no-network {@link HardwareVerifier} for tests. `verifyHardware`
 * resolves by default; pass `{ fail }` to make it reject with that error. Never
 * touches the network.
 */
export function mockHardwareVerifier(opts: { fail?: Error } = {}): HardwareVerifier {
  return {
    async verifyHardware(): Promise<void> {
      if (opts.fail !== undefined) {
        throw opts.fail;
      }
    },
  };
}
