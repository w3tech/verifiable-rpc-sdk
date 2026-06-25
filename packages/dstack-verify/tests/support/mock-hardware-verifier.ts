// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Reusable no-network HardwareVerifier test mock.
//
// The hardware-signature verifier is now MANDATORY and always-on — the live SDK
// path defaults to the Phala CloudVerifier, which POSTs the raw quote to a
// network endpoint. Unit tests must NEVER hit that endpoint, so they inject this
// mock into the policy / adapter options instead. It makes ZERO network calls:
//   - default → `verifyHardware` resolves (the hardware step "passes").
//   - `{ fail: <Error> }` → `verifyHardware` rejects with that error (propagation).
//
// This is the canonical copy. Cross-package test dirs (core / ethers / viem)
// keep a byte-identical local copy when their tsconfig/vitest resolver makes
// importing across package boundaries awkward — keep all copies in sync.

import type { HardwareVerifier } from "../../src/hardware-verifier";

/**
 * Build a no-network {@link HardwareVerifier} for tests. `verifyHardware`
 * resolves by default; pass `{ fail }` to make it reject with that error (used
 * to prove the mandatory verifier's failure propagates through
 * `verifyDstackAttestation`). Never touches the network.
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
