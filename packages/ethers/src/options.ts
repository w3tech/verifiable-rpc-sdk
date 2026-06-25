// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// VrpcProvider options.
//
// `VrpcOptions` is a superset of ethers' `JsonRpcApiProviderOptions`: every
// stock JsonRpcProvider knob (batching, polling, etc.) is preserved and passed
// through to `super(...)`, plus the vRPC-specific knobs.

import type { HardwareVerifier } from "@ankr.com/vrpc-core";
import type { JsonRpcApiProviderOptions } from "ethers";

/**
 * Options accepted by `VrpcProvider`. Extends `JsonRpcApiProviderOptions` so the
 * provider is a true one-line drop-in: any ethers option (e.g. `batchMaxCount`,
 * `polling`) is honored unchanged.
 *
 * Verification is always fail-closed (see `provider.ts`).
 */
export interface VrpcOptions extends JsonRpcApiProviderOptions {
  /**
   * Replay window (ms) forwarded to verification. Omitted → vrpc-core
   * default (60s). Tests pass a wide window to neutralize static-fixture
   * staleness.
   *
   * Note: `0` (exact-millisecond match) is only usable in tests that inject
   * `nowMs` into `verifyResponse`. `VrpcProvider` does NOT expose `nowMs`, so
   * `replayWindowMs: 0` in production will always reject due to clock skew —
   * do not use it outside fixture tests.
   */
  replayWindowMs?: number;
  /** Verified-pubkey cache TTL (ms) for the attestation seam; default 1h (vrpc-core). */
  pubkeyCacheTtlMs?: number;
  /** `fetch` override for the attestation leg — test injectable. Internal. */
  fetch?: typeof fetch;
  /**
   * Internal / advanced. Override the mandatory hardware-signature verifier
   * (default: the Phala cloud verifier wired by vrpc-core). Point it at a
   * self-hosted endpoint, a future local-DCAP verifier, or a no-network test
   * mock. Hardware verification is always-on and cannot be disabled — omitting
   * this just keeps the cloud default.
   */
  hardwareVerifier?: HardwareVerifier;
}

// NOTE (v6.0): `allowlist`/`tcb`/`pccsUrl` were removed — the mock verifier
// ignores them, so exposing inert security knobs is misleading; v7.0 reintroduces
// them. `headers` was removed too: set auth on the `FetchRequest` you pass as the
// URL (`req.setHeader("x-api-key", …)`), which already covers BOTH the RPC POST
// and the internal attestation fetch.
