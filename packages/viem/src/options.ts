// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpcHttp transport options. Mirrors vrpc-ethers' VrpcOptions knobs plus the
// viem-specific passthroughs: `headers` (x-api-key / gateway route) and an
// injectable `fetchFn` seam. All verification lives in vrpc-core; these only feed it.

import type { HardwareVerifier } from "@ankr.com/vrpc-core";

/**
 * Options for `vrpcHttp(url, opts?)`. All optional with safe defaults. Always
 * fail-closed (see `transport.ts`). The chain id bound into the signed pre-image
 * comes from the viem client's `chain` (`chain.id`); with no chain set it is
 * auto-derived from a verified `eth_chainId` bootstrap on the first request.
 */
export interface VrpcHttpOptions {
  /**
   * Replay window (ms) forwarded to `verifyResponse`. Omitted → vrpc-core
   * default (60s). Tests pass a wide window to neutralize static-fixture
   * staleness.
   *
   * Note: `0` (exact-millisecond match) is only usable in tests that inject
   * `nowMs` into `verifyResponse`. The transport does NOT expose `nowMs`, so
   * `replayWindowMs: 0` in production will always reject due to clock skew —
   * do not use it outside fixture tests.
   */
  replayWindowMs?: number;
  /**
   * Extra request headers (e.g. `x-api-key`, or the gateway `chain_vrpc` route
   * header). Applied to BOTH the JSON-RPC POST and the internal attestation
   * fetch, so a single auth set here covers both legs. `content-type:
   * application/json` is always set by the transport.
   */
  headers?: Record<string, string>;
  /**
   * Injectable fetch seam (mirrors viem's `http` transport `fetchFn`). Defaults
   * to the global `fetch`. Lets tests drive the transport offline and consumers
   * pass a routing fetch wrapper.
   */
  fetchFn?: (url: string, init: RequestInit) => Promise<Response>;
  /**
   * Per-request HTTP timeout (ms) applied to the own `fetch` as an
   * `AbortSignal.timeout`. Mirrors viem `http()` resolution
   * (`config.timeout ?? 10_000`): when omitted, the client-injected timeout is
   * used, falling back to 10s.
   */
  timeout?: number;
  /** Verified-pubkey cache TTL (ms) forwarded to the verifier; default 1h. */
  pubkeyCacheTtlMs?: number;
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
// them when the real verifier needs consumer-pinned anchors.
