// vrpcHttp transport options. Mirrors vrpc-ethers' VrpcOptions knobs plus the
// viem-specific passthroughs: `headers` (x-api-key / shark route) and an
// injectable `fetchFn` seam. All verification lives in vrpc-core; these only feed it.

import type { PinnedAllowlist, TcbPolicy } from "@ankr.com/dstack-verify";

/**
 * Options for `vrpcHttp(url, opts?)`. `chainId` is optional (auto-derived when
 * omitted); everything else is optional with safe defaults. Always fail-closed
 * (see `transport.ts`).
 */
export interface VrpcHttpOptions {
  /**
   * EVM chain id bound into the signed pre-image. Optional: auto-derived from a
   * verified `eth_chainId` bootstrap on first request when omitted. Coerced to
   * bigint without a number round-trip (chain ids can exceed 2^53). Passing it
   * explicitly is RECOMMENDED — skips the bootstrap and pins the binding.
   */
  chainId?: number | bigint;
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
   * Extra request headers merged into every POST (e.g. `x-api-key`, or the
   * shark `chain_vrpc` route header). `content-type: application/json` is always
   * set by the transport.
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
   * used, falling back to 10s. (LO-03)
   */
  timeout?: number;
  /** Verified-pubkey cache TTL (ms) forwarded to the verifier; default 1h. */
  pubkeyCacheTtlMs?: number;
  /** Pinned trust anchors (INTEG-02); default `EMPTY_ALLOWLIST` when omitted. */
  allowlist?: PinnedAllowlist;
  /** DCAP TCB acceptance forwarded to the seam; default rejects debug quotes. */
  tcb?: TcbPolicy;
  /** Operational collateral source for dcap-qvl (NOT a trust dependency). */
  pccsUrl?: string;
  /**
   * Auth key sent as `x-api-key` on the attestation fetch (parity with the
   * ethers half). `headers` may also carry `x-api-key` for the RPC leg.
   */
  apiKey?: string;
}
