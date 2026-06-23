// VrpcProvider options.
//
// `VrpcOptions` is a superset of ethers' `JsonRpcApiProviderOptions`: every
// stock JsonRpcProvider knob (batching, polling, etc.) is preserved and passed
// through to `super(...)`, plus the vRPC-specific knobs.

import type { PinnedAllowlist, TcbPolicy } from "@ankr.com/dstack-verify";
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
  /** Pinned trust anchors for the attestation `VerifyPolicy`; default empty (v5.0 mock). */
  allowlist?: PinnedAllowlist;
  /** DCAP TCB acceptance policy for the attestation `VerifyPolicy`. */
  tcb?: TcbPolicy;
  /** Operational collateral source for dcap-qvl (NOT a trust dependency). */
  pccsUrl?: string;
  /**
   * Auth headers for the SDK. The idiomatic ethers way is to set them on the
   * `FetchRequest` you pass as the URL (`req.setHeader("x-api-key", …)`) — those
   * already ride to BOTH the RPC POST and the internal attestation fetch. This
   * `headers` option is an additional override for the attestation leg only
   * (e.g. when attestation needs a different/extra header than the RPC leg);
   * it merges over the FetchRequest headers per-key. SECRET — MUST NOT be logged.
   */
  headers?: Record<string, string>;
  /** `fetch` override for the attestation leg — test injectable. Internal. */
  fetch?: typeof fetch;
}
