// VrpcProvider options (Phase 30, ETHERS-01).
//
// `VrpcOptions` is a superset of ethers' `JsonRpcApiProviderOptions`: every
// stock JsonRpcProvider knob (batching, polling, etc.) is preserved and passed
// through to `super(...)`, plus the three vRPC-specific knobs.

import type { JsonRpcApiProviderOptions } from "ethers";

/**
 * Verification policy:
 *   - `strict`     (default) — a `VerificationError` from `verifyResponse`
 *     propagates out of `_send`; no unverified data is ever returned.
 *   - `permissive` — a `VerificationError` is caught, the `logger` fires once,
 *     and the parsed body is returned anyway. Opt-in only.
 */
export type VrpcVerification = "strict" | "permissive";

/**
 * Options accepted by `VrpcProvider`. Extends `JsonRpcApiProviderOptions` so the
 * provider is a true one-line drop-in: any ethers option (e.g. `batchMaxCount`,
 * `polling`) is honored unchanged.
 */
export interface VrpcOptions extends JsonRpcApiProviderOptions {
  /** Verification policy. Defaults to `"strict"` (fail-closed). */
  verification?: VrpcVerification;
  /**
   * Replay window (ms) forwarded to `verifyResponse`. Omitted → vrpc-core
   * default (60s). Tests pass a wide window to neutralize static-fixture
   * staleness.
   *
   * Note: `0` (exact-millisecond match) is only usable in tests that inject
   * `nowMs` into `verifyResponse`. `VrpcProvider` does NOT expose `nowMs`, so
   * `replayWindowMs: 0` in production will always reject due to clock skew —
   * do not use it outside fixture tests.
   */
  replayWindowMs?: number;
  /**
   * Invoked once per downgraded verification failure in permissive mode.
   * Defaults to a `console.warn`.
   */
  logger?: (msg: string, err: unknown) => void;
}
