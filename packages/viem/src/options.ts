// vrpcHttp transport options (Phase 31, VIEM-01).
//
// `VrpcHttpOptions` mirrors the vrpc-ethers `VrpcOptions` verification knobs
// (verification policy, replay window, logger) and adds the viem-specific
// transport passthroughs: per-request `headers` (x-api-key / shark `chain_vrpc`
// route) and an injectable `fetchFn` seam (mirrors viem's own `http` transport
// `fetchFn`) — the cleanest offline-wiring test seam AND a hook for a consumer's
// routing fetch wrapper. All verification logic lives in vrpc-core (PKG-05);
// these options only feed it.

/**
 * Verification policy:
 *   - `strict`     (default) — a `VerificationError` from `verifyResponse`
 *     propagates out of the transport `request`; no unverified data is returned.
 *   - `permissive` — a `VerificationError` is caught, the `logger` fires once,
 *     and the parsed body is returned anyway. Opt-in only.
 */
export type VrpcVerification = "strict" | "permissive";

/**
 * Options accepted by `vrpcHttp(url, opts)`. `chainId` is required (it is bound
 * into the signed pre-image); everything else is optional with safe defaults.
 */
export interface VrpcHttpOptions {
  /**
   * EVM-style chain id bound into the canonical pre-image. Coerced to `bigint`
   * via `BigInt()` WITHOUT a number round-trip — chain ids may exceed
   * `Number.MAX_SAFE_INTEGER` (2^53−1) and widening through `number` would lose
   * precision and reject intact responses (false `BadSignature`). MD-01.
   */
  chainId: number | bigint;
  /** Verification policy. Defaults to `"strict"` (fail-closed). */
  verification?: VrpcVerification;
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
   * Invoked once per downgraded verification failure in permissive mode.
   * Defaults to a `console.warn`.
   */
  logger?: (msg: string, err: unknown) => void;
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
}
