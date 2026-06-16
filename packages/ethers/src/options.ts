// VrpcProvider options (Phase 30, ETHERS-01).
//
// `VrpcOptions` is a superset of ethers' `JsonRpcApiProviderOptions`: every
// stock JsonRpcProvider knob (batching, polling, etc.) is preserved and passed
// through to `super(...)`, plus the three vRPC-specific knobs.

import type { PinnedAllowlist, TcbPolicy } from "@ankr.com/dstack-verify";
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
  /**
   * EVM-style chain id bound into the canonical pre-image. OPTIONAL: when
   * omitted (and not supplied positionally) the provider lazily derives it via
   * one UNVERIFIED `eth_chainId` bootstrap on first use. Passing it explicitly
   * is STRONGLY RECOMMENDED — it removes the bootstrap round-trip, pins the
   * binding, and turns a chain misconfig into an immediate fail-closed
   * `BadSignature`. Coerced with `BigInt()` WITHOUT a number round-trip, so
   * chain ids beyond `Number.MAX_SAFE_INTEGER` (2^53−1) bind exactly.
   */
  chainId?: number | bigint;
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
  /**
   * Shark proxy base URL (no trailing slash) for the lazy-attestation leg, e.g.
   * `https://rpc.ankr.com`. OPT-IN: routing through the `TrustedVerifier` seam
   * (lazy TDX attestation) engages ONLY when BOTH `attestationBaseUrl` and
   * `chainSlug` are set; otherwise the provider verifies via plain
   * `verifyResponse` (unchanged).
   */
  attestationBaseUrl?: string;
  /**
   * Chain slug used to build the `<chain>_vrpc` attestation route, e.g. `eth`.
   * OPT-IN: see {@link attestationBaseUrl} — both are required to engage the seam.
   */
  chainSlug?: string;
  /** Verified-pubkey cache TTL (ms) for the seam; default 1h (vrpc-core). */
  pubkeyCacheTtlMs?: number;
  /** Pinned trust anchors for the attestation `VerifyPolicy`; default empty (v5.0 mock). */
  allowlist?: PinnedAllowlist;
  /** DCAP TCB acceptance policy for the attestation `VerifyPolicy`. */
  tcb?: TcbPolicy;
  /** Operational collateral source for dcap-qvl (NOT a trust dependency). */
  pccsUrl?: string;
  /**
   * Auth key for the attestation-leg fetch ONLY (sent as `x-api-key` on the
   * shark `/attestation` GET). ethers carries RPC auth in its `FetchRequest`,
   * not here. SECRET — MUST NOT be logged.
   */
  apiKey?: string;
  /**
   * Extra request headers for the attestation-leg fetch ONLY. SECRET — MUST NOT
   * be logged.
   */
  headers?: Record<string, string>;
  /** `fetch` override for the attestation leg — test injectable. Internal. */
  fetch?: typeof fetch;
}
