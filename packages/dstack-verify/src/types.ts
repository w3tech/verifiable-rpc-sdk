// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Frozen, complete contract types for dstack/TDX attestation verification.
//
// Field sets derived from the sidecar /attestation wire shape and the
// phala dstack reference (TcbInfo/EventLog/report_data layout, signature_chain).
// These types are FROZEN now: a future release (real DCAP verification) fills
// helper/verifier bodies WITHOUT changing any exported type. Optional fields use `field?: T`
// (NOT `| undefined`) to stay compatible with exactOptionalPropertyTypes.

import type { HardwareVerifier } from "./hardware-verifier";

/**
 * Minimal opt-in debug logger. Declared locally (NOT imported from
 * @w3tech.io/vrpc-core) so this package stays a dependency-free leaf. It is
 * structurally identical to — and assignable from — core's `Logger`, so core
 * threads its own logger straight into {@link VerifyPolicy.logger}.
 */
export interface Logger {
  /** Debug-level narration. MUST NOT throw; observability only, never control flow. */
  debug(event: string, data?: Record<string, unknown>): void;
}

/** One TDX event-log entry (RTMR replay input). Matches dstack TcbInfo.event_log. */
export interface EventLogEntry {
  /** 0..3 — which RTMR this event measures into. */
  imr: number;
  event_type: number;
  /** bare hex, SHA-384 digest (right-padded to 48B during replay). → CHK-A4/P3 */
  digest: string;
  event: string;
  /** bare hex. */
  event_payload: string;
}

/** Raw quote object as served by the sidecar (bare-hex, no 0x). Mirrors core GetQuoteResponse. */
export interface QuoteEnvelope {
  /** DCAP quote, bare hex. → CHK-P1/P2/P3/P4 */
  quote: string;
  /** Serialized event log (structured form also on TcbInfo.event_log). */
  event_log: string;
  /** 64-byte bare hex: [0:32]=pubkey, [32:64]=nonce. → CHK-A1 */
  report_data: string;
  /** VM config; may be "" under simulator. → CHK-P4 */
  vm_config: string;
}

/** TCB / measurement info (source for compose-hash + RTMR replay). */
export interface TcbInfo {
  /** → CHK-P3 */
  mrtd: string;
  /** → CHK-P3 */
  rtmr0: string;
  /** OS measurement, pinned. → CHK-P3 */
  rtmr1: string;
  /** OS measurement, pinned. → CHK-P3 */
  rtmr2: string;
  /** Replay target for the app event log. → CHK-A4 */
  rtmr3: string;
  /** RAW app_compose text; computeComposeHash input. → CHK-A2 */
  app_compose: string;
  event_log: EventLogEntry[];
  /** Pinned. → CHK-P5 */
  os_image_hash?: string;
  /** Sidecar-reported; recompute, never trust. */
  compose_hash?: string;
  /** → CHK-P7 */
  key_provider_info?: string;
  device_id?: string;
  mr_aggregated?: string;
}

/** Full attestation bundle handed to the verifier. */
export interface AttestationBundle {
  quote: QuoteEnvelope;
  tcbInfo: TcbInfo;
  /** Ed25519 signing pubkey the sidecar bound into report_data[0:32]; 0x + 64 hex. → CHK-A1 */
  pubkey: string;
  /** Caller-supplied 32-byte freshness nonce echoed in report_data[32:64]; bare hex. → CHK-A1 */
  nonce: string;
  /**
   * KMS signature chain from dstack get_key (guest-agent: [link0_sig, k256_signature]).
   * Bare-hex array. UNUSED by the current mock and by the initial real-verify path
   * (kept for the cross-repo follow-up). MANDATORY now so the follow-up never has to
   * change the frozen contract. → CHK-P7/P8
   */
  signature_chain: string[];
  /** Optional structured app/instance ids if surfaced by the attestation. */
  appId?: string;
  instanceId?: string;
}

/** report_data → pubkey/nonce binding inputs. → CHK-A1 */
export interface ReportDataBinding {
  /** Expected signing pubkey (0x+64 hex) that MUST equal report_data[0:32]. */
  expectedPubkey: string;
  /** Expected 32-byte nonce (bare hex) that MUST equal report_data[32:64]. */
  expectedNonce: string;
}

/** Pinned allowlists replacing on-chain governance (CHK-A6/P5/P9/G*). */
export interface PinnedAllowlist {
  /** Whitelisted compose-hashes, bare hex. → CHK-A2/A6 */
  composeHashes: string[];
  /** → CHK-P3 */
  mrtd: string;
  /** → CHK-P3 */
  rtmr0: string;
  /** → CHK-P3 */
  rtmr1: string;
  /** → CHK-P3 */
  rtmr2: string;
  /** → CHK-P5 */
  osImageHashes: string[];
  /** Trusted key-provider identities. → CHK-P7 */
  kmsIdentities: string[];
}

/**
 * Canonical empty allowlist — pins NOTHING. The current mock verifier ignores the
 * allowlist, so callers (the adapters / core seam) use this as the default when
 * no pins are supplied. The shape lives here because `PinnedAllowlist` is a
 * dstack-verify domain type — consumers MUST NOT hand-roll their own.
 * ⚠️ Once real verification lands, an empty allowlist trusts no anchors and would
 * reject — production deployments MUST supply real pins. Treat as immutable
 * (shared reference; do not mutate its arrays).
 */
export const EMPTY_ALLOWLIST: PinnedAllowlist = {
  composeHashes: [],
  mrtd: "",
  rtmr0: "",
  rtmr1: "",
  rtmr2: "",
  osImageHashes: [],
  kmsIdentities: [],
};

/** TCB acceptance policy for DCAP (CHK-P2). */
export interface TcbPolicy {
  /** Allowed dcap-qvl TCB statuses, e.g. ["UpToDate","SWHardeningNeeded"]. */
  allowedStatuses: string[];
  /** Reject if the quote debug flag is set. Default true. */
  rejectDebug?: boolean;
}

/** Key-provider identity extracted from the RTMR3 key-provider event. → CHK-P7 */
export interface KeyProvider {
  kind: string;
  id: string;
}

/** Verification policy (pinned trust anchors + reportData binding + escape hatch). */
export interface VerifyPolicy {
  /** reportData→pubkey/nonce binding inputs. → CHK-A1 */
  binding: ReportDataBinding;
  /** Pinned trust anchors. → CHK-A2/A6/P3/P5/P7/P9 */
  allowlist: PinnedAllowlist;
  /** DCAP TCB acceptance. → CHK-P1/P2 */
  tcb: TcbPolicy;
  /** Operational collateral source for dcap-qvl (NOT a trust dependency). Default Intel PCS. */
  pccsUrl?: string;
  /**
   * ESCAPE HATCH. When true, the mock verifier resolves (with a loud warning).
   * To be removed in a future release once the real body lands. Default/absent = fail-closed.
   */
  allowInsecureMock?: boolean;
  /**
   * OPT-IN pluggable step-4 hardware-signature verifier (→ CHK-P1). When set,
   * `verifyDstackAttestation` runs it after CHK-A2 and, on success, bypasses the
   * CHK-MOCK gate (the verifier IS the hardware root of trust for that call).
   * When ABSENT, behavior is unchanged — the CHK-MOCK gate / `allowInsecureMock`
   * governs as before. A future LocalDcapVerifier drops into this same field.
   */
  hardwareVerifier?: HardwareVerifier;
  /**
   * OPT-IN debug logger threaded in by core's `buildVerifyPolicy` (the verifier's
   * `this.logger`, structurally compatible with the local {@link Logger}). Present
   * only when the caller injected a logger; absent == silent. Carries narration
   * into the verify steps without changing the frozen `(bundle, policy)` seam.
   */
  logger?: Logger;
}
