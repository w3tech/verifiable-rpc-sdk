// Frozen, v6.0-complete contract types for dstack/TDX attestation verification.
//
// Field sets derived from the sidecar /attestation + /info wire shape and the
// phala dstack reference (TcbInfo/EventLog/report_data layout, signature_chain).
// These types are FROZEN now: v6.0 (real DCAP verification) fills helper/verifier
// bodies WITHOUT changing any exported type. Optional fields use `field?: T`
// (NOT `| undefined`) to stay compatible with exactOptionalPropertyTypes.

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

/** TCB / measurement info from /info tcb_info (source for compose-hash + RTMR replay). */
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
   * Bare-hex array. UNUSED by the v5.0 mock and by v6.0 3a (kept for the 3b cross-repo
   * ticket). MANDATORY now so 3b never has to change the frozen contract. → CHK-P7/P8 (3b)
   */
  signature_chain: string[];
  /** Optional structured app/instance ids if surfaced by /info. */
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
   * v5.0 ESCAPE HATCH. When true, the mock verifier resolves (with a loud warning).
   * Removed in v6.0 once the real body lands. Default/absent = fail-closed.
   */
  allowInsecureMock: boolean;
}
