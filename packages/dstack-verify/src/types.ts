// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Optional fields use `field?: T` (not `| undefined`) for exactOptionalPropertyTypes.

/** Opt-in debug logger, structurally compatible with vrpc-core's `Logger`. */
export interface Logger {
  /** Observability only; must not throw. */
  debug(event: string, data?: Record<string, unknown>): void;
}

/** One TDX event-log entry (RTMR replay input). */
export interface EventLogEntry {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}

/** Attestation evidence from one node. */
export interface AttestationBundle {
  /** DCAP quote, bare hex. */
  quote: string;
  /** 64 bytes, bare hex: pubkey ‖ nonce. */
  reportData: string;
  /** Self-reported by the node; "" when absent. */
  composeHash: string;
  /** Raw app-compose text, self-reported; "" when absent. */
  appCompose: string;
}

/** report_data[0:32] must equal expectedPubkey, report_data[32:64] expectedNonce. */
export interface ReportDataBinding {
  /** 0x + 64 hex. */
  expectedPubkey: string;
  /** 32 bytes, bare hex. */
  expectedNonce: string;
}

/** Key-provider identity extracted from the RTMR3 key-provider event. */
export interface KeyProvider {
  kind: string;
  id: string;
}

/** What verifyDstackAttestation checks a bundle against. */
export interface VerifyPolicy {
  binding: ReportDataBinding;
  /** Hardware root of trust, run after CHK-A1/A2. */
  hardwareVerifier: HardwareVerifier;
  logger?: Logger;
}

/** Verifies the quote's hardware signature; resolves on success, throws `AttestationError` otherwise. Must not print. */
export interface HardwareVerifier {
  verifyHardware(bundle: AttestationBundle, policy: VerifyPolicy): Promise<void>;
}
