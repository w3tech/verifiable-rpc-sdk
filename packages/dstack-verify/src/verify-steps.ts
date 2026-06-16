// Frozen v6.0 verify-step signatures. v5.0 bodies are throwing stubs — v6.0 replaces
// ONLY the body, never the signature. Kept dependency-free (no @noble/hashes) so
// v5.0 stays a pure contract+mock with a clean A/B boundary.

import type { EventLogEntry, KeyProvider, ReportDataBinding } from "./types";

/**
 * CHK-A4/P3: replay one IMR's event log to its expected RTMR
 * (SHA-384 chain, INIT_MR zero state, 48-byte right-pad). Returns the RTMR hex.
 */
export function replayRtmr(events: EventLogEntry[]): string {
  void events;
  throw new Error("replayRtmr: not implemented in v5.0 (filled in v6.0)");
}

/**
 * CHK-A2: sha256 of the RAW app_compose text, bare lowercase hex —
 * `sha256(utf8(appCompose))`, matching core's computeComposeHash and the sidecar
 * wire (NOT deterministic-JSON re-serialization). v6.0 must hash verbatim bytes.
 */
export function computeComposeHash(appCompose: string): string {
  void appCompose;
  throw new Error("computeComposeHash: not implemented in v5.0 (filled in v6.0)");
}

/** CHK-A1: split the 64-byte report_data into pubkey[0:32] ‖ nonce[32:64]. */
export function parseReportData(reportDataHex: string): ReportDataBinding {
  void reportDataHex;
  throw new Error("parseReportData: not implemented in v5.0 (filled in v6.0)");
}

/** CHK-P7: extract the key-provider identity from the RTMR3 event log. */
export function extractKeyProvider(events: EventLogEntry[]): KeyProvider {
  void events;
  throw new Error("extractKeyProvider: not implemented in v5.0 (filled in v6.0)");
}
