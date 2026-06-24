// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Frozen verify-step signatures; bodies are throwing stubs until implemented.
// Only the body is replaced, never the signature. Kept dependency-free (no
// @noble/hashes) so this stays a pure contract+mock with a clean A/B boundary.

import { AttestationError } from "./errors";
import type { EventLogEntry, KeyProvider, ReportDataBinding } from "./types";

/**
 * CHK-A4/P3: replay one IMR's event log to its expected RTMR
 * (SHA-384 chain, INIT_MR zero state, 48-byte right-pad). Returns the RTMR hex.
 */
export function replayRtmr(events: EventLogEntry[]): string {
  void events;
  throw new Error("replayRtmr: not implemented yet");
}

/**
 * CHK-A2: sha256 of the RAW app_compose text, bare lowercase hex —
 * `sha256(utf8(appCompose))`, matching core's computeComposeHash and the sidecar
 * wire (NOT deterministic-JSON re-serialization). Must hash verbatim bytes.
 */
export function computeComposeHash(appCompose: string): string {
  void appCompose;
  throw new Error("computeComposeHash: not implemented yet");
}

/**
 * CHK-A1: split the 64-byte report_data into pubkey[0:32] ‖ nonce[32:64].
 * `report_data` is bare hex (no `0x`). The returned `expectedPubkey` carries a
 * `0x` prefix to match the `ReportDataBinding`/bundle convention; `expectedNonce`
 * stays bare. Shape-gates the input to exactly 128 hex chars and throws
 * `AttestationError("CHK-A1", …)` on malformed input — never a silent slice.
 */
export function parseReportData(reportDataHex: string): ReportDataBinding {
  const hex = reportDataHex.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{128}$/.test(hex)) {
    throw new AttestationError(
      "CHK-A1",
      `report_data must be 64 bytes (128 hex chars); got ${hex.length} hex chars`,
    );
  }
  return {
    expectedPubkey: `0x${hex.slice(0, 64)}`,
    expectedNonce: hex.slice(64, 128),
  };
}

/** CHK-P7: extract the key-provider identity from the RTMR3 event log. */
export function extractKeyProvider(events: EventLogEntry[]): KeyProvider {
  void events;
  throw new Error("extractKeyProvider: not implemented yet");
}
