// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Frozen verify-step signatures. computeComposeHash + parseReportData are
// implemented (used by the active CHK-A1/CHK-A2 checks); replayRtmr +
// extractKeyProvider remain throwing stubs until the real DCAP layers land.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

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
 * CHK-A2: the dstack compose-hash of an `app_compose` string —
 * `sha256(utf8(appCompose))` as bare lowercase hex. No canonicalization: dstack
 * hashes the raw file bytes verbatim (NOT deterministic-JSON re-serialization),
 * matching the sidecar wire.
 */
export function computeComposeHash(appCompose: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(appCompose)));
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
