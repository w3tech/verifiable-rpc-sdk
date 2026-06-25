// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// CloudVerifier — a HardwareVerifier implementation backed by Phala's hosted
// attestation-verify endpoint.
//
// It POSTs the raw DCAP quote (`bundle.quote.quote`, bare hex) to a configurable
// Phala-compatible endpoint and asserts `result.quote.verified === true`. Because
// the vRPC trust model treats the node as untrusted, `verified` alone is
// decorative — a genuine quote for a DIFFERENT key/node would also report
// verified===true. So this verifier ALSO performs B+ binding against OUR values:
//
//   - reportdata bind: result.quote.body.reportdata == expectedPubkey ‖ expectedNonce
//   - composeHash bind: composeHash sits at a fixed offset inside
//     result.quote.body.mr_config_id (dstack layout = 0x01 prefix byte +
//     composeHash(32B) + zero-pad), so we positionally compare hex[2:66].
//
// ⚠️ The default Phala endpoint is UNAUTHENTICATED, best-effort / no-SLA, and
// PUBLISHES the submitted quote to a public registry (readable by checksum). It
// is opt-in and the endpoint is configurable so a self-hosted verifier can avoid
// the egress. See README. No new runtime dependency — raw globalThis.fetch only.

import { AttestationError } from "./errors";
import type { HardwareVerifier } from "./hardware-verifier";
import type { AttestationBundle, VerifyPolicy } from "./types";

/** Default Phala-hosted DCAP-quote verify endpoint. */
export const DEFAULT_PHALA_VERIFY_ENDPOINT =
  "https://cloud-api.phala.com/api/v1/attestations/verify";

/** Default request timeout (ms) for the cloud verify call. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Configuration for {@link createCloudVerifier}. */
export interface CloudVerifierConfig {
  /** Verify endpoint URL. Default {@link DEFAULT_PHALA_VERIFY_ENDPOINT}. */
  endpoint?: string;
  /** Abort the request after this many ms. Default 10000. */
  timeoutMs?: number;
  /** Injectable fetch (tests). Default `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
}

/** Minimal shape of the cloud verify response — only the fields we read. */
interface CloudVerifyResponse {
  success?: boolean;
  quote?: {
    verified?: boolean;
    body?: {
      reportdata?: string;
      mr_config_id?: string;
    };
  };
}

/** Bare lowercase hex for comparison (strip optional `0x`, lowercase). */
function normHex(s: string): string {
  return s.replace(/^0x/i, "").toLowerCase();
}

/**
 * Build a {@link HardwareVerifier} backed by a Phala-compatible cloud verify
 * endpoint. The returned verifier POSTs `{ hex: bundle.quote.quote }`, asserts
 * the cloud verdict, and binds the cloud-extracted quote body to the policy's
 * expected pubkey/nonce + the bundle's composeHash (B+). All failures throw
 * `AttestationError("CHK-P1", ...)` (fail-closed). Never prints.
 */
export function createCloudVerifier(config: CloudVerifierConfig = {}): HardwareVerifier {
  const endpoint = config.endpoint ?? DEFAULT_PHALA_VERIFY_ENDPOINT;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const doFetch = config.fetch ?? globalThis.fetch;

  return {
    async verifyHardware(bundle: AttestationBundle, policy: VerifyPolicy): Promise<void> {
      // 1. POST the raw DCAP quote with an AbortController timeout.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let res: Response;
      try {
        res = await doFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hex: bundle.quote.quote }),
          signal: controller.signal,
        });
      } catch (cause) {
        const aborted =
          cause instanceof Error && (cause.name === "AbortError" || controller.signal.aborted);
        throw new AttestationError(
          "CHK-P1",
          aborted
            ? `cloud verify request timed out after ${timeoutMs}ms`
            : "cloud verify request failed (transport error)",
          { cause },
        );
      } finally {
        clearTimeout(timer);
      }

      // 2. Non-2xx → fail closed.
      if (!res.ok) {
        throw new AttestationError("CHK-P1", `cloud verify endpoint returned HTTP ${res.status}`);
      }

      // 3. Parse + shape-gate the response.
      let parsed: CloudVerifyResponse;
      try {
        parsed = (await res.json()) as CloudVerifyResponse;
      } catch (cause) {
        throw new AttestationError("CHK-P1", "malformed cloud verify response (invalid JSON)", {
          cause,
        });
      }
      const quote = parsed.quote;
      if (quote === undefined || quote === null || quote.body === undefined) {
        throw new AttestationError("CHK-P1", "malformed cloud verify response (missing quote)");
      }

      // 4. CHK-P1 verdict — strict === true (verified alone is not trusted; see B+ below).
      if (quote.verified !== true) {
        throw new AttestationError("CHK-P1", "cloud verifier reported quote NOT verified");
      }

      // 5. B+ reportdata bind: reportdata == expectedPubkey ‖ expectedNonce.
      const reportData = normHex(quote.body.reportdata ?? "");
      const expectedReportData =
        normHex(policy.binding.expectedPubkey) + normHex(policy.binding.expectedNonce);
      if (reportData !== expectedReportData) {
        throw new AttestationError(
          "CHK-P1",
          "cloud quote reportdata does not bind to expected pubkey‖nonce (real-but-foreign quote)",
        );
      }

      // 6. B+ composeHash bind: composeHash MUST be measured into mr_config_id
      //    at its fixed offset. dstack layout: mr_config_id (48B = 96 hex) =
      //    0x01 prefix byte + composeHash(32B) + zero-pad. Positionally compare
      //    hex[2:66] — a loose substring match would accept composeHash at any
      //    offset (or spanning the pad), weakening the bind.
      const composeHash = normHex(bundle.tcbInfo?.compose_hash ?? "");
      if (!/^[0-9a-f]{64}$/.test(composeHash)) {
        throw new AttestationError(
          "CHK-P1",
          "compose_hash absent or malformed — cannot bind composeHash into mr_config_id",
        );
      }
      const mrConfigId = normHex(quote.body.mr_config_id ?? "");
      if (!/^[0-9a-f]{96}$/.test(mrConfigId)) {
        throw new AttestationError(
          "CHK-P1",
          "mr_config_id absent or malformed (expected 48-byte hex)",
        );
      }
      if (mrConfigId.slice(2, 66) !== composeHash) {
        throw new AttestationError("CHK-P1", "composeHash not measured into mr_config_id");
      }

      // Point 10: success-path narration AFTER the verdict + both B+ binds pass.
      // Emitted ONLY via policy.logger (never console.*) so the "Never prints"
      // contract holds — silent unless a logger was injected.
      if (policy.logger) {
        policy.logger.debug("hardware.verify", {
          verifier: "CloudVerifier",
          quoteVerified: true,
          reportdataBind: true,
          composeHashBind: true,
        });
      }
    },
  };
}
