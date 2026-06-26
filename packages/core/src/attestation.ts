// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Standalone `fetchAttestation` helper — calls `GET /attestation?nonce=<hex>`
// against the configured sidecar URL, parses the nested `attestation.quote`
// wire shape, and returns a typed `Attestation`.
//
// The attestation route is unsigned by contract: the sidecar does NOT emit
// `vRPC-*` headers for this endpoint, and the SDK MUST NOT call any
// signature-verification machinery on the response. This file therefore does
// not import `verifyAsync` or touch `vRPC-Signature` / `vRPC-Pubkey` /
// `vRPC-Timestamp` at all — by construction.

import { bytesToHex } from "@noble/hashes/utils.js";

import {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  InvalidNonce,
  MalformedAttestationResponse,
} from "./errors";
import type { Logger } from "./logger";
import type { VerifiedResponse } from "./verifier";

/**
 * Inner `quote` object inside the attestation response. All fields are
 * bare-hex (no `0x` prefix), matching the dstack-guest-agent wire format.
 * `vm_config` may be empty string under the simulator.
 */
export interface GetQuoteResponse {
  quote: string;
  event_log: string;
  report_data: string;
  vm_config: string;
}

/**
 * Top-level attestation response. `pubkey` is `0x` + 64 hex chars (32-byte
 * Ed25519 pubkey), `composeHash` is the `app-compose.json` content hash
 * (may be empty under the simulator), and `app_compose` is the raw verbatim
 * `app-compose.json` text the sidecar returns alongside `composeHash`.
 */
export interface Attestation {
  quote: GetQuoteResponse;
  pubkey: string;
  composeHash: string;
  /**
   * Raw verbatim `app_compose` text, served in the `/attestation` body next to
   * `composeHash`. Self-reported by the node (NOT a trust anchor) — used only for
   * CHK-A2 self-consistency (`sha256(utf8(app_compose)) == composeHash`). Defaults
   * to `""` when the sidecar does not provide it (older nodes / simulator), in
   * which case CHK-A2 dormant-skips.
   */
  app_compose: string;
}

/** Options for {@link fetchAttestation}. */
export interface FetchAttestationOptions {
  /**
   * Full attestation endpoint URL (no query), e.g.
   * `https://rpc.ankr.com/arbitrum_vrpc/attestation`. The transport layer derives
   * this from the user URL (`deriveVrpcUrls`); the `_vrpc` route convention lives
   * there, not here.
   */
  attestationUrl: string;
  /** Caller-supplied 32-byte attestation nonce. */
  nonce: Uint8Array;
  /**
   * Serving node id (`vRPC-NodeId`). Added as `node_id` when present, OMITTED when
   * absent. Absent + behind the gateway → the gateway can't route → error (fail-closed, catches
   * a "behind the gateway but no routing id" misconfig); absent + direct node →
   * `/attestation?nonce=…` works (the node is identified by the connection). NodeId
   * is attestation ROUTING only — never part of signature verification (the trust
   * unit is the `vRPC-Pubkey` the signature is checked against).
   */
  nodeId?: string;
  /** Extra request headers (e.g. `x-api-key`). */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Fetch a fresh TDX attestation quote from the `/attestation` endpoint, bound to
 * the caller-supplied 32-byte nonce. The single attestation-fetch entry point —
 * used by both the lazy verify seam ({@link TrustedVerifier}) and the boot-time
 * `anchorTrust`.
 *
 * Sends `GET ${attestationUrl}?nonce=<bare-lowercase-hex>`, plus `&node_id=<id>`
 * when {@link FetchAttestationOptions.nodeId} is present. The nonce is validated
 * synchronously (32 bytes) — a wrong length throws {@link InvalidNonce} BEFORE any
 * network call. The query nonce is bare hex (no `0x` prefix), matching the
 * sidecar's canonical wire convention.
 *
 * A `404` is terminal (stale/unknown node id, or a gateway route miss) and throws
 * {@link AttestationNodeNotFoundError} BEFORE parsing — the SDK does NOT retry or
 * fall back to another node. This route is unsigned by contract, so no `vRPC-*`
 * verification runs here; a malformed body throws {@link MalformedAttestationResponse}.
 */
export async function fetchAttestation(opts: FetchAttestationOptions): Promise<Attestation> {
  // Synchronous fast-fail BEFORE any fetch.
  if (opts.nonce.length !== 32) {
    throw new InvalidNonce(`expected 32 bytes, got ${opts.nonce.length}`);
  }

  // Bare-hex (no 0x prefix) nonce; node_id only when a serving node id is known.
  const nonceHex = bytesToHex(opts.nonce);
  const target =
    `${opts.attestationUrl}?nonce=${nonceHex}` +
    (opts.nodeId === undefined ? "" : `&node_id=${encodeURIComponent(opts.nodeId)}`);

  const headers: Record<string, string> = opts.headers ?? {};

  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const resp = await fetchImpl(target, { headers });

  // Stale/unknown node id (or gateway route miss) — terminal, no fallback or retry.
  if (resp.status === 404) {
    throw new AttestationNodeNotFoundError(opts.nodeId ?? "(no node_id)");
  }

  const body = (await resp.json()) as unknown;
  return narrowAttestation(body);
}

/**
 * Prove the fetched attestation belongs to the node that signed the RPC
 * response: the attestation `pubkey` must equal the response `vRPC-Pubkey`
 * (`verification.pubkeyHex`, already normalized to lowercase `0x`-hex). On
 * mismatch throws {@link AttestationCorrelationError}; on match returns.
 *
 * `logger` is an OPTIONAL opt-in narration sink (already safe-wrapped by the
 * caller). When present, the `attestation.correlation` event is emitted BEFORE
 * the throw-on-mismatch so a mismatch is observable before it raises. Omitted
 * (the default) keeps the silent path allocation-free.
 */
export function verifyAttestationCorrelation(
  attestation: Attestation,
  verifiedResponse: VerifiedResponse,
  logger?: Logger,
): void {
  const expected = verifiedResponse.verification.pubkeyHex;
  if (logger) {
    logger.debug("attestation.correlation", {
      expectedPubkey: expected,
      actualPubkey: attestation.pubkey,
      match: attestation.pubkey === expected,
    });
  }
  if (attestation.pubkey !== expected) {
    throw new AttestationCorrelationError(expected, attestation.pubkey);
  }
}

/**
 * Defensive narrowing of an `unknown` JSON body to {@link Attestation}.
 * Every missing or wrong-typed field is reported with a field-path reason.
 */
function narrowAttestation(body: unknown): Attestation {
  if (body === null || typeof body !== "object") {
    throw new MalformedAttestationResponse("response is not a JSON object");
  }
  const obj = body as Record<string, unknown>;

  if (typeof obj.pubkey !== "string") {
    throw new MalformedAttestationResponse(
      "pubkey" in obj ? "pubkey must be string" : "missing field: pubkey",
    );
  }
  if (typeof obj.composeHash !== "string") {
    throw new MalformedAttestationResponse(
      "composeHash" in obj ? "composeHash must be string" : "missing field: composeHash",
    );
  }
  if (obj.quote === null || typeof obj.quote !== "object") {
    throw new MalformedAttestationResponse("quote must be an object");
  }

  const quote = obj.quote as Record<string, unknown>;
  if (typeof quote.quote !== "string") {
    throw new MalformedAttestationResponse(
      "quote" in quote ? "quote.quote must be string" : "missing field: quote.quote",
    );
  }
  if (typeof quote.event_log !== "string") {
    throw new MalformedAttestationResponse(
      "event_log" in quote ? "quote.event_log must be string" : "missing field: quote.event_log",
    );
  }
  if (typeof quote.report_data !== "string") {
    throw new MalformedAttestationResponse(
      "report_data" in quote
        ? "quote.report_data must be string"
        : "missing field: quote.report_data",
    );
  }
  if (typeof quote.vm_config !== "string") {
    throw new MalformedAttestationResponse(
      "vm_config" in quote ? "quote.vm_config must be string" : "missing field: quote.vm_config",
    );
  }

  return {
    quote: {
      quote: quote.quote,
      event_log: quote.event_log,
      report_data: quote.report_data,
      vm_config: quote.vm_config,
    },
    pubkey: obj.pubkey,
    composeHash: obj.composeHash,
    // Raw verbatim app_compose, served next to composeHash. Lenient: absent or
    // non-string (older sidecars / simulator) defaults to "" → CHK-A2 dormant-skips.
    app_compose: typeof obj.app_compose === "string" ? obj.app_compose : "",
  };
}
