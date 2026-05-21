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

import { InvalidNonce, MalformedAttestationResponse } from "./errors";

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
 * (may be empty under the simulator).
 */
export interface Attestation {
  quote: GetQuoteResponse;
  pubkey: string;
  composeHash: string;
}

/**
 * Fetch a fresh TDX attestation quote from the sidecar, bound to the caller
 * supplied 32-byte nonce.
 *
 * The nonce length is validated synchronously — a wrong-length nonce throws
 * {@link InvalidNonce} BEFORE any network call.
 *
 * Sends `GET ${url}/attestation?nonce=<bare-lowercase-hex>` with no headers.
 * The query parameter is encoded without the `0x` prefix; the sidecar's
 * `parse_user_nonce` accepts both forms but bare hex matches the canonical
 * wire convention.
 *
 * On a malformed response body (missing or wrong-typed fields), throws
 * {@link MalformedAttestationResponse} — never {@link BadSignature}, because
 * this route is unsigned.
 */
export async function fetchAttestation(url: string, nonce: Uint8Array): Promise<Attestation> {
  // Synchronous fast-fail BEFORE any fetch.
  if (nonce.length !== 32) {
    throw new InvalidNonce(`expected 32 bytes, got ${nonce.length}`);
  }

  // Bare-hex (no 0x prefix) query encoding.
  const nonceHex = bytesToHex(nonce);
  const target = `${url}/attestation?nonce=${nonceHex}`;

  // Unsigned route — no headers required, response headers ignored.
  const resp = await fetch(target);
  const body = (await resp.json()) as unknown;

  return narrowAttestation(body);
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
  };
}
