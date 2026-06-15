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

/** Options for {@link fetchAttestationViaShark}. */
export interface FetchAttestationViaSharkOptions {
  /** Shark proxy base URL (no trailing slash), e.g. `https://rpc.ankr.com`. */
  sharkBase: string;
  /** Chain slug used to build the `<chain>_vrpc` route segment, e.g. `eth`. */
  chain: string;
  /** Id of the serving node (from `vRPC-NodeId`) whose attestation to fetch. */
  nodeId: string;
  /** Caller-supplied 32-byte attestation nonce. */
  nonce: Uint8Array;
  /** Auth key sent as `x-api-key`; an explicit `headers` entry wins. */
  apiKey?: string;
  /** Extra request headers; an `x-api-key` entry here overrides `apiKey`. */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Fetch a serving node's attestation through the shark proxy's targeted route
 * `GET <sharkBase>/<chain>_vrpc/attestation?nonce=<hex>&node_id=<id>`.
 *
 * The nonce is validated synchronously (32 bytes) and encoded as bare lowercase
 * hex; `node_id` is URL-encoded. A 404 means the node id is stale/unknown and
 * throws {@link AttestationNodeNotFoundError} BEFORE parsing — the SDK does NOT
 * retry or fall back to another node. Other responses are parsed with the same
 * narrowing as the direct-node path; this route is unsigned, so no `vRPC-*`
 * verification runs here.
 */
export async function fetchAttestationViaShark(
  opts: FetchAttestationViaSharkOptions,
): Promise<Attestation> {
  // Synchronous fast-fail BEFORE any fetch.
  if (opts.nonce.length !== 32) {
    throw new InvalidNonce(`expected 32 bytes, got ${opts.nonce.length}`);
  }

  const nonceHex = bytesToHex(opts.nonce);
  const target =
    `${opts.sharkBase}/${opts.chain}_vrpc/attestation` +
    `?nonce=${nonceHex}&node_id=${encodeURIComponent(opts.nodeId)}`;

  // apiKey-derived x-api-key first so an explicit headers entry wins.
  const headers: Record<string, string> = {
    ...(opts.apiKey === undefined ? {} : { "x-api-key": opts.apiKey }),
    ...(opts.headers ?? {}),
  };

  const fetchImpl = opts.fetch ?? globalThis.fetch;
  const resp = await fetchImpl(target, { headers });

  // Stale/unknown node id — terminal, no fallback or retry.
  if (resp.status === 404) {
    throw new AttestationNodeNotFoundError(opts.nodeId);
  }

  const body = (await resp.json()) as unknown;
  return narrowAttestation(body);
}

/**
 * Prove the fetched attestation belongs to the node that signed the RPC
 * response: the attestation `pubkey` must equal the response `vRPC-Pubkey`
 * (`verification.pubkeyHex`, already normalized to lowercase `0x`-hex). On
 * mismatch throws {@link AttestationCorrelationError}; on match returns.
 */
export function verifyAttestationCorrelation(
  attestation: Attestation,
  verifiedResponse: VerifiedResponse,
): void {
  const expected = verifiedResponse.verification.pubkeyHex;
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
  };
}
