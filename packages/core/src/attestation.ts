// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Attest a node: GET `/attestation`, check the answer, verify the quote. The route is unsigned
// by contract, so no `vRPC-*` signature check runs here.

import { bytesToHex } from "@noble/hashes/utils.js";
import {
  type AttestationBundle,
  AttestationError,
  EMPTY_ALLOWLIST,
  type HardwareVerifier,
  type VerifyPolicy,
  verifyDstackAttestation,
} from "@w3tech.io/dstack-verify";

import { AttestationFailed, AttestationUnavailable, InvalidNonce } from "./errors";
import { byteLen, truncateHex } from "./log-redact";
import { defaultLogger, type Logger } from "./logger";
import { type ConfidentialTransport, fetchTransport, guardedSend } from "./transport";
import { getHeader, NODE_ID_RE } from "./verify";

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
  /** Full attestation endpoint URL (no query), e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
  /** Caller-supplied 32-byte attestation nonce. */
  nonce: Uint8Array;
  /** Serving node id (`vRPC-NodeId`), sent as `node_id` when present. Routing only, never part of signature checks. */
  nodeId?: string;
  /** Extra request headers (e.g. `x-api-key`). */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Fetch a TDX attestation bound to a 32-byte nonce: `GET <attestationUrl>?nonce=<hex>[&node_id=<id>]`.
 * A nonce that is not 32 bytes throws {@link InvalidNonce} before any network call. Redirects are
 * not followed; a transport failure or a non-2xx answer throws {@link AttestationUnavailable}, a
 * malformed body {@link AttestationFailed}.
 */
export async function fetchAttestation(opts: FetchAttestationOptions): Promise<Attestation> {
  if (opts.nonce.length !== 32) {
    throw new InvalidNonce(`expected 32 bytes, got ${opts.nonce.length}`);
  }
  const { attestation } = await getAttestation(fetchTransport(opts.fetch), {
    attestationUrl: opts.attestationUrl,
    nonce: opts.nonce,
    nodeId: opts.nodeId,
    headers: opts.headers ?? {},
    requireNodeId: false,
  });
  return attestation;
}

// Real answers are about 20 KB; the gateway caps at 4 MiB.
const MAX_ATTESTATION_BYTES = 1_048_576;

interface GetAttestationOptions {
  attestationUrl: string;
  nonce: Uint8Array;
  headers: Record<string, string>;
  nodeId?: string | undefined;
  signal?: AbortSignal | undefined;
  requireNodeId: boolean;
}

async function getAttestation(
  transport: ConfidentialTransport,
  opts: GetAttestationOptions,
): Promise<{ attestation: Attestation; nodeId: string | undefined }> {
  const response = await guardedSend(
    transport,
    {
      method: "GET",
      url:
        `${opts.attestationUrl}?nonce=${bytesToHex(opts.nonce)}` +
        (opts.nodeId === undefined ? "" : `&node_id=${encodeURIComponent(opts.nodeId)}`),
      headers: opts.headers,
      ...(opts.signal === undefined ? {} : { signal: opts.signal }),
      maxBytes: MAX_ATTESTATION_BYTES,
    },
    (tooLarge, cause) =>
      new AttestationUnavailable(tooLarge ? "too-large" : "transport", { cause }),
  );
  // The size cap comes first: an oversize 429 is unavailable without a status (503 in the proxy).
  if (response.status < 200 || response.status > 299) {
    throw new AttestationUnavailable("status", { status: response.status });
  }
  const nodeId = getHeader(response.headers, "vRPC-NodeId") || undefined;
  // A repeated header arrives comma-joined: malformed evidence, as on a signed response.
  if (nodeId !== undefined && !NODE_ID_RE.test(nodeId)) {
    throw new AttestationFailed("malformed", "vRPC-NodeId must be a single node id");
  }
  if (opts.requireNodeId && nodeId === undefined) {
    throw new AttestationUnavailable("node-id-missing", { status: response.status });
  }
  return { attestation: parseAttestationBody(response.body), nodeId };
}

// Above the gateway's attestation timeout plus the hardware verifier's.
export const ATTESTATION_TIMEOUT_MS = 60_000;

export interface AttestNodeOptions {
  transport: ConfidentialTransport;
  attestationUrl: string;
  headers: Record<string, string>;
  hardwareVerifier: HardwareVerifier;
  /** Already safe-wrapped; `defaultLogger` keeps the path silent. */
  logger: Logger;
  signal?: AbortSignal | undefined;
  /** Open mode: the verified signer; the attested pubkey must equal it. */
  expectPubkey?: string;
  /** Open mode: `vRPC-NodeId` of the signed response, sent as `node_id`. */
  nodeId?: string | undefined;
}

export interface NodeAttestation<NodeId extends string | undefined = string | undefined> {
  nodeId: NodeId;
  pubkeyHex: string;
  composeHash: string;
  attestedAt: number;
}

const ATTESTED_PUBKEY_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * Attest one node with a fresh nonce. With `expectPubkey` (open mode) the attested pubkey must
 * match it before the hardware verifier runs; without it (Ankr Confidential RPC) the answer must
 * carry `vRPC-NodeId`.
 */
export function attestNode(
  opts: AttestNodeOptions & { expectPubkey: string },
): Promise<NodeAttestation>;
export function attestNode(
  opts: Omit<AttestNodeOptions, "expectPubkey" | "nodeId">,
): Promise<NodeAttestation<string>>;
export async function attestNode(opts: AttestNodeOptions): Promise<NodeAttestation> {
  const { logger, expectPubkey } = opts;
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  // The URL may carry the API key; nodeId and nonce identify the fetch.
  logger.debug("attestation.fetch", {
    ...(opts.nodeId === undefined ? {} : { nodeId: opts.nodeId }),
    nonce: bytesToHex(nonce),
  });
  const { attestation, nodeId } = await getAttestation(opts.transport, {
    attestationUrl: opts.attestationUrl,
    nonce,
    headers: opts.headers,
    nodeId: opts.nodeId,
    signal: opts.signal,
    requireNodeId: expectPubkey === undefined,
  });
  if (!ATTESTED_PUBKEY_RE.test(attestation.pubkey)) {
    throw new AttestationFailed("malformed", "pubkey must be 0x + 64 hex chars");
  }
  const pubkeyHex = attestation.pubkey.toLowerCase();
  if (expectPubkey !== undefined) {
    logger.debug("attestation.correlation", {
      expectedPubkey: expectPubkey,
      actualPubkey: pubkeyHex,
      match: pubkeyHex === expectPubkey,
    });
    if (pubkeyHex !== expectPubkey) {
      throw new AttestationFailed("pubkey-mismatch", `expected ${expectPubkey}, got ${pubkeyHex}`);
    }
  }
  if (logger !== defaultLogger) {
    logger.debug("attestation.received", {
      reportData: attestation.quote.report_data,
      composeHash: attestation.composeHash,
      pubkeyHex,
      quote: truncateHex(attestation.quote.quote),
      eventLog: byteLen(attestation.quote.event_log),
      appCompose: byteLen(new TextEncoder().encode(attestation.app_compose)),
    });
  }
  try {
    await verifyDstackAttestation(
      mapAttestationToBundle(attestation, pubkeyHex, nonce),
      buildVerifyPolicy(pubkeyHex, nonce, opts.hardwareVerifier, logger),
    );
  } catch (err) {
    if (err instanceof AttestationError) {
      if (err.unavailable) throw new AttestationUnavailable("verifier", { cause: err });
      throw new AttestationFailed("check", err.detail, { chkId: err.chkId, cause: err });
    }
    throw new AttestationFailed("check", "hardware verifier failed", {
      chkId: "CHK-P1",
      cause: err,
    });
  }
  return { nodeId, pubkeyHex, composeHash: attestation.composeHash, attestedAt: Date.now() };
}

/** `app_compose` is self-reported by the node: CHK-A2 self-consistency only, never a trust anchor. */
function mapAttestationToBundle(
  attestation: Attestation,
  pubkeyHex: string,
  nonce: Uint8Array,
): AttestationBundle {
  return {
    quote: { ...attestation.quote },
    pubkey: pubkeyHex,
    nonce: bytesToHex(nonce),
    tcbInfo: {
      mrtd: "",
      rtmr0: "",
      rtmr1: "",
      rtmr2: "",
      rtmr3: "",
      app_compose: attestation.app_compose,
      event_log: [],
      compose_hash: attestation.composeHash,
    },
    signature_chain: [],
  };
}

/** Binds report_data to the pubkey and nonce; the hardware verifier always runs. */
function buildVerifyPolicy(
  pubkeyHex: string,
  nonce: Uint8Array,
  hardwareVerifier: HardwareVerifier,
  logger: Logger,
): VerifyPolicy {
  return {
    binding: { expectedPubkey: pubkeyHex, expectedNonce: bytesToHex(nonce) },
    allowlist: EMPTY_ALLOWLIST,
    tcb: { allowedStatuses: [], rejectDebug: true },
    hardwareVerifier,
    ...(logger === defaultLogger ? {} : { logger }),
  };
}

function parseAttestationBody(bytes: Uint8Array): Attestation {
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    // The platform parse error quotes the input.
    throw new AttestationFailed("malformed", "response is not valid JSON");
  }
  return narrowAttestation(body);
}

/**
 * Defensive narrowing of an `unknown` JSON body to {@link Attestation}.
 * Every missing or wrong-typed field is reported with a field-path reason.
 */
function narrowAttestation(body: unknown): Attestation {
  if (body === null || typeof body !== "object") {
    throw new AttestationFailed("malformed", "response is not a JSON object");
  }
  const obj = body as Record<string, unknown>;

  if (typeof obj.pubkey !== "string") {
    throw new AttestationFailed(
      "malformed",
      "pubkey" in obj ? "pubkey must be string" : "missing field: pubkey",
    );
  }
  if (typeof obj.composeHash !== "string") {
    throw new AttestationFailed(
      "malformed",
      "composeHash" in obj ? "composeHash must be string" : "missing field: composeHash",
    );
  }
  if (obj.quote === null || typeof obj.quote !== "object") {
    throw new AttestationFailed("malformed", "quote must be an object");
  }

  const quote = obj.quote as Record<string, unknown>;
  if (typeof quote.quote !== "string") {
    throw new AttestationFailed(
      "malformed",
      "quote" in quote ? "quote.quote must be string" : "missing field: quote.quote",
    );
  }
  if (typeof quote.event_log !== "string") {
    throw new AttestationFailed(
      "malformed",
      "event_log" in quote ? "quote.event_log must be string" : "missing field: quote.event_log",
    );
  }
  if (typeof quote.report_data !== "string") {
    throw new AttestationFailed(
      "malformed",
      "report_data" in quote
        ? "quote.report_data must be string"
        : "missing field: quote.report_data",
    );
  }
  if (typeof quote.vm_config !== "string") {
    throw new AttestationFailed(
      "malformed",
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
