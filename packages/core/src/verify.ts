// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Transport-agnostic verify seam.
//
// `verifyResponse` is the verify half (steps 4-9) of `VerifierClient.call()`,
// lifted into a free function so both the ethers `_send` override and
// the viem `custom` transport can feed raw request bytes + raw
// (content-decoded) response bytes + response headers through ONE verify path
// without any client-lib knowledge. `VerifierClient.call()` is itself refactored
// to delegate here — there is exactly one verify implementation.
//
// Steps performed:
//   4. Header parse — missing -> MissingHeader
//   5. Header validate — bad shape -> MalformedHeader
//   6. Canonical 104-byte pre-image reconstruct (buildPreImage, verbatim)
//   7. Hex -> bytes
//   8. Ed25519 verifyAsync — false -> BadSignature
//   9. Replay-window check (AFTER signature verify) -> StaleTimestamp
//
// This function operates on whatever bytes it is given: the caller hands it the
// already content-decoded request/response bytes (exactly like buildPreImage).
// It does NOT know about fetch, JSON-RPC envelopes, accept-encoding, or JSON
// parsing — those stay in the transport layer.

import { verifyAsync } from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils.js";

import { BadSignature, MalformedHeader, MissingHeader, StaleTimestamp } from "./errors";
import type { Logger } from "./logger";
import { buildPreImage, sha256, validateChainId } from "./preimage";

export const DEFAULT_REPLAY_WINDOW_MS = 60_000;

const SIGNATURE_HEADER = "vRPC-Signature";
const TIMESTAMP_HEADER = "vRPC-Timestamp";
const PUBKEY_HEADER = "vRPC-Pubkey";
const NODE_ID_HEADER = "vRPC-NodeId";

const SIGNATURE_HEX_RE = /^0x[0-9a-f]{128}$/;
const PUBKEY_HEX_RE = /^0x[0-9a-f]{64}$/;
const TIMESTAMP_RE = /^\d+$/;

/**
 * Headers as they may arrive from any transport: a `Headers` object (fetch /
 * viem), or a plain `Record` (ethers `FetchResponse.headers` is a lowercased
 * `Record`; some transports preserve mixed case). Access is case-insensitive so
 * neither adapter can smuggle a header shape that bypasses validation.
 */
export type ResponseHeaders = Headers | Record<string, string>;

export interface VerifyResponseOptions {
  /**
   * Opaque chain id string bound into the canonical pre-image as
   * `sha256(utf8(chainId))` at bytes [0..32]. MUST match the chain id string
   * the sidecar was configured with — mismatch produces a `BadSignature` even
   * on intact responses. Validated at entry (`validateChainId`); an invalid id
   * throws `InvalidChainId` before any header parsing.
   */
  chainId: string;
  /**
   * Allowed skew between the client clock and the sidecar's signed timestamp.
   * Default 60_000 ms. `0` rejects anything but an exact-millisecond match —
   * useful for tests, not for production.
   */
  replayWindowMs?: number;
  /**
   * Injected wall clock (unix ms) for the replay-window check. Defaults to
   * `BigInt(Date.now())`. Injectable for deterministic tests.
   */
  nowMs?: bigint;
  /**
   * INTERNAL opt-in narration sink, threaded in by `TrustedVerifier.verify`
   * (the verifier's safe-wrapped `this.logger`). NOT a public adapter option:
   * it exists so the preimage/signature/timestamp steps can narrate from within
   * `verifyResponse`. Omitted (the default) keeps this path silent.
   */
  logger?: Logger;
}

export interface VerifiedPair {
  /** The verified (content-decoded) response body bytes, exactly as signed. */
  responseBytes: Uint8Array;
  /**
   * The serving node's id from the `vRPC-NodeId` response header, used to fetch
   * that node's attestation via the gateway. Absent when the proxy is older and does
   * not emit the header.
   */
  nodeId?: string;
  verification: {
    /** `0x` + 128 lowercase hex chars. */
    signatureHex: string;
    /** `0x` + 64 lowercase hex chars. */
    pubkeyHex: string;
    timestampMs: bigint;
    /** sha256 of the 104-byte canonical pre-image, for diagnostics. */
    preImageSha256: Uint8Array;
  };
}

/**
 * Case-insensitive header lookup over `Headers | Record<string, string>`.
 * Returns `null` when absent (matching `Headers.get` semantics).
 */
function getHeader(headers: ResponseHeaders, name: string): string | null {
  if (headers instanceof Headers) {
    return headers.get(name);
  }
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers as Record<string, string>)) {
    if (key.toLowerCase() === lower) {
      return value;
    }
  }
  return null;
}

/**
 * True if the response carries the `vRPC-Signature` header — i.e. it is a signed
 * vRPC response, not a bare transport error. Lets adapters distinguish a signed
 * `{error}` body from an unsigned gateway failure WITHOUT hardcoding the wire
 * header name (the contract stays owned by core).
 */
export function isSignedVrpcResponse(headers: ResponseHeaders): boolean {
  return getHeader(headers, SIGNATURE_HEADER) !== null;
}

/**
 * Convert `0x...` hex (already shape-validated) to a `Uint8Array`.
 * Caller is responsible for ensuring the input matches `0x[0-9a-f]{2n}`.
 */
function hexToBytes(hex0x: string): Uint8Array {
  const stripped = hex0x.slice(2);
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function absBigint(n: bigint): bigint {
  return n < 0n ? -n : n;
}

/**
 * Verify a (requestBytes, rawResponseBytes, responseHeaders) triple against the
 * canonical pre-image signed by the sidecar. Transport-agnostic: the caller
 * supplies already content-decoded bytes and the raw response headers.
 *
 * Throws a typed `VerificationError` subclass on any failure:
 *   - `InvalidChainId`  — the configured chain id failed validation
 *   - `MissingHeader`   — a required `vRPC-*` header is absent
 *   - `MalformedHeader` — a header is present but fails shape validation
 *   - `BadSignature`    — Ed25519 verify failed (tampered bytes or wrong chainId)
 *   - `StaleTimestamp`  — signed timestamp fell outside the replay window
 */
export async function verifyResponse(
  requestBytes: Uint8Array,
  rawResponseBytes: Uint8Array,
  responseHeaders: ResponseHeaders,
  opts: VerifyResponseOptions,
): Promise<VerifiedPair> {
  // Validate the configured chain id ONCE at entry — fail-fast with
  // InvalidChainId before any header parsing. The trimmed return value is what
  // gets bound into the pre-image, mirroring the sidecar's boot validation.
  const chainId = validateChainId(opts.chainId);

  // 4. Header parse — missing -> MissingHeader.
  const sigHex = getHeader(responseHeaders, SIGNATURE_HEADER);
  if (sigHex === null) {
    throw new MissingHeader(SIGNATURE_HEADER);
  }
  const pubkeyHex = getHeader(responseHeaders, PUBKEY_HEADER);
  if (pubkeyHex === null) {
    throw new MissingHeader(PUBKEY_HEADER);
  }
  const tsRaw = getHeader(responseHeaders, TIMESTAMP_HEADER);
  if (tsRaw === null) {
    throw new MissingHeader(TIMESTAMP_HEADER);
  }
  // Optional — older proxies omit it, in which case nodeId stays absent.
  const nodeId = getHeader(responseHeaders, NODE_ID_HEADER);

  // 5. Header validate — bad shape -> MalformedHeader.
  if (!SIGNATURE_HEX_RE.test(sigHex)) {
    throw new MalformedHeader(SIGNATURE_HEADER, sigHex, "expected 0x + 128 lowercase hex chars");
  }
  if (!PUBKEY_HEX_RE.test(pubkeyHex)) {
    throw new MalformedHeader(PUBKEY_HEADER, pubkeyHex, "expected 0x + 64 lowercase hex chars");
  }
  if (!TIMESTAMP_RE.test(tsRaw)) {
    throw new MalformedHeader(TIMESTAMP_HEADER, tsRaw, "expected decimal u64 ms");
  }
  const timestampMs = BigInt(tsRaw);

  // 6. Pre-image reconstruct.
  const preImage = buildPreImage(chainId, requestBytes, rawResponseBytes, timestampMs);

  if (opts.logger) {
    opts.logger.debug("preimage.computed", {
      preImageSha256: bytesToHex(sha256(preImage)),
    });
  }

  // 7. Hex -> bytes (cheap, no dep).
  const sigBytes = hexToBytes(sigHex);
  const pubkeyBytes = hexToBytes(pubkeyHex);

  // 8. Ed25519 verify — bad signature -> BadSignature.
  const ok = await verifyAsync(sigBytes, preImage, pubkeyBytes);
  if (opts.logger) {
    opts.logger.debug("signature.checked", { ok });
  }
  if (!ok) {
    throw new BadSignature({
      signatureHex: sigHex,
      pubkeyHex,
      preImageSha256: sha256(preImage),
    });
  }

  // 9. Replay-window check — outside the window -> StaleTimestamp.
  //    Done AFTER signature verify: a tampered timestamp would have failed
  //    step 8. We only reach here on a valid signature.
  const replayWindowMs = opts.replayWindowMs ?? DEFAULT_REPLAY_WINDOW_MS;
  const nowMs = opts.nowMs ?? BigInt(Date.now());
  const skewMs = timestampMs - nowMs;
  const isWithinWindow = absBigint(skewMs) <= BigInt(replayWindowMs);

  if (opts.logger) {
    opts.logger.debug("timestamp.checked", {
      timestampMs: timestampMs.toString(),
      nowMs: nowMs.toString(),
      skewMs: skewMs.toString(),
      replayWindowMs,
      withinWindow: isWithinWindow,
    });
  }

  if (!isWithinWindow) {
    throw new StaleTimestamp({
      observedMs: timestampMs,
      nowMs,
      skewMs,
      allowedWindowMs: replayWindowMs,
    });
  }

  // Return the verified pair. Omit nodeId entirely when absent
  // (exactOptionalPropertyTypes).
  return {
    responseBytes: rawResponseBytes,
    ...(nodeId === null ? {} : { nodeId }),
    verification: {
      signatureHex: sigHex,
      pubkeyHex,
      timestampMs,
      preImageSha256: sha256(preImage),
    },
  };
}
