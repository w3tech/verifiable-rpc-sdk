// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Test node signing key material and response signer.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { CHAIN_ID } from "./fixtures";

export { bytesToHex as toHex } from "@noble/hashes/utils.js";

// Ed25519 seed of the open-mode signer: signResponse and attestationStub default to it.
export const TEST_SEED = new Uint8Array(32).fill(0x42);
export const TEST_PUBKEY_HEX = `0x${bytesToHex(ed25519.getPublicKey(TEST_SEED))}`;

export interface SignOptions {
  seed?: Uint8Array | undefined;
  timestampMs?: bigint | number | undefined;
  pubkeyHex?: string | undefined;
  nodeId?: string | undefined;
}

const utf8 = new TextEncoder();

// vRPC-* headers over the 104-byte pre-image, built here rather than by core.
export function signResponse(
  chainId: string,
  request: Uint8Array,
  response: Uint8Array,
  options: SignOptions = {},
): Record<string, string> {
  const seed = options.seed ?? TEST_SEED;
  const pubkeyHex =
    options.seed === undefined ? TEST_PUBKEY_HEX : `0x${bytesToHex(ed25519.getPublicKey(seed))}`;
  const timestamp = BigInt(options.timestampMs ?? Date.now());
  const timestampBytes = new Uint8Array(8);
  new DataView(timestampBytes.buffer).setBigUint64(0, timestamp, true);
  const preImage = concatBytes(
    sha256(utf8.encode(chainId)),
    sha256(request),
    sha256(response),
    timestampBytes,
  );
  return {
    "vRPC-Signature": `0x${bytesToHex(ed25519.sign(preImage, seed))}`,
    "vRPC-Timestamp": timestamp.toString(),
    "vRPC-Pubkey": options.pubkeyHex ?? pubkeyHex,
    ...(options.nodeId === undefined ? {} : { "vRPC-NodeId": options.nodeId }),
  };
}

// Long past: a response signed at it verifies only under a replay window wider than the default.
export const FIXTURE_TIMESTAMP_MS = 1_700_000_000_000n;
// Replay window wide enough for responses signed at FIXTURE_TIMESTAMP_MS.
export const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;

// JSON content type plus signResponse headers, signed at FIXTURE_TIMESTAMP_MS by default.
export function signedJsonHeaders(
  chainId: string,
  request: Uint8Array,
  response: Uint8Array,
  options: SignOptions = {},
): Record<string, string> {
  return {
    "content-type": "application/json",
    ...signResponse(chainId, request, response, {
      ...options,
      timestampMs: options.timestampMs ?? FIXTURE_TIMESTAMP_MS,
    }),
  };
}

export interface SignedAnswerOptions {
  /** Only `content-type`, without the `vRPC-*` headers. */
  unsigned?: boolean | undefined;
  /** Changes a digit of the body after signing. */
  tamper?: boolean | undefined;
  /** Chain id bound into the signature; default `CHAIN_ID`. */
  signingChainId?: string | undefined;
  status?: number | undefined;
  nodeId?: string | undefined;
}

// `responseBody` as an open-mode node answers `request`, with signedJsonHeaders.
export function signedAnswer(
  request: Uint8Array,
  responseBody: string,
  options: SignedAnswerOptions = {},
): { status: number; headers: Record<string, string>; body: Uint8Array<ArrayBuffer> } {
  const body = utf8.encode(responseBody);
  const headers = options.unsigned
    ? { "content-type": "application/json" }
    : signedJsonHeaders(options.signingChainId ?? CHAIN_ID, request, body, {
        nodeId: options.nodeId,
      });
  return {
    status: options.status ?? 200,
    headers,
    body: options.tamper ? flipFirstDigit(body) : body,
  };
}

// A copy of `bytes` with its first ASCII digit changed, so it stays valid JSON.
export function flipFirstDigit(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes);
  for (const [i, b] of out.entries()) {
    if (b >= 0x30 && b <= 0x39) {
      out[i] = b === 0x39 ? 0x30 : b + 1;
      break;
    }
  }
  return out;
}
