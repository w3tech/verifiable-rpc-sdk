// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Test node signing key material and response signer.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";

export { bytesToHex as toHex } from "@noble/hashes/utils.js";

// Ed25519 seed of the test node key.
export const TEST_SEED = new Uint8Array(32).fill(0x42);

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
    "vRPC-Pubkey": options.pubkeyHex ?? `0x${bytesToHex(ed25519.getPublicKey(seed))}`,
    ...(options.nodeId === undefined ? {} : { "vRPC-NodeId": options.nodeId }),
  };
}

// Long past: a response signed at it verifies only under a replay window wider than the default.
export const FIXTURE_TIMESTAMP_MS = 1_700_000_000_000n;

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
