// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Content-Encoding decode layer for the throwaway verify copy. The sidecar
// signs the content-DECODED (plaintext) body, so the proxy must reproduce the
// plaintext to verify — the relayed bytes stay the originals. Decoding an
// upstream body the proxy cannot decode means the signature cannot be checked,
// so unknown codings fail closed.

import { promisify } from "node:util";
import * as zlib from "node:zlib";

import { DecodeFailedError } from "./errors";

type AsyncCodec = (buf: Buffer, opts: { maxOutputLength: number }) => Promise<Buffer>;

const gunzip = promisify(zlib.gunzip) as AsyncCodec;

// A Map, not an object literal: a coding named like an Object.prototype key must not resolve.
const CODECS = new Map<string, AsyncCodec>([
  ["gzip", gunzip],
  ["x-gzip", gunzip],
  // zlib-wrapped deflate per RFC. Raw-deflate servers exist in the wild;
  // their bodies fail to decode and fail closed — no inflateRaw fallback.
  ["deflate", promisify(zlib.inflate) as AsyncCodec],
  ["br", promisify(zlib.brotliDecompress) as AsyncCodec],
  ["zstd", promisify(zlib.zstdDecompress) as AsyncCodec],
]);

/**
 * Decode `body` per its Content-Encoding list into the plaintext copy used
 * for verification. Encodings are listed in application order (RFC 9110
 * §8.4), so decoding runs in REVERSE list order. Every codec call carries
 * `maxOutputLength` — the zip-bomb cap: a decode expanding past the limit
 * fails like any other decode error.
 *
 * Absent or identity-only Content-Encoding returns the input unchanged.
 * Unknown coding and decode failure (including the output cap)
 * → DecodeFailedError — fail closed upstream.
 */
export async function decodeBody(
  body: Buffer,
  contentEncoding: string | undefined,
  maxOutputLength: number,
): Promise<Buffer> {
  const codings = (contentEncoding ?? "")
    .split(",")
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c !== "" && c !== "identity");

  let out = body;
  for (const coding of codings.reverse()) {
    const codec = CODECS.get(coding);
    if (codec === undefined) {
      throw new DecodeFailedError(`Unsupported upstream content-encoding: "${coding}"`);
    }
    try {
      out = await codec(out, { maxOutputLength });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new DecodeFailedError(
        `Failed to decode ${JSON.stringify(coding)} upstream body: ${detail}`,
      );
    }
  }
  return out;
}
