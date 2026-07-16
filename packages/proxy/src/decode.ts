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
const inflate = promisify(zlib.inflate) as AsyncCodec;
const brotliDecompress = promisify(zlib.brotliDecompress) as AsyncCodec;

/**
 * Runtime zstd feature detect — `zlib.zstdDecompressSync` landed in Node
 * 23.8; older runtimes lack it, in which case a zstd upstream response fails
 * closed as DecodeFailed.
 */
export function zstdAvailable(): boolean {
  return typeof zlib.zstdDecompressSync === "function";
}

function resolveCodec(coding: string): AsyncCodec {
  switch (coding) {
    case "gzip":
    case "x-gzip":
      return gunzip;
    case "deflate":
      // zlib-wrapped deflate per RFC. Raw-deflate servers exist in the wild;
      // their bodies fail to decode and fail closed — no inflateRaw fallback.
      return inflate;
    case "br":
      return brotliDecompress;
    case "zstd":
      if (zstdAvailable()) {
        return promisify(zlib.zstdDecompress) as AsyncCodec;
      }
      throw new DecodeFailedError(`Unsupported upstream content-encoding: "${coding}"`);
    default:
      throw new DecodeFailedError(`Unsupported upstream content-encoding: "${coding}"`);
  }
}

/**
 * Decode `body` per its Content-Encoding list into the plaintext copy used
 * for verification. Encodings are listed in application order (RFC 9110
 * §8.4), so decoding runs in REVERSE list order. Every codec call carries
 * `maxOutputLength` — the zip-bomb cap: a decode expanding past the limit
 * fails like any other decode error.
 *
 * Absent or identity-only Content-Encoding returns the input unchanged.
 * Unknown/unavailable coding and decode failure (including the output cap)
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
    const codec = resolveCodec(coding);
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
