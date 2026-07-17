// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Codec-layer tests for the throwaway verify copy: per-codec round-trips,
// identity passthrough, reverse-order multi-coding, unknown tokens, decode
// failures, and the maxOutputLength zip-bomb cap. Sync zlib compressors are
// fine here — test-only.

import * as zlib from "node:zlib";

import { describe, expect, test } from "vitest";

import { decodeBody } from "../src/decode";
import { DecodeFailedError } from "../src/errors";

const CAP = 1024 * 1024;
const ORIGINAL = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0xdecode-me"}');

describe("decodeBody", () => {
  test("gzipRoundTrip", async () => {
    const decoded = await decodeBody(zlib.gzipSync(ORIGINAL), "gzip", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });

  test("xGzipAliasRoundTrip", async () => {
    const decoded = await decodeBody(zlib.gzipSync(ORIGINAL), "x-gzip", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });

  test("deflateRoundTrip", async () => {
    const decoded = await decodeBody(zlib.deflateSync(ORIGINAL), "deflate", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });

  test("brotliRoundTrip", async () => {
    const decoded = await decodeBody(zlib.brotliCompressSync(ORIGINAL), "br", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });

  test("identityReturnsInputUnchanged", async () => {
    const decoded = await decodeBody(ORIGINAL, "identity", CAP);
    expect(decoded).toBe(ORIGINAL);
  });

  test("absentHeaderReturnsInputUnchanged", async () => {
    const decoded = await decodeBody(ORIGINAL, undefined, CAP);
    expect(decoded).toBe(ORIGINAL);
  });

  test("multiCodingDecodesInReverseListOrder", async () => {
    // Header lists application order: gzip first, then br — so the wire body
    // is br(gzip(original)) and decode must run br, then gzip.
    const wire = zlib.brotliCompressSync(zlib.gzipSync(ORIGINAL));
    const decoded = await decodeBody(wire, "gzip, br", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });

  test("unknownTokenFailsClosedWithDecodeFailed", async () => {
    await expect(decodeBody(ORIGINAL, "snappy", CAP)).rejects.toThrow(DecodeFailedError);
    await expect(decodeBody(ORIGINAL, "snappy", CAP)).rejects.toMatchObject({
      kind: "DecodeFailed",
    });
  });

  test("corruptedGzipThrowsDecodeFailed", async () => {
    const corrupted = zlib.gzipSync(ORIGINAL);
    corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
    await expect(decodeBody(corrupted, "gzip", CAP)).rejects.toThrow(DecodeFailedError);
  });

  test("outputExceedingMaxOutputLengthThrowsDecodeFailed", async () => {
    const wire = zlib.gzipSync(Buffer.alloc(4096));
    await expect(decodeBody(wire, "gzip", 1024)).rejects.toThrow(DecodeFailedError);
  });
});

// Gated by the SAME runtime detect the production decode layer uses — CI's
// Node 22.14 lacks zstd (landed in Node 23.8).
describe.skipIf(typeof zlib.zstdDecompressSync !== "function")("decodeBody (zstd)", () => {
  test("zstdRoundTrip", async () => {
    const decoded = await decodeBody(zlib.zstdCompressSync(ORIGINAL), "zstd", CAP);
    expect(Buffer.compare(decoded, ORIGINAL)).toBe(0);
  });
});
