// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The upstream leg of both proxy modes: one undici request, every header value kept, the body buffered under a cap.

import { type Dispatcher, request } from "undici";

import { UpstreamBodyTooLargeError } from "./errors";
import type { RawHeaders } from "./headers";

/** Buffer a stream into one Buffer; a byte past `maxBytes` throws `overflow()`. */
export async function bufferStream(
  stream: AsyncIterable<Buffer | Uint8Array>,
  maxBytes: number,
  overflow: () => Error,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > maxBytes) {
      throw overflow();
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

export interface UpstreamResponse {
  status: number;
  /** Global `Headers`: core logs headers through `instanceof Headers`. */
  headers: Headers;
  /** undici's own object, for the verbatim relay. */
  rawHeaders: RawHeaders;
  body: Buffer;
}

/** Errors are thrown as undici raised them, so their `code` reaches the caller's error map. */
export async function sendUpstream(
  dispatcher: Dispatcher,
  maxBytes: number,
  req: {
    url: string;
    method: string;
    headers: Record<string, string | string[]>;
    body?: Uint8Array | undefined;
    signal?: AbortSignal | undefined;
  },
): Promise<UpstreamResponse> {
  const res = await request(req.url, {
    method: req.method as Dispatcher.HttpMethod,
    headers: req.headers,
    body: req.body !== undefined && req.body.byteLength > 0 ? req.body : null,
    dispatcher,
    ...(req.signal === undefined ? {} : { signal: req.signal }),
  });
  const headers = new Headers();
  try {
    for (const [name, value] of Object.entries(res.headers)) {
      if (value === undefined) continue;
      for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
    }
  } catch (err) {
    res.body.destroy();
    throw err;
  }
  const body = await bufferStream(res.body, maxBytes, () => new UpstreamBodyTooLargeError());
  return { status: res.statusCode, headers, rawHeaders: res.headers, body };
}
