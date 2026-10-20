// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Outer HTTP seam of the Ankr Confidential RPC client.

import type { ResponseHeaders } from "./verify";

// 192 MiB: above the 160 MiB gateway response cap, so it never fires first on a relayed answer.
export const MAX_RESPONSE_BYTES = 201_326_592;

export interface OuterRequest {
  method: "GET" | "POST";
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
  signal?: AbortSignal;
}

export interface OuterResponse {
  status: number;
  headers: ResponseHeaders;
  body: Uint8Array;
}

/**
 * Sends one outer request: the body byte for byte, no redirect following, no retry, honouring the signal.
 * Resolves with the content-decoded response body.
 */
export type ConfidentialTransport = (request: OuterRequest) => Promise<OuterResponse>;

/** Thrown by `readCappedBody` when an answer passes the response size cap; never reaches the caller. */
export class ResponseTooLarge extends Error {
  constructor() {
    super("Response exceeds the size cap");
    this.name = "ResponseTooLarge";
  }
}

/** Reads a fetch `Response` body for a `ConfidentialTransport`, stopping at the response size cap. */
export async function readCappedBody(response: Response): Promise<Uint8Array> {
  const body = response.body as ReadableStream<Uint8Array> | null | undefined;
  // node-fetch hands over a Node Readable, whatwg-fetch and React Native no body at all.
  const stream = typeof body?.getReader === "function" ? body : undefined;
  // With an encoding, content-length is the encoded size; the runtime hands over decoded bytes.
  const encoding = (response.headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  const declared = Number(response.headers.get("content-length"));
  if ((encoding === "" || encoding === "identity") && declared > MAX_RESPONSE_BYTES) {
    await stream?.cancel();
    throw new ResponseTooLarge();
  }
  if (body === null) return new Uint8Array(0);
  if (stream === undefined) {
    const buffered = new Uint8Array(await response.arrayBuffer());
    if (buffered.byteLength > MAX_RESPONSE_BYTES) throw new ResponseTooLarge();
    return buffered;
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new ResponseTooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function errorCode(err: unknown): string | undefined {
  const code =
    typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]*$/.test(code) ? code : undefined;
}

// A fetch error message may quote the keyed URL; keep a fixed message and the error code only.
function sanitised(err: unknown): Error {
  const out = new Error("The request failed.");
  const code = errorCode(err) ?? errorCode((err as { cause?: unknown } | null)?.cause);
  if (code !== undefined) Object.assign(out, { code });
  return out;
}

/** A `ConfidentialTransport` over `fetchFn` (the global fetch at call time when omitted). */
export function fetchTransport(
  fetchFn?: (url: string, init: RequestInit) => Promise<Response>,
): ConfidentialTransport {
  return async (request) => {
    const send = fetchFn ?? globalThis.fetch;
    try {
      const response = await send(request.url, {
        method: request.method,
        headers: request.headers,
        redirect: "manual",
        ...(request.body === undefined ? {} : { body: request.body }),
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
      if (response.type === "opaqueredirect") {
        return { status: 0, headers: new Headers(), body: new Uint8Array(0) };
      }
      return {
        status: response.status,
        headers: response.headers,
        body: await readCappedBody(response),
      };
    } catch (err) {
      if (request.signal?.aborted) throw request.signal.reason;
      if (err instanceof ResponseTooLarge) throw err;
      throw sanitised(err);
    }
  };
}

export const defaultTransport: ConfidentialTransport = fetchTransport();
