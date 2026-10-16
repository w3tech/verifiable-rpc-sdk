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

/** Thrown by the default transport when an answer passes the response size cap; never reaches the caller. */
export class ResponseTooLarge extends Error {
  constructor() {
    super("Response exceeds the size cap");
    this.name = "ResponseTooLarge";
  }
}

async function readCapped(body: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
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

export const defaultTransport: ConfidentialTransport = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    redirect: "manual",
    ...(request.body === undefined ? {} : { body: request.body }),
    ...(request.signal === undefined ? {} : { signal: request.signal }),
  });
  if (response.type === "opaqueredirect") {
    return { status: 0, headers: new Headers(), body: new Uint8Array(0) };
  }
  // With an encoding, content-length is the encoded size; the runtime hands over decoded bytes.
  const encoding = (response.headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  const declared = Number(response.headers.get("content-length"));
  if ((encoding === "" || encoding === "identity") && declared > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new ResponseTooLarge();
  }
  return {
    status: response.status,
    headers: response.headers,
    body: await readCapped(response.body),
  };
};
