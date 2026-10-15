// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Outer HTTP seam of the Ankr Confidential RPC client.

import type { ResponseHeaders } from "./verify";

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

export const defaultTransport: ConfidentialTransport = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    redirect: "manual",
    ...(request.body === undefined ? {} : { body: request.body }),
    ...(request.signal === undefined ? {} : { signal: request.signal }),
  });
  return {
    status: response.status,
    headers: response.headers,
    body: new Uint8Array(await response.arrayBuffer()),
  };
};
