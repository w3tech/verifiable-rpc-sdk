// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode for vrpcHttp: map an inner answer the way viem's http transport would.

import type { ConfidentialResponse } from "@w3tech.io/vrpc-core";
import { HttpRequestError, RpcRequestError } from "viem";

const utf8 = new TextDecoder();

function parse(body: Uint8Array): unknown {
  if (body.byteLength === 0) return undefined;
  try {
    return JSON.parse(utf8.decode(body));
  } catch {
    return undefined;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRpcError(value: unknown): value is { error: { code: number; message: string } } {
  if (!isObject(value) || !isObject(value.error)) return false;
  return typeof value.error.code === "number" && typeof value.error.message === "string";
}

/** The inner answer as viem's http transport surfaces it; `url` is an origin, and no error carries params or body text. */
// biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
export function mapInnerResponse(response: ConfidentialResponse, url: string): any {
  const { status } = response;
  const parsed = parse(response.body);
  if (status < 200 || status > 299) {
    if (isRpcError(parsed)) throw new RpcRequestError({ body: {}, error: parsed.error, url });
    const contentType = response.contentType;
    throw new HttpRequestError({
      status,
      url,
      headers: new Headers(contentType === undefined ? {} : { "content-type": contentType }),
    });
  }
  if (parsed === undefined) {
    throw new HttpRequestError({ status, url, details: "The response body is not valid JSON." });
  }
  // An `error` member that is not an object would crash the viem error constructor.
  if (!isObject(parsed) || ("error" in parsed && !isObject(parsed.error))) {
    throw new HttpRequestError({
      status,
      url,
      details: "The response body is not a JSON-RPC response.",
    });
  }
  if ("error" in parsed) {
    const error = parsed.error as { code: number; message: string };
    throw new RpcRequestError({ body: {}, error, url });
  }
  return parsed.result;
}
