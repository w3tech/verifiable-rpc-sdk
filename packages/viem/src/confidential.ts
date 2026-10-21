// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Map an answer the way viem's http transport would: the inner answer in Ankr Confidential RPC
// mode, and the JSON-RPC rules open mode shares with it.

import type { ConfidentialResponse } from "@w3tech.io/vrpc-core";
import { HttpRequestError, RpcRequestError } from "viem";

const utf8 = new TextDecoder();

function parse(body: Uint8Array): unknown {
  try {
    return JSON.parse(utf8.decode(body));
  } catch {
    return undefined;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isRpcError(value: unknown): value is { error: { code: number; message: string } } {
  if (!isObject(value) || !isObject(value.error)) return false;
  return typeof value.error.code === "number" && typeof value.error.message === "string";
}

/** The `result` of a 2xx JSON-RPC answer; as in viem's http transport, only a truthy `error` fails. */
// biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
export function resultOf(
  json: unknown,
  url: string,
  status?: number,
  body?: Record<string, unknown>,
): any {
  if (!isObject(json) || (json.error && !isObject(json.error))) {
    throw new HttpRequestError({
      url,
      details: "The response body is not a JSON-RPC response.",
      ...(status === undefined ? {} : { status }),
      ...(body === undefined ? {} : { body }),
    });
  }
  if (json.error) {
    const error = json.error as { code: number; message: string };
    throw new RpcRequestError({ body: body ?? {}, error, url });
  }
  return json.result;
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
  return resultOf(parsed, url, status);
}
