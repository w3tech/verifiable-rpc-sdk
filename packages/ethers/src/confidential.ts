// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode for VrpcProvider: FetchRequest transport, lazy client, answer mapping.

import { fetchTransport, type LazyConfidentialClient } from "@w3tech.io/vrpc-core";
import type { ConfidentialTransport, OuterRequest } from "@w3tech.io/vrpc-core/confidential";
import {
  assert,
  type FetchGetUrlFunc,
  FetchRequest,
  FetchResponse,
  type JsonRpcPayload,
  type JsonRpcResult,
  makeError,
  toUtf8Bytes,
} from "ethers";

// Same checks as ethers' toUtf8String, which keeps a BOM.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// A FetchRequest.registerGetUrl() made before this module loads is taken for the stock fetcher.
const stockGetUrl = new FetchRequest("http://localhost").getUrlFunc;

// Replaces the ethers fetchers, which buffer the whole body (and gunzip it in Node) before returning.
const cappedGetUrl =
  (send: ConfidentialTransport, maxBytes: number | undefined): FetchGetUrlFunc =>
  async (req, signal) => {
    assert(signal == null || !signal.cancelled, "request cancelled before sending", "CANCELLED");
    const protocol = req.url.split(":")[0]?.toLowerCase();
    assert(
      protocol === "http" || protocol === "https",
      `unsupported protocol ${protocol}`,
      "UNSUPPORTED_OPERATION",
      { operation: "request" },
    );
    assert(
      protocol === "https" || !req.credentials || req.allowInsecureAuthentication,
      "insecure authorized connections unsupported",
      "UNSUPPORTED_OPERATION",
      { operation: "request" },
    );
    let reason: Error | undefined;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      reason = makeError("request timeout", "TIMEOUT");
      controller.abort();
    }, req.timeout);
    signal?.addListener(() => {
      reason = makeError("request cancelled", "CANCELLED");
      controller.abort();
    });
    try {
      const response = await send({
        method: req.method as OuterRequest["method"],
        url: req.url,
        headers: Object.fromEntries(req),
        signal: controller.signal,
        ...(req.body === null ? {} : { body: req.body }),
        ...(maxBytes === undefined ? {} : { maxBytes }),
      });
      return {
        statusCode: response.status,
        statusMessage: "",
        headers: Object.fromEntries(new Headers(response.headers)),
        body: response.body,
      };
    } catch (err) {
      throw reason ?? err;
    } finally {
      clearTimeout(timer);
    }
  };

// `send()` clones the request per attempt and the clone turns gzip back on, so it is set here.
function noFollowIdentity(base: FetchGetUrlFunc): FetchGetUrlFunc {
  return async (req, signal) => {
    req.allowGzip = false;
    req.setHeader("accept-encoding", "identity");
    const res = await base(req, signal);
    if (res.statusCode < 300 || res.statusCode > 399) return res;
    const headers = Object.fromEntries(
      Object.entries(res.headers).filter(([name]) => name.toLowerCase() !== "location"),
    );
    return { ...res, headers };
  };
}

/**
 * Sends each outer request once through a clone of the provider's `FetchRequest`; with the stock
 * `getUrlFunc` it goes out through `fetchFn`, the global fetch when omitted.
 */
export function fetchRequestTransport(
  connection: () => FetchRequest,
  fetchFn: typeof fetch | undefined,
): ConfidentialTransport {
  const send = fetchTransport(fetchFn);
  return async (outer) => {
    const req = connection();
    req.url = outer.url;
    req.method = outer.method;
    req.body = outer.body ?? null;
    for (const [name, value] of Object.entries(outer.headers)) req.setHeader(name, value);
    req.retryFunc = async () => false;
    req.processFunc = null;
    const own = req.getUrlFunc;
    const base = own === stockGetUrl ? cappedGetUrl(send, outer.maxBytes) : own;
    req.getUrlFunc = noFollowIdentity(base);

    const signal = outer.signal;
    const pending = req.send();
    const cancel = () => req.cancel();
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      const res = await pending;
      return { status: res.statusCode, headers: res.headers, body: res.body ?? new Uint8Array(0) };
    } finally {
      signal?.removeEventListener("abort", cancel);
    }
  };
}

export async function sendConfidential(
  client: LazyConfidentialClient,
  payload: JsonRpcPayload | Array<JsonRpcPayload>,
): Promise<Array<JsonRpcResult>> {
  const res = await client.request({
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: toUtf8Bytes(JSON.stringify(payload)),
  });
  // Only on the error paths: FetchResponse copies the body and bodyJson decodes it one byte at a time.
  const inner = () =>
    new FetchResponse(
      res.status,
      "",
      res.contentType === undefined ? {} : { "content-type": res.contentType },
      res.body,
    );
  if (res.status < 200 || res.status > 299) {
    // Built by hand: the ethers ok-assertion copies the decrypted body into the message.
    const status = `${res.status} `;
    throw makeError(`server response ${status}`, "SERVER_ERROR", {
      request: "unknown request",
      response: inner(),
      info: { requestUrl: null, responseStatus: status },
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(strictUtf8.decode(res.body));
  } catch {
    // Throws ethers' own error for a body that is not UTF-8 JSON.
    parsed = inner().bodyJson;
  }
  const results = (Array.isArray(parsed) ? parsed : [parsed]) as unknown[];
  const payloads = Array.isArray(payload) ? payload : [payload];
  const answered = (id: number) => results.some((r) => (r as { id?: unknown }).id === id);
  // ethers' own error for a missing id quotes every result and request in its message.
  if (
    !results.every((r) => r !== null && typeof r === "object") ||
    !payloads.every((p) => answered(p.id))
  ) {
    throw makeError("missing response for request", "BAD_DATA");
  }
  return results as Array<JsonRpcResult>;
}
