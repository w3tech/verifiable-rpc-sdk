// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode for VrpcProvider: FetchRequest transport, lazy client, answer mapping.

import type {
  ConfidentialClient,
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialTransport,
} from "@w3tech.io/vrpc-core/confidential";
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

// The core default transport's cap: 192 MiB, above the 160 MiB gateway response cap.
const MAX_RESPONSE_BYTES = 201_326_592;

// With an encoding, content-length is the encoded size; the runtime hands over decoded bytes.
async function readCapped(response: Response): Promise<Uint8Array> {
  const encoding = (response.headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  const declared = Number(response.headers.get("content-length"));
  if ((encoding === "" || encoding === "identity") && declared > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new Error("Response exceeds the size cap");
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Response exceeds the size cap");
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

// Replaces the ethers fetchers, which buffer the whole body (and gunzip it in Node) before returning.
const cappedGetUrl: FetchGetUrlFunc = async (req, signal) => {
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
    const response = await fetch(req.url, {
      method: req.method,
      headers: new Headers(Array.from(req)),
      redirect: "manual",
      signal: controller.signal,
      ...(req.body === null ? {} : { body: req.body }),
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    const body = await readCapped(response);
    return { statusCode: response.status, statusMessage: response.statusText, headers, body };
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

// ethers and Node attach the request, the keyed URL and partial bodies; keep the message and code only.
function sanitised(err: unknown): Error {
  const source = typeof err === "object" && err !== null ? (err as Record<string, unknown>) : {};
  const message =
    typeof source.shortMessage === "string"
      ? source.shortMessage
      : typeof source.message === "string"
        ? source.message
        : "transport error";
  const out = new Error(message);
  const cause = source.cause as { code?: unknown } | null | undefined;
  const code = typeof source.code === "string" ? source.code : cause?.code;
  if (typeof code === "string") Object.assign(out, { code });
  return out;
}

/** Sends each outer request once through a clone of the provider's `FetchRequest`. */
export function fetchRequestTransport(connection: () => FetchRequest): ConfidentialTransport {
  return async (outer) => {
    const req = connection();
    req.url = outer.url;
    req.method = outer.method;
    req.body = outer.body ?? null;
    for (const [name, value] of Object.entries(outer.headers)) req.setHeader(name, value);
    req.retryFunc = async () => false;
    req.processFunc = null;
    const own = req.getUrlFunc;
    const base = own === new FetchRequest("http://localhost").getUrlFunc ? cappedGetUrl : own;
    req.getUrlFunc = noFollowIdentity(base);

    const signal = outer.signal;
    if (signal?.aborted) throw signal.reason;
    const pending = req.send();
    const cancel = () => req.cancel();
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      const res = await pending;
      return { status: res.statusCode, headers: res.headers, body: res.body ?? new Uint8Array(0) };
    } catch (err) {
      if (signal?.aborted) throw signal.reason;
      throw sanitised(err);
    } finally {
      signal?.removeEventListener("abort", cancel);
    }
  };
}

/** The core client's check, run in the constructor so a bad value throws before any call. */
export function requirePositiveMs(name: string, value: number | undefined): void {
  if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) {
    throw new RangeError(`${name} must be a positive integer number of milliseconds`);
  }
}

/** One lazily loaded client per provider; a failed load or construction is retried on next use. */
export class ConfidentialHolder {
  readonly #options: ConfidentialClientOptions;
  #client: ConfidentialClient | undefined;
  #pending: Promise<ConfidentialClient> | undefined;

  constructor(options: ConfidentialClientOptions) {
    this.#options = options;
  }

  client(): Promise<ConfidentialClient> {
    if (this.#client !== undefined) return Promise.resolve(this.#client);
    this.#pending ??= (async () => {
      try {
        const { ConfidentialClient } = await import("@w3tech.io/vrpc-core/confidential");
        this.#client = new ConfidentialClient(this.#options);
        return this.#client;
      } catch (err) {
        this.#pending = undefined;
        throw err;
      }
    })();
    return this.#pending;
  }

  async ready(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo> {
    return (await this.client()).ready(options);
  }

  info(): ConfidentialInfo | undefined {
    return this.#client?.getConfidentialInfo();
  }
}

export async function sendConfidential(
  holder: ConfidentialHolder,
  payload: JsonRpcPayload | Array<JsonRpcPayload>,
): Promise<Array<JsonRpcResult>> {
  const client = await holder.client();
  const res = await client.request({
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: toUtf8Bytes(JSON.stringify(payload)),
  });
  const inner = new FetchResponse(
    res.status,
    "",
    res.contentType === undefined ? {} : { "content-type": res.contentType },
    res.body,
  );
  if (!inner.ok()) {
    // Built by hand: the ethers ok-assertion copies the decrypted body into the message.
    const status = `${inner.statusCode} `;
    throw makeError(`server response ${status}`, "SERVER_ERROR", {
      request: "unknown request",
      response: inner,
      info: { requestUrl: null, responseStatus: status },
    });
  }
  const parsed: unknown = inner.bodyJson;
  const results = (Array.isArray(parsed) ? parsed : [parsed]) as unknown[];
  const payloads = Array.isArray(payload) ? payload : [payload];
  const answered = (id: number) =>
    results.some((r) => r !== null && typeof r === "object" && (r as { id?: unknown }).id === id);
  // ethers' own error for a missing id quotes every result and request in its message.
  if (
    !results.every((r) => r !== null && typeof r === "object") ||
    !payloads.every((p) => answered(p.id))
  ) {
    throw makeError("missing response for request", "BAD_DATA");
  }
  return results as Array<JsonRpcResult>;
}
