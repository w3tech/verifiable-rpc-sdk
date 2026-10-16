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
  type FetchGetUrlFunc,
  FetchRequest,
  FetchResponse,
  type JsonRpcPayload,
  type JsonRpcResult,
  toUtf8Bytes,
} from "ethers";

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
    const base =
      own === new FetchRequest("http://localhost").getUrlFunc
        ? FetchRequest.createGetUrlFunc({ redirect: "manual" })
        : own;
    req.getUrlFunc = noFollowIdentity(base);

    const signal = outer.signal;
    if (signal?.aborted) throw signal.reason;
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
  const parsed = inner.bodyJson as JsonRpcResult | Array<JsonRpcResult>;
  return Array.isArray(parsed) ? parsed : [parsed];
}
