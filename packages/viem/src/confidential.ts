// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode for vrpcHttp: fetch transport, lazy client, signal linking, answer mapping.

import type {
  ConfidentialClient,
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialResponse,
  ConfidentialTransport,
} from "@w3tech.io/vrpc-core/confidential";
import { RpcRequestError } from "viem";

import type { VrpcHttpOptions } from "./options";

/** Sends each outer request once through `fetchFn` (or the global fetch at call time), never following a redirect. */
export function fetchTransport(fetchFn: VrpcHttpOptions["fetchFn"]): ConfidentialTransport {
  return async (request) => {
    const send = fetchFn ?? globalThis.fetch;
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
      body: new Uint8Array(await response.arrayBuffer()),
    };
  };
}

/** One lazily loaded client per vrpcHttp(); a failed load or construction is retried on next use. */
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

const linked = new WeakMap<AbortSignal, Set<AbortController>>();
const listeners = new WeakMap<AbortSignal, () => void>();

function register(caller: AbortSignal): Set<AbortController> {
  const existing = linked.get(caller);
  if (existing !== undefined) return existing;
  const fresh = new Set<AbortController>();
  const onAbort = () => {
    linked.delete(caller);
    listeners.delete(caller);
    for (const controller of fresh) controller.abort(caller.reason);
  };
  linked.set(caller, fresh);
  listeners.set(caller, onAbort);
  caller.addEventListener("abort", onAbort, { once: true });
  return fresh;
}

/** One signal per call from the caller's signal and the timeout, with one listener per caller signal. */
export function linkSignal(
  caller: AbortSignal | undefined,
  timeoutMs: number,
): { signal: AbortSignal | undefined; done(): void } {
  if (caller === undefined) {
    return { signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined, done() {} };
  }
  const controller = new AbortController();
  if (caller.aborted) {
    controller.abort(caller.reason);
    return { signal: controller.signal, done() {} };
  }
  const entry = register(caller);
  entry.add(controller);
  const timer =
    timeoutMs > 0
      ? setTimeout(
          () => controller.abort(new DOMException("The operation timed out.", "TimeoutError")),
          timeoutMs,
        )
      : undefined;
  return {
    signal: controller.signal,
    done() {
      clearTimeout(timer);
      entry.delete(controller);
      if (entry.size > 0 || linked.get(caller) !== entry) return;
      linked.delete(caller);
      const onAbort = listeners.get(caller);
      listeners.delete(caller);
      if (onAbort !== undefined) caller.removeEventListener("abort", onAbort);
    },
  };
}

const utf8 = new TextDecoder();

/** The inner answer as viem's http transport would surface it, without params, body text or URL path. */
// biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
export function mapInnerResponse(response: ConfidentialResponse, url: string): any {
  // biome-ignore lint/suspicious/noExplicitAny: parsed JSON-RPC answer.
  const parsed: any = JSON.parse(utf8.decode(response.body));
  if (parsed != null && "error" in parsed) {
    throw new RpcRequestError({ body: {}, error: parsed.error, url });
  }
  return parsed.result;
}
