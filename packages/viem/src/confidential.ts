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
import { HttpRequestError, RpcRequestError } from "viem";

import type { VrpcHttpOptions } from "./options";

// The core default transport's cap: 192 MiB, above the 160 MiB gateway response cap.
const MAX_RESPONSE_BYTES = 201_326_592;

class ResponseTooLarge extends Error {
  constructor() {
    super("Response exceeds the size cap");
    this.name = "ResponseTooLarge";
  }
}

// With an encoding, content-length is the encoded size; the runtime hands over decoded bytes.
async function readCapped(response: Response): Promise<Uint8Array> {
  const encoding = (response.headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  const declared = Number(response.headers.get("content-length"));
  if ((encoding === "" || encoding === "identity") && declared > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new ResponseTooLarge();
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

// A fetch error message may quote the keyed URL; keep a fixed message and the error code only.
function sanitised(err: unknown): Error {
  const out = new Error("The request failed.");
  const code = errorCode(err) ?? errorCode((err as { cause?: unknown } | null)?.cause);
  if (code !== undefined) Object.assign(out, { code });
  return out;
}

function errorCode(err: unknown): string | undefined {
  const code =
    typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]*$/.test(code) ? code : undefined;
}

/** Sends each outer request once through `fetchFn` (or the global fetch at call time), never following a redirect. */
export function fetchTransport(fetchFn: VrpcHttpOptions["fetchFn"]): ConfidentialTransport {
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
        body: await readCapped(response),
      };
    } catch (err) {
      if (request.signal?.aborted) throw request.signal.reason;
      if (err instanceof ResponseTooLarge) throw err;
      throw sanitised(err);
    }
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
