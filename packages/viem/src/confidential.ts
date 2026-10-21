// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode for vrpcHttp: fetch transport, lazy client, signal linking, answer mapping.

import type { ConfidentialResponse } from "@w3tech.io/vrpc-core";
import { HttpRequestError, RpcRequestError } from "viem";

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
