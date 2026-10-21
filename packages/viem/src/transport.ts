// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpcHttp — verifiable drop-in for viem's `http(url)` transport. Open mode posts raw bytes and
// maps the answers the core open session verified; Ankr Confidential RPC mode seals every call.

import {
  checkOptions,
  createOpenSession,
  InvalidOption,
  LazyConfidentialClient,
} from "@w3tech.io/vrpc-core";
import type { ConfidentialInfo } from "@w3tech.io/vrpc-core/confidential";
import { createTransport, HttpRequestError, RpcRequestError, type Transport } from "viem";

import { linkSignal, mapInnerResponse } from "./confidential";
import type { VrpcHttpOptions } from "./options";

/**
 * Ankr Confidential RPC mode: every JSON-RPC call is sealed to an attested node. CCIP-Read
 * requests go to the gateway a contract names in plaintext; create the client with
 * `ccipRead: false` to keep every request encrypted. The client must declare `chain`; one
 * transport binds one chain.
 * `client.transport.ready()` attests up front and `getConfidentialInfo()` reports the pinned node;
 * both are typed only when `confidential` is the literal `true`.
 */
export function vrpcHttp(
  url: string,
  opts: VrpcHttpOptions & { confidential: true },
): Transport<"vrpc-http", ConfidentialValue>;
/**
 * A viem `Transport` that Ed25519-verifies every response over its raw bytes
 * before it reaches the client. Drop-in:
 * `createPublicClient({ transport: vrpcHttp(url) })`. The URL is the explicit
 * vRPC route (e.g. `…/arbitrum_vrpc`), used verbatim for RPC; the transport
 * derives only the `/attestation` sub-route from it.
 *
 * The chain id bound into the pre-image comes from the viem client's `chain`
 * (`chain.id`). With no chain set it is derived from a self-consistently verified
 * `eth_chainId` response on the first request (fail-fast, no unverified fallback);
 * declaring `chain` on the client pins YOUR chain and skips the bootstrap.
 */
export function vrpcHttp(url: string, opts?: VrpcHttpOptions): Transport<"vrpc-http">;
export function vrpcHttp(
  url: string,
  opts: VrpcHttpOptions = {},
): Transport<"vrpc-http"> | Transport<"vrpc-http", ConfidentialValue> {
  const { urls, confidential } = checkOptions({
    url,
    headers: opts.headers,
    replayWindowMs: opts.replayWindowMs,
    pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
    confidential: opts.confidential,
  });
  if (confidential) return confidentialHttp(urls.rpcUrl, opts);
  const fetchFn = opts.fetchFn ?? fetch;
  const { rpcUrl, attestationUrl } = urls;
  // A signed JSON-RPC error is the PRESENCE of the `error` key; same class viem's http transport throws.
  const rpcError = (body: Record<string, unknown>, json: unknown) =>
    typeof json === "object" && json !== null && "error" in json
      ? new RpcRequestError({
          body,
          error: json.error as { code: number; message: string },
          url: rpcUrl,
        })
      : undefined;
  const session = createOpenSession<{ status: number; headers: Headers; body: Uint8Array }>({
    attestationUrl,
    headers: opts.headers,
    fetch: opts.fetchFn as typeof fetch | undefined,
    replayWindowMs: opts.replayWindowMs,
    pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
    hardwareVerifier: opts.hardwareVerifier,
    logger: opts.logger,
    httpError: (response, payload, json) =>
      rpcError(payload as Record<string, unknown>, json) ??
      new HttpRequestError({
        body: payload as Record<string, unknown>,
        status: response.status,
        headers: response.headers,
        url: rpcUrl,
      }),
  });

  return ({ chain, timeout: injectedTimeout }) => {
    // viem chain ids are plain numbers; decimal stringification matches the sidecar config.
    const clientChainId = chain?.id == null ? undefined : String(chain.id);
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    const post = async (body: Uint8Array) => {
      const res = await fetchFn(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...opts.headers },
        body,
        ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
      });
      return {
        status: res.status,
        headers: res.headers,
        body: new Uint8Array(await res.arrayBuffer()),
      };
    };

    return createTransport(
      {
        key: "vrpc-http",
        name: "vRPC HTTP JSON-RPC",
        type: "vrpc-http",
        // Hardcoded; viem's injected default is ignored: buildRequest would RETRY a
        // codeless VerificationError 3× and re-wrap it as UnknownRpcError, masking
        // the failure. retryCount:0 lets the typed error propagate (recover via
        // err.walk / .cause).
        retryCount: 0,
        timeout,
        async request({ method, params }) {
          if (clientChainId !== undefined) session.pin(clientChainId);
          const payload = { jsonrpc: "2.0", id: 1, method, params };
          const json = await session.send(payload, post);
          const error = rpcError(payload, json);
          if (error) throw error;
          // biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
          return (json as { result?: any } | null)?.result;
        },
      },
      { url: rpcUrl },
    );
  };
}

const utf8 = new TextEncoder();
/** Members `vrpcHttp(url, { confidential: true })` adds to `client.transport`. */
export interface ConfidentialValue {
  url: string;
  /** Attests now unless a valid pin exists, and returns the pinned node. */
  ready(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo>;
  /** The pinned node, or `undefined` before the first attestation and after the pin expired or was dropped. */
  getConfidentialInfo(): ConfidentialInfo | undefined;
}

function confidentialHttp(
  rpcUrl: string,
  opts: VrpcHttpOptions,
): Transport<"vrpc-http", ConfidentialValue> {
  const origin = new URL(rpcUrl).origin;
  let client: LazyConfidentialClient | undefined;
  let boundChainId: string | undefined;

  return ({ chain, timeout: injectedTimeout }) => {
    if (chain?.id == null) {
      throw new InvalidOption("chainId", "Ankr Confidential RPC mode needs the client's chain");
    }
    const chainId = String(chain.id);
    if (boundChainId !== undefined && boundChainId !== chainId) {
      throw new InvalidOption("chainId", "this transport is bound to another chain");
    }
    boundChainId = chainId;
    client ??= new LazyConfidentialClient({
      url: rpcUrl,
      chainId,
      headers: opts.headers,
      replayWindowMs: opts.replayWindowMs,
      pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
      logger: opts.logger,
      hardwareVerifier: opts.hardwareVerifier,
      fetch: opts.fetchFn as typeof fetch | undefined,
    });
    const confidential = client;
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    return createTransport(
      {
        key: "vrpc-http",
        name: "vRPC HTTP JSON-RPC",
        type: "vrpc-http",
        retryCount: 0,
        timeout,
        async request({ method, params }, options) {
          const { signal, done } = linkSignal(options?.signal, timeout);
          try {
            const res = await confidential.request(
              {
                method: "POST",
                path: "/",
                contentType: "application/json",
                body: utf8.encode(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })),
              },
              signal === undefined ? undefined : { signal },
            );
            return mapInnerResponse(res, origin);
          } finally {
            done();
          }
        },
      },
      {
        url: rpcUrl,
        ready: (options?: { signal?: AbortSignal }) => confidential.ready(options),
        getConfidentialInfo: () => confidential.getConfidentialInfo(),
      },
    );
  };
}
