// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpcHttp — verifiable drop-in for viem's `http(url)` transport. A custom
// transport whose `request` owns its fetch, captures the RAW content-decoded
// response bytes BEFORE `JSON.parse`, and verifies them through vrpc-core's seam
// (the same one ethers' `_send` uses). Always fail-closed: a verify failure
// throws and no unverified data is returned. A signed JSON-RPC `{error}` body
// surfaces as viem's `RpcRequestError` (not a VerificationError) so
// `buildRequest` maps it by code.

import {
  type ConfidentialInfo,
  checkOptions,
  deriveVrpcUrls,
  fetchTransport,
  InvalidOption,
  isSignedVrpcResponse,
  LazyConfidentialClient,
  parseChainId,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@w3tech.io/vrpc-core";
import { createTransport, HttpRequestError, RpcRequestError, type Transport } from "viem";

import { linkSignal, mapInnerResponse } from "./confidential";
import type { VrpcHttpOptions } from "./options";

// Drop `undefined`-valued keys: `exactOptionalPropertyTypes` forbids passing an
// explicit `undefined` to an optional slot. `as T` is the one audited assertion.
function pruneUndefined<T extends object>(obj: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

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
  if (opts.confidential !== undefined && typeof opts.confidential !== "boolean") {
    throw new TypeError("confidential must be a boolean");
  }
  if (opts.confidential === true) return confidentialHttp(url, opts);
  const fetchFn = opts.fetchFn ?? fetch;

  // Derive the `/attestation` sub-route from the single URL.
  const { rpcUrl, attestationUrl } = deriveVrpcUrls(url);

  // Pinned from the viem client's chain.id (seeded in the factory below), or
  // auto-derived lazily when no chain is set; the in-flight bootstrap promise is
  // memoized so concurrent first calls share ONE fetch.
  let chainIdResolved: string | undefined;
  let chainIdPromise: Promise<string> | null = null;

  // ONE TrustedVerifier per transport (lifetime pubkey cache); built lazily once
  // chainId is known. (v6.0: the verifier defaults the trust policy internally.)
  let trustedVerifier: TrustedVerifier | undefined;
  const makeVerifier = (chainId: string): TrustedVerifier =>
    new TrustedVerifier(
      pruneUndefined<TrustedVerifierOptions>({
        chainId,
        attestationUrl,
        replayWindowMs: opts.replayWindowMs,
        pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
        headers: opts.headers,
        // fetchFn's (url, init) => Promise<Response> aligns with the verifier's
        // `fetch` for the attestation GET leg.
        fetch: opts.fetchFn as typeof fetch | undefined,
        hardwareVerifier: opts.hardwareVerifier,
        logger: opts.logger,
      }),
    );
  const getTrustedVerifier = (chainId: string): TrustedVerifier =>
    (trustedVerifier ??= makeVerifier(chainId));

  return ({ chain, timeout: injectedTimeout }) => {
    // viem injects the client's `chain`; its id is the pin source (chainId left
    // the options bag — mirrors ethers taking it from the ctor). No chain → the
    // lazy verified eth_chainId bootstrap fills it on the first request.
    // viem chain ids are plain numbers; decimal stringification matches what
    // EVM sidecars are configured with (e.g. 42161 → "42161").
    const clientChainId = chain?.id == null ? undefined : String(chain.id);
    chainIdResolved ??= clientChainId;
    // Effective timeout: explicit option → client-injected → viem's 10s default.
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    // Derive chainId from a self-consistently verified `eth_chainId` response (its
    // own `result` IS the chainId, so the signature only verifies for the chain
    // the node really signed). Memoized; reuses the in-scope fetch/headers/timeout.
    // A failed bootstrap fails its own call and leaves neither the memo nor a
    // verifier, so the next call bootstraps again (no unverified fallback).
    const resolveChainId = (): Promise<string> => {
      if (chainIdResolved != null) {
        return Promise.resolve(chainIdResolved);
      }
      if (chainIdPromise != null) {
        return chainIdPromise;
      }
      chainIdPromise = (async () => {
        try {
          const { requestBytes, rawResponseBytes, res } = await post({
            jsonrpc: "2.0",
            id: 1,
            method: "eth_chainId",
            params: [],
          });

          const chainId = parseChainId(rawResponseBytes);
          const verifier = makeVerifier(chainId);
          await verifier.verify(requestBytes, rawResponseBytes, res.headers);

          // A client with a chain may have pinned the transport while this was in flight.
          chainIdResolved = bindChainId(chainIdResolved, chainId);
          trustedVerifier ??= verifier;
          return chainId;
        } catch (err) {
          chainIdPromise = null;
          throw err;
        }
      })();
      return chainIdPromise;
    };

    // Shared POST choke (mirrors ethers' #post): serialize once, send exactly the
    // bytes verify hashes, capture the content-decoded body bytes as is (what the
    // sidecar signed).
    const post = async (payload: Record<string, unknown>) => {
      const requestBytes = utf8.encode(JSON.stringify(payload));
      const res = await fetchFn(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...opts.headers },
        body: requestBytes,
        ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
      });
      const rawResponseBytes = new Uint8Array(await res.arrayBuffer());
      return { requestBytes, rawResponseBytes, res };
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
          // One transport serves one chain: the node URL is chain-specific.
          if (clientChainId !== undefined) {
            chainIdResolved = bindChainId(chainIdResolved, clientChainId);
          }
          // POST first, then resolve chainId (memoized) and verify the held bytes.
          const { requestBytes, rawResponseBytes, res } = await post({
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
          });

          // HTTP-status parity with ethers `response.assertOk()`: an UNSIGNED
          // non-2xx (gateway 502 / timeout) is a transport failure → network error,
          // not a `MissingHeader` that looks like an attack. A SIGNED non-2xx body
          // still flows into verify; an unsigned 2xx still fails closed.
          if (!res.ok && !isSignedVrpcResponse(res.headers)) {
            throw new HttpRequestError({
              body: { method, params },
              status: res.status,
              headers: res.headers,
              url: rpcUrl,
            });
          }

          const chainId = chainIdResolved ?? (await resolveChainId());
          // Pass the fetch `Headers` directly — the verifier reads it
          // case-insensitively; lowercasing into a Record would risk smuggling.
          await getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, res.headers);

          // Parse ONLY after verify. `any` mirrors viem's own `http` transport
          // (returns the parsed value untyped); a parse failure propagates (fail-closed).
          // biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
          const parsed: any = JSON.parse(utf8Decoder.decode(rawResponseBytes));
          // Signed JSON-RPC error = PRESENCE of the `error` key (not a truthy check).
          if (parsed != null && "error" in parsed) {
            // Same class viem's http transport throws — buildRequest maps it by code.
            throw new RpcRequestError({
              body: { method, params },
              error: parsed.error,
              url: rpcUrl,
            });
          }
          return parsed.result;
        },
      },
      { url: rpcUrl },
    );
  };
}

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

/** Returns the chain a transport serves: `pinned`, or `chainId` while nothing is pinned. */
function bindChainId(pinned: string | undefined, chainId: string): string {
  if (pinned !== undefined && pinned !== chainId) {
    throw new InvalidOption("chainId", "this transport is bound to another chain");
  }
  return chainId;
}

/** Members `vrpcHttp(url, { confidential: true })` adds to `client.transport`. */
export interface ConfidentialValue {
  url: string;
  /** Attests now unless a valid pin exists, and returns the pinned node. */
  ready(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo>;
  /** The pinned node, or `undefined` before the first attestation and after the pin expired or was dropped. */
  getConfidentialInfo(): ConfidentialInfo | undefined;
}

function confidentialHttp(
  url: string,
  opts: VrpcHttpOptions,
): Transport<"vrpc-http", ConfidentialValue> {
  const { rpcUrl } = checkOptions({
    url,
    headers: opts.headers,
    replayWindowMs: opts.replayWindowMs,
    pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
  }).urls;
  const origin = new URL(rpcUrl).origin;
  let client: LazyConfidentialClient | undefined;
  let boundChainId: string | undefined;

  return ({ chain, timeout: injectedTimeout }) => {
    if (chain?.id == null) {
      throw new InvalidOption("chainId", "Ankr Confidential RPC mode needs the client's chain");
    }
    const chainId = String(chain.id);
    boundChainId = bindChainId(boundChainId, chainId);
    client ??= new LazyConfidentialClient({
      url: rpcUrl,
      chainId,
      transport: fetchTransport(opts.fetchFn),
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
