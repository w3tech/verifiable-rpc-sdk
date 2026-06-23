// vrpcHttp — verifiable drop-in for viem's `http(url)` transport. A custom
// transport whose `request` owns its fetch, captures the RAW content-decoded
// response bytes BEFORE `JSON.parse`, and verifies them through vrpc-core's seam
// (the same one ethers' `_send` uses). Always fail-closed: a verify failure
// throws and no unverified data is returned. A signed JSON-RPC `{error}` body
// surfaces as viem's `RpcRequestError` (not a VerificationError) so
// `buildRequest` maps it by code.

import {
  deriveVrpcUrls,
  isSignedVrpcResponse,
  parseChainId,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@ankr.com/vrpc-core";
import { createTransport, HttpRequestError, RpcRequestError, type Transport } from "viem";

import type { VrpcHttpOptions } from "./options";

// Drop `undefined`-valued keys: `exactOptionalPropertyTypes` forbids passing an
// explicit `undefined` to an optional slot. `as T` is the one audited assertion.
function pruneUndefined<T extends object>(obj: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

/**
 * A viem `Transport` that Ed25519-verifies every response over its raw bytes
 * before it reaches the client. Drop-in:
 * `createPublicClient({ transport: vrpcHttp(url) })`. The transport derives the
 * `_vrpc` RPC route + `/attestation` sub-route from the single URL.
 *
 * The chain id bound into the pre-image comes from the viem client's `chain`
 * (`chain.id`). With no chain set it is derived from a self-consistently verified
 * `eth_chainId` response on the first request (fail-fast, no unverified fallback);
 * declaring `chain` on the client pins YOUR chain and skips the bootstrap.
 */
export function vrpcHttp(url: string, opts: VrpcHttpOptions = {}): Transport<"vrpc-http"> {
  const fetchFn = opts.fetchFn ?? fetch;

  // Derive the `_vrpc` RPC route + `/attestation` from the single URL.
  const { rpcUrl, attestationUrl } = deriveVrpcUrls(url);

  // Pinned from the viem client's chain.id (seeded in the factory below), or
  // auto-derived lazily when no chain is set; the in-flight bootstrap promise is
  // memoized so concurrent first calls share ONE fetch.
  let chainIdResolved: bigint | undefined;
  let chainIdPromise: Promise<bigint> | null = null;

  // ONE TrustedVerifier per transport (lifetime pubkey cache); built lazily once
  // chainId is known. (v6.0: the verifier defaults the trust policy internally.)
  let trustedVerifier: TrustedVerifier | undefined;
  const getTrustedVerifier = (chainId: bigint): TrustedVerifier => {
    if (trustedVerifier === undefined) {
      trustedVerifier = new TrustedVerifier(
        pruneUndefined<TrustedVerifierOptions>({
          chainId,
          attestationUrl,
          replayWindowMs: opts.replayWindowMs,
          pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs,
          headers: opts.headers,
          // fetchFn's (url, init) => Promise<Response> aligns with the verifier's
          // `fetch` for the attestation GET leg.
          fetch: opts.fetchFn as typeof fetch | undefined,
        }),
      );
    }
    return trustedVerifier;
  };

  return ({ chain, timeout: injectedTimeout }) => {
    // viem injects the client's `chain`; its id is the pin source (chainId left
    // the options bag — mirrors ethers taking it from the ctor). No chain → the
    // lazy verified eth_chainId bootstrap fills it on the first request.
    if (chainIdResolved === undefined && chain?.id != null) {
      chainIdResolved = BigInt(chain.id);
    }
    // Effective timeout: explicit option → client-injected → viem's 10s default.
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    // Derive chainId from a self-consistently verified `eth_chainId` response (its
    // own `result` IS the chainId, so the signature only verifies for the chain
    // the node really signed). Memoized; reuses the in-scope fetch/headers/timeout;
    // on verify failure chainIdResolved is NOT set (fail-fast, no fallback).
    const resolveChainId = (): Promise<bigint> => {
      if (chainIdResolved != null) {
        return Promise.resolve(chainIdResolved);
      }
      if (chainIdPromise != null) {
        return chainIdPromise;
      }
      chainIdPromise = (async () => {
        const { requestBytes, rawResponseBytes, res } = await post({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_chainId",
          params: [],
        });

        const chainId = parseChainId(rawResponseBytes);
        await getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, res.headers);

        chainIdResolved = chainId;
        return chainId;
      })();
      return chainIdPromise;
    };

    // Shared POST choke (mirrors ethers' #post): serialize once, fetch, capture the
    // RAW content-decoded body. `res.text()` decodes gzip/br transparently — the
    // sidecar signs the decoded body — so encode that exact text for the pre-image.
    const post = async (payload: Record<string, unknown>) => {
      const body = JSON.stringify(payload);
      const res = await fetchFn(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...opts.headers },
        body,
        ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
      });
      const rawText = await res.text();
      return {
        requestBytes: new TextEncoder().encode(body),
        rawText,
        rawResponseBytes: new TextEncoder().encode(rawText),
        res,
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
          // POST first, then resolve chainId (memoized) and verify the held bytes.
          const { requestBytes, rawText, rawResponseBytes, res } = await post({
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
          const parsed: any = JSON.parse(rawText);
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
