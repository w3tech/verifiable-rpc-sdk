// vrpcHttp — verifiable drop-in for viem's `http(url)` transport (Phase 31).
//
// A viem custom transport (built on `createTransport`) whose `request` owns its
// own `fetch`, captures the RAW content-decoded response bytes BEFORE
// `JSON.parse`, and feeds them — with the exact request bytes it POSTed — into
// vrpc-core's `verifyResponse` (the SAME seam the ethers `_send` override uses,
// PKG-05). Only after verification passes is the body parsed and the result
// returned. Verification is always fail-closed: a `VerificationError` propagates
// out of `request`; no unverified data is returned. A signed JSON-RPC `{error}`
// body surfaces as viem's own
// `RpcRequestError` (NOT a VerificationError) so `buildRequest` maps it by code.
//
// HTTP-status parity (MD-01): mirrors the ethers `_send` override's
// `response.assertOk()` (provider.ts:87). An UNSIGNED non-2xx response (a bare
// gateway 502 / timeout error page with no `vRPC-*` headers) is a transport
// failure and throws viem's `HttpRequestError` BEFORE verify — so it reads as a
// network error, not a `MissingHeader` that looks like a verify attack. This
// does NOT weaken fail-closed: a SIGNED non-2xx body still flows into
// `verifyResponse` (its signed `{error}` surfaces as an ordinary RpcError), and
// an UNSIGNED 2xx body still reaches verify and fails closed with `MissingHeader`.
//
// Batching is OFF by default for v1: every action issues a single non-batched
// `{ id: 1 }` request that is verified as one unit (consistent with ETHERS-05 —
// VIEM-03). Batched-as-one-unit verification is a deferred opt-in.
//
// `retryCount: 0` is hardcoded and viem's injected default is ignored on purpose:
// `buildRequest` (viem utils/buildRequest.ts) treats a thrown VerificationError
// as a codeless non-HTTP error and would otherwise RETRY it 3× and re-wrap it as
// an UnknownRpcError, masking the verify failure. With retryCount:0 the typed
// error propagates; a full-client caller recovers it via
// `err.walk(e => e instanceof VerificationError)` since buildRequest preserves it
// as `.cause`.

import { EMPTY_ALLOWLIST } from "@ankr.com/dstack-verify";
import {
  deriveVrpcUrls,
  parseChainId,
  TrustedVerifier,
  VerificationError,
} from "@ankr.com/vrpc-core";
import { createTransport, HttpRequestError, RpcRequestError, type Transport } from "viem";

import type { VrpcHttpOptions } from "./options";

/**
 * A viem `Transport` that Ed25519-verifies every HTTP JSON-RPC response over its
 * raw content-decoded bytes before the value reaches the client.
 *
 * Drop-in: `createPublicClient({ transport: vrpcHttp(url) })` substitutes for
 * `http(url)`. The user passes ONE URL (e.g. `https://rpc.ankr.com/arbitrum`);
 * the transport derives the `_vrpc` RPC route it POSTs to (`…/arbitrum_vrpc`) and
 * its `/attestation` sub-route via `deriveVrpcUrls`. The chain id bound into the
 * signed pre-image is OPTIONAL — omit
 * it and the transport lazily derives it from a SIGNED `eth_chainId` response on
 * the first request, verifying that signature self-consistently (the response's
 * own `result` IS the chainId, so it only verifies if the node really signed for
 * that chain). A tampered/forged/unsigned bootstrap fails FAST with a
 * `VerificationError`; there is no unverified fallback. Passing it explicitly —
 * `vrpcHttp(url, { chainId })` — is STRONGLY RECOMMENDED: it pins to YOUR
 * expected chain (catching a wrong-node / wrong-URL misconfig that auto-derive,
 * which trusts the node's self-reported chain, would not) and skips the
 * bootstrap round-trip. Every read (getBalance, readContract/call, getLogs,
 * getBlock, estimateGas, getTransactionReceipt, sendRawTransaction, …) funnels
 * through the single verifying `request`.
 */
export function vrpcHttp(url: string, opts: VrpcHttpOptions = {}): Transport<"vrpc-http"> {
  const fetchFn = opts.fetchFn ?? fetch;

  // Derive the `_vrpc` RPC route and its `/attestation` sub-route from the single
  // user URL. The RPC POST goes to `rpcUrl`; the verifier's attestation GET goes
  // to `attestationUrl`. The user never spells either out
  // (`https://rpc.ankr.com/arbitrum` → POST `…/arbitrum_vrpc`).
  const { rpcUrl, attestationUrl } = deriveVrpcUrls(url);

  // Coerce to bigint WITHOUT a number round-trip (MD-01). When chainId is
  // omitted it is resolved lazily on the first request via an UNVERIFIED
  // eth_chainId bootstrap, memoized so concurrent first calls share ONE fetch.
  let chainIdResolved: bigint | undefined = opts.chainId != null ? BigInt(opts.chainId) : undefined;
  let chainIdPromise: Promise<bigint> | null = null;

  // The TrustedVerifier is ALWAYS active. Its chainId is REQUIRED, but the viem
  // chainId may be resolved lazily, so the single verifier is built lazily on the
  // first request AFTER `chainId` is known and memoized here so all subsequent
  // requests reuse the SAME instance + pubkey cache (one verifier per transport,
  // never per call).
  let trustedVerifier: TrustedVerifier | undefined;
  const getTrustedVerifier = (chainId: bigint): TrustedVerifier => {
    if (trustedVerifier === undefined) {
      trustedVerifier = new TrustedVerifier({
        chainId,
        attestationUrl,
        allowlist: opts.allowlist ?? EMPTY_ALLOWLIST,
        ...(opts.replayWindowMs === undefined ? {} : { replayWindowMs: opts.replayWindowMs }),
        ...(opts.pubkeyCacheTtlMs === undefined ? {} : { pubkeyCacheTtlMs: opts.pubkeyCacheTtlMs }),
        ...(opts.tcb === undefined ? {} : { tcb: opts.tcb }),
        ...(opts.pccsUrl === undefined ? {} : { pccsUrl: opts.pccsUrl }),
        ...(opts.apiKey === undefined ? {} : { apiKey: opts.apiKey }),
        ...(opts.headers === undefined ? {} : { headers: opts.headers }),
        // `fetchFn`'s (url, init) => Promise<Response> aligns with the verifier's
        // `fetch` for the attestation GET leg (Pitfall 6).
        ...(opts.fetchFn === undefined ? {} : { fetch: opts.fetchFn as typeof fetch }),
      });
    }
    return trustedVerifier;
  };

  return ({ timeout: injectedTimeout }) => {
    // Resolve the effective timeout the viem-`http()` way: explicit option, then
    // the client-injected value, then viem's 10s default. Applied to the own
    // fetch as an AbortSignal below. (LO-03)
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    /**
     * Lazily derive the chain id from ONE SELF-CONSISTENTLY VERIFIED
     * `eth_chainId` response. The promise is assigned BEFORE awaiting so N
     * concurrent first `request` calls share a single in-flight fetch
     * (memoization). It reuses the in-scope `fetchFn`/`headers`/`timeout` so
     * x-api-key / routing carry over, and its result is used ONLY to set
     * `chainIdResolved`; it is NEVER returned to the caller.
     *
     * The `eth_chainId` response is itself a signed vRPC response whose `result`
     * IS the chainId. We parse `C = BigInt(result)` then call `verifyResponse`
     * with `{ chainId: C }`: the signature is over a pre-image binding
     * chainId=C, so it only verifies if the node really signed for C
     * (self-consistent). On any verify failure (BadSignature / MissingHeader /
     * tampered / unsigned) the error PROPAGATES (fail-FAST at bootstrap) — we
     * never set `chainIdResolved` and never fall back to an unverified value. A
     * lying/forged/tampered bootstrap fails immediately instead of deferring to
     * a later BadSignature on a real read.
     */
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
        // Convert the response body to a chainId (shared core util). A malformed
        // body throws MalformedHeader → reads as a fail-fast verify failure.
        const chainId = parseChainId(rawResponseBytes);
        // Verify-AND-attest the bootstrap through the SAME TrustedVerifier built
        // for this chainId. eth_chainId is itself a vRPC call: its response is
        // verified self-consistently (the signature must bind its OWN claimed
        // chainId C) AND the signing pubkey is attested (first-unseen pubkey →
        // lazy TDX attestation, cached so the first real read reuses it). A
        // tampered/forged/unsigned bootstrap, or an unattested signer, fails FAST
        // here. Fail-closed: do NOT set chainIdResolved, do NOT fall back.
        try {
          await getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, res.headers);
        } catch (err) {
          if (err instanceof VerificationError) {
            err.message = `auto-derived chainId could not be verified (pass \`chainId\` explicitly): ${err.message}`;
          }
          throw err;
        }
        chainIdResolved = chainId;
        return chainId;
      })();
      return chainIdPromise;
    };

    // Shared POST choke (mirrors the ethers `#post` helper): serialize ONCE, fetch,
    // capture the RAW content-decoded body. `res.text()` decodes gzip/br transparently
    // — the sidecar signs the decoded body (ENC-04) — so encode that exact text for the
    // verify pre-image. Used by both the chainId bootstrap and the request path.
    const post = async (payload: Record<string, unknown>) => {
      const body = JSON.stringify(payload);
      const res = await fetchFn(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...opts.headers },
        body,
        // Apply the transport `timeout` to the actual HTTP request (parity with viem
        // `http()`). A consumer `fetchFn` wrapper forwards this signal too. (LO-03)
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
        // Hardcoded — do NOT honor viem's injected default (see file header).
        retryCount: 0,
        timeout,
        async request({ method, params }) {
          // Single choke point: resolve the chain id (cheap memoized read after
          // the first derive, or the pre-populated explicit pin) BEFORE building
          // the request that flows into verify.
          const chainId = chainIdResolved ?? (await resolveChainId());

          const { requestBytes, rawText, rawResponseBytes, res } = await post({
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
          });

          // HTTP-status parity with ethers `response.assertOk()` (provider.ts:87):
          // a non-2xx response that is NOT vRPC-signed is a transport-level
          // failure (gateway timeout / 502 / 4xx) and must surface as a network
          // error, NOT as a `MissingHeader` that looks like a verify attack. This
          // does NOT weaken fail-closed: a SIGNED non-2xx body still flows into
          // `verifyResponse` below (its signed `{error}` surfaces as an ordinary
          // RpcRequestError), and an unsigned 2xx body still reaches verify and
          // fails closed with `MissingHeader`. (MD-01)
          if (!res.ok && !res.headers.get("vRPC-Signature")) {
            throw new HttpRequestError({
              body: { method, params },
              status: res.status,
              headers: res.headers,
              url: rpcUrl,
            });
          }

          // Fail-closed: any verify error (VerificationError or otherwise)
          // propagates out of `request`; no unverified data is returned. The
          // verify ALWAYS runs through the per-transport TrustedVerifier (which
          // wraps verifyResponse and lazily attests unknown pubkeys) — including
          // the chainId bootstrap, which runs through the SAME verifier (see
          // resolveChainId). Pass the fetch `Headers` object DIRECTLY — the
          // verifier reads it case-insensitively; lowercasing into a Record would
          // risk smuggling.
          await getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, res.headers);

          // Parse ONLY after verification. A JSON.parse failure propagates
          // naturally (fail-closed; no unverified data is returned).
          // `JSON.parse` returns `any` so `parsed.result` flows back through the
          // viem `EIP1193RequestFn` return without a cast (parity with viem's own
          // `http` transport, which returns the parsed value untyped).
          // biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
          const parsed: any = JSON.parse(rawText);
          // `"error" in parsed` (not a truthy check): a signed JSON-RPC error
          // body is identified by the PRESENCE of the `error` key, matching
          // JSON-RPC semantics. (LO-02)
          if (parsed != null && "error" in parsed) {
            // Same class viem's http transport throws — buildRequest maps it by
            // code and `instanceof VerificationError === false`.
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
