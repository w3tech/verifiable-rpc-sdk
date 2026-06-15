// vrpcHttp — verifiable drop-in for viem's `http(url)` transport (Phase 31).
//
// A viem custom transport (built on `createTransport`) whose `request` owns its
// own `fetch`, captures the RAW content-decoded response bytes BEFORE
// `JSON.parse`, and feeds them — with the exact request bytes it POSTed — into
// vrpc-core's `verifyResponse` (the SAME seam the ethers `_send` override uses,
// PKG-05). Only after verification passes is the body parsed and the result
// returned. Verification is fail-closed by default (strict); permissive mode
// (opt-in) downgrades a `VerificationError` to one logged warning and passes the
// parsed body through. A signed JSON-RPC `{error}` body surfaces as viem's own
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

import { VerificationError, verifyResponse } from "@ankr.com/vrpc-core";
import { createTransport, HttpRequestError, RpcRequestError, type Transport } from "viem";

import type { VrpcHttpOptions } from "./options";

const defaultLogger = (msg: string, err: unknown): void => {
  console.warn(`[vrpc-viem] ${msg}`, err);
};

/**
 * A viem `Transport` that Ed25519-verifies every HTTP JSON-RPC response over its
 * raw content-decoded bytes before the value reaches the client.
 *
 * Drop-in: `createPublicClient({ transport: vrpcHttp(url) })` substitutes for
 * `http(url)`. The chain id bound into the signed pre-image is OPTIONAL — omit
 * it and the transport lazily derives it via one UNVERIFIED `eth_chainId`
 * bootstrap on the first request (fail-closed-safe). Passing it explicitly —
 * `vrpcHttp(url, { chainId })` — is STRONGLY RECOMMENDED: it skips the bootstrap
 * round-trip and pins the binding. Every read (getBalance, readContract/call,
 * getLogs, getBlock, estimateGas, getTransactionReceipt, sendRawTransaction, …)
 * funnels through the single verifying `request`.
 */
export function vrpcHttp(url: string, opts: VrpcHttpOptions = {}): Transport<"vrpc-http"> {
  const verification = opts.verification ?? "strict";
  const fetchFn = opts.fetchFn ?? fetch;
  const logger = opts.logger ?? defaultLogger;

  // Coerce to bigint WITHOUT a number round-trip (MD-01). When chainId is
  // omitted it is resolved lazily on the first request via an UNVERIFIED
  // eth_chainId bootstrap, memoized so concurrent first calls share ONE fetch.
  let chainIdResolved: bigint | undefined = opts.chainId != null ? BigInt(opts.chainId) : undefined;
  let chainIdPromise: Promise<bigint> | null = null;

  return ({ timeout: injectedTimeout }) => {
    // Resolve the effective timeout the viem-`http()` way: explicit option, then
    // the client-injected value, then viem's 10s default. Applied to the own
    // fetch as an AbortSignal below. (LO-03)
    const timeout = opts.timeout ?? injectedTimeout ?? 10_000;

    /**
     * Lazily derive the chain id via ONE UNVERIFIED `eth_chainId` bootstrap. The
     * promise is assigned BEFORE awaiting so N concurrent first `request` calls
     * share a single in-flight fetch (memoization). It reuses the in-scope
     * `fetchFn`/`headers`/`timeout` so x-api-key / routing carry over, does NOT
     * call `verifyResponse` (the bootstrap is intentionally unverified — chainId
     * is a binding parameter, not a trust anchor), and its result is used ONLY
     * to set `chainIdResolved`; it is NEVER returned to the caller. A lying
     * bootstrap can only cause a fail-closed `BadSignature` DoS, never
     * silent-accept.
     */
    const resolveChainId = (): Promise<bigint> => {
      if (chainIdResolved != null) {
        return Promise.resolve(chainIdResolved);
      }
      if (chainIdPromise != null) {
        return chainIdPromise;
      }
      chainIdPromise = (async () => {
        const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });
        const res = await fetchFn(url, {
          method: "POST",
          headers: { "content-type": "application/json", ...opts.headers },
          body,
          ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
        });
        // BigInt() directly off the hex string — no number round-trip (a chain
        // id may exceed 2^53−1 and must bind the full u64 into the pre-image).
        const parsed = JSON.parse(await res.text()) as { result?: string };
        const cid = BigInt(parsed.result as string);
        chainIdResolved = cid;
        return cid;
      })();
      return chainIdPromise;
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
          const cid = chainIdResolved ?? (await resolveChainId());

          // Serialize ONCE: the same bytes are POSTed and fed to verify, so the
          // pre-image reconstruction matches what the sidecar signed.
          const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
          const requestBytes = new TextEncoder().encode(body);

          const res = await fetchFn(url, {
            method: "POST",
            headers: { "content-type": "application/json", ...opts.headers },
            body,
            // Apply the transport `timeout` to the actual HTTP request (parity
            // with viem `http()`, which aborts on timeout). A consumer-provided
            // `fetchFn` wrapper still forwards this signal to the underlying
            // fetch. (LO-03)
            ...(timeout ? { signal: AbortSignal.timeout(timeout) } : {}),
          });

          // RAW, content-decoded bytes exactly as signed. `res.text()` decodes
          // gzip/br transparently — the sidecar signs the decoded body (ENC-04),
          // so do NOT read res.body or set Accept-Encoding: identity.
          const rawText = await res.text();
          const rawResponseBytes = new TextEncoder().encode(rawText);

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
              url,
            });
          }

          let downgraded = false;
          try {
            // Pass the fetch `Headers` object DIRECTLY — verifyResponse reads it
            // case-insensitively; lowercasing into a Record would risk smuggling.
            await verifyResponse(requestBytes, rawResponseBytes, res.headers, {
              chainId: cid,
              ...(opts.replayWindowMs != null ? { replayWindowMs: opts.replayWindowMs } : {}),
            });
          } catch (err) {
            if (err instanceof VerificationError && verification === "permissive") {
              // Mark the verify as actually DOWNGRADED so the parse-failure log
              // below fires only on a genuinely-downgraded body, not on every
              // invalid signed body. (LO-01, parity with ethers `downgraded`.)
              downgraded = true;
              logger("verification failed (permissive mode, passing through)", err);
            } else {
              // strict fail-closed + any non-VerificationError always propagates.
              throw err;
            }
          }

          // Parse ONLY after verification. In permissive mode a body that failed
          // verification may also be invalid JSON (truncated / HTML error page);
          // surface that parse failure through the same logger so the permissive
          // consumer sees one coherent diagnostic rather than an opaque
          // SyntaxError. The error still propagates (fail-closed; no unverified
          // data is returned silently). (MD-02, parity with ethers LO-03.)
          // `JSON.parse` returns `any` so `parsed.result` flows back through the
          // viem `EIP1193RequestFn` return without a cast (parity with viem's own
          // `http` transport, which returns the parsed value untyped).
          // biome-ignore lint/suspicious/noExplicitAny: viem request returns untyped.
          let parsed: any;
          try {
            parsed = JSON.parse(rawText);
          } catch (err) {
            if (downgraded) {
              logger("permissive passthrough: response body is not valid JSON", err);
            }
            throw err;
          }
          // `"error" in parsed` (not a truthy check): a signed JSON-RPC error
          // body is identified by the PRESENCE of the `error` key, matching
          // JSON-RPC semantics. (LO-02)
          if (parsed != null && "error" in parsed) {
            // Same class viem's http transport throws — buildRequest maps it by
            // code and `instanceof VerificationError === false`.
            throw new RpcRequestError({ body: { method, params }, error: parsed.error, url });
          }
          return parsed.result;
        },
      },
      { url },
    );
  };
}
