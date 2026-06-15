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
import { createTransport, RpcRequestError, type Transport } from "viem";

import type { VrpcHttpOptions } from "./options";

const defaultLogger = (msg: string, err: unknown): void => {
  console.warn(`[vrpc-viem] ${msg}`, err);
};

/**
 * A viem `Transport` that Ed25519-verifies every HTTP JSON-RPC response over its
 * raw content-decoded bytes before the value reaches the client.
 *
 * Drop-in: `createPublicClient({ transport: vrpcHttp(url, { chainId }) })`
 * substitutes for `http(url)` with one extra option (the chain id bound into the
 * signed pre-image). Every read (getBalance, readContract/call, getLogs,
 * getBlock, estimateGas, getTransactionReceipt, sendRawTransaction, …) funnels
 * through the single verifying `request`.
 */
export function vrpcHttp(url: string, opts: VrpcHttpOptions): Transport<"vrpc-http"> {
  // Coerce to bigint WITHOUT a number round-trip (MD-01).
  const chainId = BigInt(opts.chainId);
  const verification = opts.verification ?? "strict";
  const fetchFn = opts.fetchFn ?? fetch;
  const logger = opts.logger ?? defaultLogger;

  return ({ timeout }) =>
    createTransport(
      {
        key: "vrpc-http",
        name: "vRPC HTTP JSON-RPC",
        type: "vrpc-http",
        // Hardcoded — do NOT honor viem's injected default (see file header).
        retryCount: 0,
        timeout,
        async request({ method, params }) {
          // Serialize ONCE: the same bytes are POSTed and fed to verify, so the
          // pre-image reconstruction matches what the sidecar signed.
          const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
          const requestBytes = new TextEncoder().encode(body);

          const res = await fetchFn(url, {
            method: "POST",
            headers: { "content-type": "application/json", ...opts.headers },
            body,
          });

          // RAW, content-decoded bytes exactly as signed. `res.text()` decodes
          // gzip/br transparently — the sidecar signs the decoded body (ENC-04),
          // so do NOT read res.body or set Accept-Encoding: identity.
          const rawText = await res.text();
          const rawResponseBytes = new TextEncoder().encode(rawText);

          try {
            // Pass the fetch `Headers` object DIRECTLY — verifyResponse reads it
            // case-insensitively; lowercasing into a Record would risk smuggling.
            await verifyResponse(requestBytes, rawResponseBytes, res.headers, {
              chainId,
              ...(opts.replayWindowMs != null ? { replayWindowMs: opts.replayWindowMs } : {}),
            });
          } catch (err) {
            if (err instanceof VerificationError && verification === "permissive") {
              logger("verification failed (permissive mode, passing through)", err);
            } else {
              // strict fail-closed + any non-VerificationError always propagates.
              throw err;
            }
          }

          // Parse ONLY after verification.
          const parsed = JSON.parse(rawText);
          if (parsed.error) {
            // Same class viem's http transport throws — buildRequest maps it by
            // code and `instanceof VerificationError === false`.
            throw new RpcRequestError({ body: { method, params }, error: parsed.error, url });
          }
          return parsed.result;
        },
      },
      { url },
    );
}
