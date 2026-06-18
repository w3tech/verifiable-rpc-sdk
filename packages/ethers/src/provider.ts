// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider. Overrides only
// `_send` (the single HTTP chokepoint) to verify the raw, content-decoded
// response body against vrpc-core's Ed25519 seam before `JSON.parse`. Native
// batching is preserved. Always fail-closed: a verify failure throws and no
// unverified data is ever returned.

import { EMPTY_ALLOWLIST } from "@ankr.com/dstack-verify";
import {
  deriveVrpcUrls,
  parseChainId,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@ankr.com/vrpc-core";
import {
  type FetchRequest,
  type JsonRpcPayload,
  JsonRpcProvider,
  type JsonRpcResult,
  Network,
  toUtf8Bytes,
  toUtf8String,
} from "ethers";

import type { VrpcOptions } from "./options";

// Drop `undefined`-valued keys: `exactOptionalPropertyTypes` forbids passing an
// explicit `undefined` to an optional slot. `as T` is the one audited assertion.
function pruneUndefined<T extends object>(obj: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

/**
 * `JsonRpcProvider` that Ed25519-verifies every response over its raw bytes and
 * lazily attests the signing pubkey via TDX (per pubkey, TTL-cached). Drop-in:
 * `new VrpcProvider(url)`; the SDK derives the `_vrpc` route + `/attestation`
 * sub-route from the single URL.
 *
 * `chainId` is optional — omit it and it is derived from a self-consistently
 * verified `eth_chainId` response on first use (fail-fast, no unverified
 * fallback). Passing it explicitly is RECOMMENDED: pins YOUR chain and skips the
 * bootstrap. To pass only options on the auto-derive path:
 * `new VrpcProvider(url, undefined, { allowlist })`.
 */
export class VrpcProvider extends JsonRpcProvider {
  #chainId: bigint | undefined;
  // Memoized in-flight bootstrap: N concurrent first calls share ONE fetch.
  #chainIdPromise: Promise<bigint> | null = null;
  // Builds the verifier from options closed over at construction; chainId is the
  // one late-bound field (may be auto-derived), so it is the factory's argument.
  readonly #makeVerifier: (chainId: bigint) => TrustedVerifier;
  // ONE TrustedVerifier per provider (lifetime cache); eager on pin, lazy on auto-derive.
  #trustedVerifier: TrustedVerifier | undefined;

  constructor(url: string | FetchRequest, chainIdArg?: number | bigint, options: VrpcOptions = {}) {
    const {
      replayWindowMs,
      pubkeyCacheTtlMs,
      allowlist,
      tcb,
      pccsUrl,
      apiKey,
      headers,
      fetch: attestationFetch,
      ...ethersOpts
    } = options;

    // Derive the `_vrpc` route + `/attestation` from the single URL; for a
    // FetchRequest, clone it so the consumer's auth/headers ride along.
    const urls = deriveVrpcUrls(typeof url === "string" ? url : url.url);
    const attestationUrl = urls.attestationUrl;
    let superUrl: string | FetchRequest = urls.rpcUrl;
    if (typeof url !== "string") {
      const clone = url.clone();
      clone.url = urls.rpcUrl;
      superUrl = clone;
    }

    // bigint without a number round-trip: chain ids can exceed 2^53 and the
    // pre-image binds the full u64, so widening through `number` would false-reject.
    const chainId = chainIdArg != null ? BigInt(chainIdArg) : undefined;

    // staticNetwork (pin only) skips ethers' startup eth_chainId probe without
    // weakening the binding; ethersOpts spread first so a user value can't win.
    const superOptions = chainId != null ? { ...ethersOpts, staticNetwork: true } : ethersOpts;
    super(superUrl, chainId, superOptions);

    this.#chainId = chainId;
    this.#makeVerifier = (resolvedChainId) =>
      new TrustedVerifier(
        pruneUndefined<TrustedVerifierOptions>({
          chainId: resolvedChainId,
          attestationUrl,
          allowlist: allowlist ?? EMPTY_ALLOWLIST,
          pubkeyCacheTtlMs,
          tcb,
          pccsUrl,
          apiKey,
          headers,
          fetch: attestationFetch,
          replayWindowMs,
        }),
      );
    // Build the verifier now if possible; auto-derive defers to the first _send.
    if (chainId != null) {
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
  }

  // POST, verify the raw bytes, then parse. chainId resolved lazily if unset.
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
    const { requestBytes, rawResponseBytes, headers } = await this.#post(payload);

    const chainId = this.#chainId ?? (await this.#resolveChainId());
    await this.#getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, headers);

    const parsed = JSON.parse(toUtf8String(rawResponseBytes)) as
      | JsonRpcResult
      | Array<JsonRpcResult>;
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  // Feed the SAME memoized resolver as _send so detection and verification agree.
  override async _detectNetwork(): Promise<Network> {
    return Network.from(await this.#resolveChainId());
  }

  // POST a payload, return the request/response bytes + headers the verifier needs.
  async #post(payload: JsonRpcPayload | Array<JsonRpcPayload>) {
    const requestBody = JSON.stringify(payload);
    const request = this._getConnection();
    request.body = requestBody;
    request.setHeader("content-type", "application/json");
    const response = await request.send();
    response.assertOk();
    return {
      requestBytes: toUtf8Bytes(requestBody),
      rawResponseBytes: response.body ?? new Uint8Array(),
      headers: response.headers,
    };
  }

  // Derive chainId from a self-consistently verified `eth_chainId` response (its
  // own `result` IS the chainId, so the signature only verifies for the chain the
  // node really signed). Memoized; own request, never via _send; on verify failure
  // chainId is NOT set (fail-fast, no unverified fallback).
  #resolveChainId(): Promise<bigint> {
    if (this.#chainId != null) {
      return Promise.resolve(this.#chainId);
    }
    if (this.#chainIdPromise != null) {
      return this.#chainIdPromise;
    }
    this.#chainIdPromise = (async () => {
      const { requestBytes, rawResponseBytes, headers } = await this.#post({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_chainId",
        params: [],
      });

      const chainId = parseChainId(rawResponseBytes);
      await this.#getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, headers);

      this.#chainId = chainId;
      return chainId;
    })();
    return this.#chainIdPromise;
  }

  // Memoized verifier, built lazily once chainId is known.
  #getTrustedVerifier(chainId: bigint): TrustedVerifier {
    if (this.#trustedVerifier === undefined) {
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
    return this.#trustedVerifier;
  }
}
