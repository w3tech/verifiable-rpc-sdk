// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider. Overrides only
// `_send` (the single HTTP chokepoint) to verify the raw, content-decoded
// response body against vrpc-core's Ed25519 seam before `JSON.parse`. Native
// batching is preserved. Always fail-closed: a verify failure throws and no
// unverified data is ever returned.

import {
  checkOptions,
  InvalidOption,
  LazyConfidentialClient,
  parseChainId,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "@w3tech.io/vrpc-core";
import type { ConfidentialInfo } from "@w3tech.io/vrpc-core/confidential";
import {
  type FetchRequest,
  type JsonRpcPayload,
  JsonRpcProvider,
  type JsonRpcResult,
  Network,
  toUtf8Bytes,
  toUtf8String,
} from "ethers";

import { fetchRequestTransport, sendConfidential } from "./confidential";
import type { VrpcOptions } from "./options";

// Drop `undefined`-valued keys: `exactOptionalPropertyTypes` forbids passing an
// explicit `undefined` to an optional slot. `as T` is the one audited assertion.
function pruneUndefined<T extends object>(obj: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

/**
 * `JsonRpcProvider` that Ed25519-verifies every response over its raw bytes and
 * lazily attests the signing pubkey via TDX (per pubkey, TTL-cached). Drop-in:
 * `new VrpcProvider(url)`; the URL is used verbatim for RPC and the SDK derives
 * the `/attestation` sub-route from it.
 *
 * `chainId` is optional — omit it and it is derived from a self-consistently
 * verified `eth_chainId` response on first use (fail-fast, no unverified
 * fallback). Passing it explicitly is RECOMMENDED: pins YOUR chain and skips the
 * bootstrap. To pass only options on the auto-derive path:
 * `new VrpcProvider(url, undefined, { pubkeyCacheTtlMs })`.
 */
export class VrpcProvider extends JsonRpcProvider {
  #chainId: string | undefined;
  // Memoized in-flight bootstrap: N concurrent first calls share ONE fetch.
  #chainIdPromise: Promise<string> | null = null;
  // Builds the verifier from options closed over at construction; chainId is the
  // one late-bound field (may be auto-derived), so it is the factory's argument.
  readonly #makeVerifier: (chainId: string) => TrustedVerifier;
  // ONE TrustedVerifier per provider (lifetime cache); eager on pin, lazy on auto-derive.
  #trustedVerifier: TrustedVerifier | undefined;
  readonly #confidential: LazyConfidentialClient | undefined;

  constructor(
    url: string | FetchRequest,
    chainIdArg?: number | bigint | string,
    options: VrpcOptions = {},
  ) {
    const {
      replayWindowMs,
      pubkeyCacheTtlMs,
      fetch: attestationFetch,
      hardwareVerifier,
      logger,
      confidential,
      ...ethersOpts
    } = options;

    // A FetchRequest's headers (e.g. `x-api-key`) also authenticate the attestation leg, as in viem.
    const attestationHeaders = typeof url === "string" ? undefined : url.headers;
    const { urls, chainId } = checkOptions({
      url: typeof url === "string" ? url : url.url,
      chainId: chainIdArg ?? undefined,
      headers: attestationHeaders,
      replayWindowMs,
      pubkeyCacheTtlMs,
      confidential,
    });
    const attestationUrl = urls.attestationUrl;
    // A FetchRequest is cloned so the consumer's auth and headers ride along.
    let superUrl: string | FetchRequest = urls.rpcUrl;
    if (typeof url !== "string") {
      const clone = url.clone();
      clone.url = urls.rpcUrl;
      superUrl = clone;
    }

    if (confidential === true) {
      if (chainId === undefined) {
        throw new InvalidOption("chainId", "Ankr Confidential RPC mode needs a pinned chain id");
      }
      // A non-decimal id leaves ethers without a network: it would retry detection forever.
      if (!/^\d+$/.test(chainId)) {
        throw new InvalidOption(
          "chainId",
          "Ankr Confidential RPC mode with ethers needs a decimal chain id",
        );
      }
    }

    // staticNetwork (pin only) skips ethers' startup eth_chainId probe without
    // weakening the binding; ethersOpts spread first so a user value can't win.
    // Only an all-decimal id can be pinned as an ethers network: CAIP-2 style
    // ids are non-EVM, ethers cannot represent such a network, so those pass no
    // network arg (ethers probes lazily) — the verifier still binds the exact string.
    const networkChainId = chainId !== undefined && /^\d+$/.test(chainId) ? BigInt(chainId) : null;
    const superOptions =
      networkChainId != null ? { ...ethersOpts, staticNetwork: true } : ethersOpts;
    super(superUrl, networkChainId ?? undefined, superOptions);

    this.#chainId = chainId;
    this.#makeVerifier = (resolvedChainId) =>
      new TrustedVerifier(
        pruneUndefined<TrustedVerifierOptions>({
          chainId: resolvedChainId,
          attestationUrl,
          pubkeyCacheTtlMs,
          headers: attestationHeaders,
          fetch: attestationFetch,
          replayWindowMs,
          hardwareVerifier,
          logger,
        }),
      );
    if (confidential === true && chainId !== undefined) {
      // CCIP-Read would send the call data in plaintext to a URL the contract names.
      this.disableCcipRead = true;
      this.#confidential = new LazyConfidentialClient({
        url: urls.rpcUrl,
        chainId,
        replayWindowMs,
        pubkeyCacheTtlMs,
        logger,
        hardwareVerifier,
        fetch: attestationFetch,
        transport: fetchRequestTransport(() => this._getConnection()),
      });
    } else if (chainId != null) {
      // Build the verifier now if possible; auto-derive defers to the first _send.
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
  }

  /**
   * Attests the node now in Ankr Confidential RPC mode and returns it; rejects with a `TypeError`
   * when the mode is off. Later calls reuse the pin until it expires.
   */
  async confidentialReady(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo> {
    if (this.#confidential === undefined) {
      throw new TypeError("Ankr Confidential RPC mode is not enabled on this provider");
    }
    return this.#confidential.ready(options);
  }

  /** The node pinned in Ankr Confidential RPC mode; `undefined` before attestation or in open mode. */
  getConfidentialInfo(): ConfidentialInfo | undefined {
    return this.#confidential?.getConfidentialInfo();
  }

  // POST, verify the raw bytes, then parse. chainId resolved lazily if unset.
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
    if (this.#confidential !== undefined) return sendConfidential(this.#confidential, payload);
    const { requestBytes, rawResponseBytes, headers } = await this.#post(payload);

    const chainId = this.#chainId ?? (await this.#resolveChainId());
    await this.#getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, headers);

    const parsed = JSON.parse(toUtf8String(rawResponseBytes)) as
      | JsonRpcResult
      | Array<JsonRpcResult>;
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  // Feed the SAME memoized resolver as _send so detection and verification agree.
  // Auto-derived ids are always decimal (parseChainId), so BigInt is safe here;
  // a pinned CAIP-2 style id has no ethers Network representation and fails loud.
  override async _detectNetwork(): Promise<Network> {
    return Network.from(BigInt(await this.#resolveChainId()));
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
  // node really signed). Memoized; own request, never via _send. A failed
  // bootstrap fails its own call and leaves neither the memo nor a verifier, so
  // the next call bootstraps again (no unverified fallback).
  #resolveChainId(): Promise<string> {
    if (this.#chainId != null) {
      return Promise.resolve(this.#chainId);
    }
    if (this.#chainIdPromise != null) {
      return this.#chainIdPromise;
    }
    this.#chainIdPromise = (async () => {
      try {
        const { requestBytes, rawResponseBytes, headers } = await this.#post({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_chainId",
          params: [],
        });

        const chainId = parseChainId(rawResponseBytes);
        const verifier = this.#makeVerifier(chainId);
        await verifier.verify(requestBytes, rawResponseBytes, headers);

        this.#trustedVerifier = verifier;
        this.#chainId = chainId;
        return chainId;
      } catch (err) {
        this.#chainIdPromise = null;
        throw err;
      }
    })();
    return this.#chainIdPromise;
  }

  // Memoized verifier, built lazily once chainId is known.
  #getTrustedVerifier(chainId: string): TrustedVerifier {
    if (this.#trustedVerifier === undefined) {
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
    return this.#trustedVerifier;
  }
}
