// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider. Open mode sends
// through ethers' FetchRequest (retry, redirect, gzip, processFunc) and hands the
// answer to the core open-mode session, which bootstraps, verifies and decodes it.

import {
  checkOptions,
  createOpenSession,
  InvalidOption,
  LazyConfidentialClient,
  type OpenSession,
} from "@w3tech.io/vrpc-core";
import type { ConfidentialInfo } from "@w3tech.io/vrpc-core/confidential";
import {
  type FetchRequest,
  type FetchResponse,
  type JsonRpcPayload,
  JsonRpcProvider,
  type JsonRpcResult,
  Network,
} from "ethers";

import { fetchRequestTransport, sendConfidential } from "./confidential";
import type { VrpcOptions } from "./options";

interface Posted {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: Uint8Array;
  fetch: FetchResponse;
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
  readonly #session: OpenSession<Posted>;
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

    // In Ankr Confidential RPC mode the session only answers _detectNetwork from the pin.
    this.#session = createOpenSession({
      chainId,
      attestationUrl,
      headers: attestationHeaders,
      fetch: attestationFetch,
      replayWindowMs,
      pubkeyCacheTtlMs,
      hardwareVerifier,
      logger,
      // assertOk throws for every non-2xx answer; a signed one reaches it only after verify.
      httpError: ({ fetch }: Posted) => {
        try {
          fetch.assertOk();
        } catch (err) {
          return err;
        }
        return new Error(`HTTP ${fetch.statusCode}`);
      },
    });
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

  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
    if (this.#confidential !== undefined) return sendConfidential(this.#confidential, payload);
    const results = (await this.#session.send(payload, (body) => this.#post(body))) as
      | JsonRpcResult
      | Array<JsonRpcResult>;
    return Array.isArray(results) ? results : [results];
  }

  // A pinned CAIP-2 style id has no ethers Network representation and fails loud.
  override async _detectNetwork(): Promise<Network> {
    return Network.from(BigInt(await this.#session.chainId((body) => this.#post(body))));
  }

  async #post(body: Uint8Array): Promise<Posted> {
    const request = this._getConnection();
    request.body = body;
    request.setHeader("content-type", "application/json");
    const fetch = await request.send();
    return {
      status: fetch.statusCode,
      headers: fetch.headers,
      body: fetch.body ?? new Uint8Array(),
      fetch,
    };
  }
}
