// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider.
//
// The ONLY override is `JsonRpcApiProvider._send`, the single HTTP chokepoint
// every JSON-RPC call funnels through (getBalance, call, getBlock, getLogs,
// broadcastTransaction, polling, batches — all of it). We mirror stock `_send`
// (ethers.js src.ts/providers/provider-jsonrpc.ts:1266-1278) but capture the
// raw, content-decoded `response.body` BEFORE `JSON.parse` and feed it, with the
// exact request bytes ethers POSTed, into vrpc-core's verify seam. Native
// batching is preserved (we do NOT pin batchMaxCount=1): the single-or-array
// payload is verified once over the whole body, and ethers' drain loop
// correlates the array results back to callers by id.
//
// Verification is always fail-closed: a `VerificationError` propagates out of
// `_send`; no unverified data is ever returned. Any non-VerificationError (e.g.
// ethers SERVER_ERROR from `assertOk`) propagates too. This is the single
// authoritative statement of the fail-closed invariant for the package.

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

/**
 * Drop keys whose value is `undefined`. Required because
 * `exactOptionalPropertyTypes` forbids assigning an explicit `undefined` to an
 * optional (`x?: T`) slot — so every absent option must be omitted, not passed
 * as `undefined`. The `as T` is the single audited spot asserting the pruned
 * shape still satisfies `T`.
 */
function pruneUndefined<T extends object>(obj: { [K in keyof T]: T[K] | undefined }): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

/**
 * A `JsonRpcProvider` that Ed25519-verifies every JSON-RPC response over its raw
 * content-decoded bytes before the value reaches the caller, and lazily attests
 * the signing pubkey via TDX on first use (per pubkey, TTL-cached).
 *
 * Drop-in: `new VrpcProvider(url)` substitutes for `new JsonRpcProvider(url)`.
 * The user passes ONE endpoint URL (e.g. `https://rpc.ankr.com/arbitrum`); the
 * SDK owns the `_vrpc` route suffix and the `/attestation` sub-route
 * (`deriveVrpcUrls`), so the provider POSTs to `…/arbitrum_vrpc` and fetches
 * attestations from `…/arbitrum_vrpc/attestation`.
 *
 * The chain id bound into the signed pre-image is OPTIONAL — omit it and the
 * provider lazily derives it from a SIGNED `eth_chainId` response on first use,
 * verifying that signature self-consistently (the response's own `result` IS
 * the chainId, so it only verifies if the node really signed for that chain). A
 * tampered/forged/unsigned bootstrap fails FAST with a `VerificationError`;
 * there is no unverified fallback. Passing it explicitly — `new
 * VrpcProvider(url, chainId)` — is STRONGLY RECOMMENDED: it pins to YOUR
 * expected chain (catching a wrong-node / wrong-URL misconfig that auto-derive,
 * which trusts the node's self-reported chain, would not) and skips the
 * bootstrap round-trip.
 *
 * `chainId` is the middle positional arg (ethers parity); to pass only vRPC
 * options on the auto-derive path, leave it explicit `undefined`:
 * `new VrpcProvider(url, undefined, { allowlist })`.
 */
export class VrpcProvider extends JsonRpcProvider {
  // Mutable: undefined until resolved (lazy derive) or set synchronously (pin).
  #chainId: bigint | undefined;
  // Memoized in-flight bootstrap so N concurrent first calls share ONE fetch.
  #chainIdPromise: Promise<bigint> | null = null;
  // Builds the per-instance TrustedVerifier given the chainId — the ONE field
  // bound late, because it may be auto-derived AFTER construction. Closes over
  // the verifier options resolved in the constructor (verification is always on).
  readonly #makeVerifier: (chainId: bigint) => TrustedVerifier;
  // ONE TrustedVerifier per provider (cache lives for the provider lifetime).
  // Built synchronously on the explicit-pin path; memoized lazily on the
  // auto-derive path (chainId is required, so it cannot exist before
  // #resolveChainId runs).
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

    // Derive the `_vrpc` RPC route + `/attestation` sub-route from the single
    // user URL once. For a FetchRequest, clone it and rewrite its url to the
    // rpcUrl so the consumer's auth/headers ride along to the `_vrpc` route.
    const urls = deriveVrpcUrls(typeof url === "string" ? url : url.url);
    const attestationUrl = urls.attestationUrl;
    let superUrl: string | FetchRequest = urls.rpcUrl;
    if (typeof url !== "string") {
      const clone = url.clone();
      clone.url = urls.rpcUrl;
      superUrl = clone;
    }

    // Coerce to bigint WITHOUT a number round-trip: EVM chain ids may exceed
    // Number.MAX_SAFE_INTEGER (2^53−1) and the pre-image binds the full u64
    // range, so widening through `number` would lose precision and reject
    // intact responses (false BadSignature). `Network.from` accepts Numeric
    // (number | bigint), so passing the bigint is compatible.
    const chainId = chainIdArg != null ? BigInt(chainIdArg) : undefined;

    // staticNetwork (pin path only) makes ethers set #network synchronously and
    // skip its startup eth_chainId probe — does NOT weaken the binding. ethersOpts
    // is spread FIRST so a user-supplied staticNetwork cannot override ours.
    const superOptions = chainId != null ? { ...ethersOpts, staticNetwork: true } : ethersOpts;
    super(superUrl, chainId, superOptions);

    this.#chainId = chainId;
    // Capture the resolved verifier options behind a chainId -> TrustedVerifier
    // factory. allowlist defaults to EMPTY_ALLOWLIST (v5.0 mock passes via
    // allowInsecureMock); absent options are dropped, not forwarded as undefined
    // (see pruneUndefined). chainId is the only late-bound field, so it is the
    // factory's parameter rather than part of the stored options.
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
    // Pin path: chainId known synchronously → build the single TrustedVerifier
    // now (its cache lives for the provider lifetime). Auto-derive: deferred to
    // the first _send after #resolveChainId (see #getTrustedVerifier).
    if (chainId != null) {
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
  }

  /**
   * Verifying override of the JSON-RPC HTTP chokepoint: POST via `#post`, verify
   * the raw bytes (single path: Ed25519 + lazy attestation), then parse.
   */
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
    const { requestBytes, rawResponseBytes, headers } = await this.#post(payload);

    // Verify the RAW content-decoded body BEFORE parsing.
    const chainId = this.#chainId ?? (await this.#resolveChainId());
    await this.#getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, headers);

    const parsed = JSON.parse(toUtf8String(rawResponseBytes)) as
      | JsonRpcResult
      | Array<JsonRpcResult>;
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  /**
   * Override so ethers never builds its own `eth_chainId` payload through the
   * verifying `_send`. Both this and the `_send` choke point feed the ONE
   * memoized resolver (#resolveChainId), so detection and verification agree.
   */
  override async _detectNetwork(): Promise<Network> {
    return Network.from(await this.#resolveChainId());
  }

  /**
   * POST a JSON-RPC payload through the configured connection — mirrors stock
   * `JsonRpcProvider._send` up to the raw response, returning the inputs the verify
   * seam needs (exact request bytes, raw content-decoded response bytes, response
   * headers) that stock's `response.bodyJson` discards. Shared by `_send` and the
   * chainId bootstrap (`#resolveChainId`).
   */
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

  /**
   * Lazily derive the chain id via ONE SELF-CONSISTENTLY VERIFIED `eth_chainId`
   * bootstrap. The promise is assigned synchronously BEFORE awaiting so N
   * concurrent first calls share a single in-flight fetch (memoization). The
   * bootstrap does its OWN request via `_getConnection()` (a fresh
   * `FetchRequest`) — NOT the verifying `_send` — and its result is used ONLY to
   * set the chainId constant; it is NEVER returned to the caller.
   *
   * The `eth_chainId` response is itself a signed vRPC response whose `result`
   * IS the chainId. We parse `C = BigInt(result)` then verify with `{ chainId: C }`:
   * the signature is over a pre-image binding chainId=C, so it only verifies if
   * the node really signed for C (self-consistent). On any verify failure
   * (BadSignature / MissingHeader / tampered / unsigned) the error PROPAGATES
   * (fail-FAST at bootstrap) — we never set the chainId and never fall back to an
   * unverified value.
   */
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

      // Verify the RAW content-decoded body BEFORE parsing.
      const chainId = parseChainId(rawResponseBytes);
      await this.#getTrustedVerifier(chainId).verify(requestBytes, rawResponseBytes, headers);

      this.#chainId = chainId;
      return chainId;
    })();
    return this.#chainIdPromise;
  }

  /**
   * Return the memoized per-instance TrustedVerifier, building it lazily
   * (auto-derive path) once `chainId` is known.
   */
  #getTrustedVerifier(chainId: bigint): TrustedVerifier {
    if (this.#trustedVerifier === undefined) {
      this.#trustedVerifier = this.#makeVerifier(chainId);
    }
    return this.#trustedVerifier;
  }
}
