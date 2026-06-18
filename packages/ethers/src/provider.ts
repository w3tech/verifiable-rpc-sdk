// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider (Phase 30).
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
// ethers SERVER_ERROR from `assertOk`) propagates too.

import { EMPTY_ALLOWLIST, type PinnedAllowlist, type TcbPolicy } from "@ankr.com/dstack-verify";
import {
  deriveVrpcUrls,
  MalformedHeader,
  TrustedVerifier,
  VerificationError,
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

/** Verifier construction config captured from VrpcOptions. */
interface VerifierConfig {
  attestationUrl: string;
  allowlist: PinnedAllowlist;
  pubkeyCacheTtlMs?: number;
  tcb?: TcbPolicy;
  pccsUrl?: string;
  apiKey?: string;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  replayWindowMs?: number;
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
 */
export class VrpcProvider extends JsonRpcProvider {
  // Mutable: undefined until resolved (lazy derive) or set synchronously (pin).
  #chainId: bigint | undefined;
  // Memoized in-flight bootstrap so N concurrent first calls share ONE fetch.
  #chainIdPromise: Promise<bigint> | null = null;
  // Verifier construction config (always present — verification is always on).
  readonly #verifierConfig: VerifierConfig;
  // ONE TrustedVerifier per provider (cache lives for the provider lifetime).
  // Built synchronously on the explicit-pin path; memoized lazily on the
  // auto-derive path (the seam's chainId is required, so it cannot exist before
  // #resolveChainId runs).
  #trustedVerifier: TrustedVerifier | undefined;

  constructor(url: string | FetchRequest, chainId?: number | bigint, options: VrpcOptions = {}) {
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
    // user URL. For a string, derive and pass the rpcUrl to super. For a
    // FetchRequest, clone it and rewrite its url to the rpcUrl so the consumer's
    // auth/headers ride along to the `_vrpc` route.
    let superUrl: string | FetchRequest;
    let attestationUrl: string;
    if (typeof url === "string") {
      const urls = deriveVrpcUrls(url);
      superUrl = urls.rpcUrl;
      attestationUrl = urls.attestationUrl;
    } else {
      const urls = deriveVrpcUrls(url.url);
      const clone = url.clone();
      clone.url = urls.rpcUrl;
      superUrl = clone;
      attestationUrl = urls.attestationUrl;
    }

    // Coerce to bigint WITHOUT a number round-trip: EVM chain ids may exceed
    // Number.MAX_SAFE_INTEGER (2^53−1) and the pre-image binds the full u64
    // range, so widening through `number` would lose precision and reject
    // intact responses (false BadSignature). `Network.from` accepts Numeric
    // (number | bigint), so passing the bigint is compatible.
    const chainIdBig = chainId != null ? BigInt(chainId) : undefined;

    // ONE super(): a bigint chainId passes straight through as the Networkish —
    // ethers does Network.from internally (no number round-trip, MD-01) — and with
    // staticNetwork it sets #network synchronously and skips the startup eth_chainId
    // detection (does NOT weaken the binding). undefined leaves the network for lazy
    // auto-derive (#resolveChainId / the _detectNetwork override). staticNetwork is
    // set ONLY when pinning; ethersOpts is spread FIRST so a user staticNetwork can't
    // override ours away (LO-01).
    const superOptions = chainIdBig != null ? { ...ethersOpts, staticNetwork: true } : ethersOpts;
    super(superUrl, chainIdBig, superOptions);

    this.#chainId = chainIdBig;
    // Verification is ALWAYS active: the TrustedVerifier (plain Ed25519 verify +
    // lazy TDX attestation) is the single verify path; allowlist defaults to
    // EMPTY_ALLOWLIST (v5.0 mock passes via allowInsecureMock).
    this.#verifierConfig = {
      attestationUrl,
      allowlist: allowlist ?? EMPTY_ALLOWLIST,
      ...(pubkeyCacheTtlMs === undefined ? {} : { pubkeyCacheTtlMs }),
      ...(tcb === undefined ? {} : { tcb }),
      ...(pccsUrl === undefined ? {} : { pccsUrl }),
      ...(apiKey === undefined ? {} : { apiKey }),
      ...(headers === undefined ? {} : { headers }),
      ...(attestationFetch === undefined ? {} : { fetch: attestationFetch }),
      ...(replayWindowMs === undefined ? {} : { replayWindowMs }),
    };
    // Pin path: chainId known synchronously → build the single TrustedVerifier
    // now (its cache lives for the provider lifetime). Auto-derive: deferred to
    // the first _send after #resolveChainId (see #getTrustedVerifier).
    if (chainIdBig != null) {
      this.#trustedVerifier = this.#buildTrustedVerifier(chainIdBig);
    }
  }

  /** Build the per-instance TrustedVerifier for a resolved chainId. */
  #buildTrustedVerifier(chainId: bigint): TrustedVerifier {
    const cfg = this.#verifierConfig;
    return new TrustedVerifier({
      chainId,
      attestationUrl: cfg.attestationUrl,
      allowlist: cfg.allowlist,
      ...(cfg.replayWindowMs === undefined ? {} : { replayWindowMs: cfg.replayWindowMs }),
      ...(cfg.pubkeyCacheTtlMs === undefined ? {} : { pubkeyCacheTtlMs: cfg.pubkeyCacheTtlMs }),
      ...(cfg.tcb === undefined ? {} : { tcb: cfg.tcb }),
      ...(cfg.pccsUrl === undefined ? {} : { pccsUrl: cfg.pccsUrl }),
      ...(cfg.apiKey === undefined ? {} : { apiKey: cfg.apiKey }),
      ...(cfg.headers === undefined ? {} : { headers: cfg.headers }),
      ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
    });
  }

  /**
   * Return the memoized per-instance TrustedVerifier, building it lazily
   * (auto-derive path) once `chainId` is known.
   */
  #getTrustedVerifier(chainId: bigint): TrustedVerifier {
    if (this.#trustedVerifier === undefined) {
      this.#trustedVerifier = this.#buildTrustedVerifier(chainId);
    }
    return this.#trustedVerifier;
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
   * IS the chainId. We parse `C = BigInt(result)` then call `verifyResponse`
   * with `{ chainId: C }`: the signature is over a pre-image binding chainId=C,
   * so it only verifies if the node really signed for C (self-consistent). On
   * any verify failure (BadSignature / MissingHeader / tampered / unsigned) the
   * error PROPAGATES (fail-FAST at bootstrap) — we never set the chainId and
   * never fall back to an unverified value. A lying/forged/tampered bootstrap
   * fails immediately instead of deferring to a later BadSignature on a real
   * read.
   */
  #resolveChainId(): Promise<bigint> {
    if (this.#chainId != null) {
      return Promise.resolve(this.#chainId);
    }
    if (this.#chainIdPromise != null) {
      return this.#chainIdPromise;
    }
    this.#chainIdPromise = (async () => {
      const request = this._getConnection();
      const requestBody = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_chainId",
        params: [],
      });
      const requestBytes = toUtf8Bytes(requestBody);
      request.body = requestBody;
      request.setHeader("content-type", "application/json");
      const response = await request.send();
      response.assertOk();
      const rawResponseBytes = response.body ?? new Uint8Array();
      // A forged/truncated bootstrap body can be invalid JSON (raw SyntaxError)
      // or carry a missing/non-hex `result` (raw TypeError from BigInt). Both
      // throw BEFORE verifyResponse, so they would bypass the typed-error
      // wrapper and surface as opaque programmer errors. Coerce them to a
      // VerificationError (MalformedHeader) so a malformed bootstrap reads as a
      // verify failure, consistent with the fail-fast contract. (LOW-01/LOW-02)
      const rawText = toUtf8String(rawResponseBytes);
      let parsed: { result?: string };
      try {
        parsed = JSON.parse(rawText) as { result?: string };
      } catch (_err) {
        throw new MalformedHeader(
          "eth_chainId.result",
          rawText,
          "auto-derived chainId could not be parsed (pass `chainId` explicitly): bootstrap body is not valid JSON",
        );
      }
      if (typeof parsed.result !== "string" || !/^0x[0-9a-fA-F]+$/.test(parsed.result)) {
        throw new MalformedHeader(
          "eth_chainId.result",
          String(parsed.result),
          "auto-derived chainId could not be parsed (pass `chainId` explicitly): expected 0x-hex chain id",
        );
      }
      // BigInt() directly off the hex string — no number round-trip (a chain id
      // may exceed 2^53−1 and must bind the full u64 into the pre-image).
      const chainId = BigInt(parsed.result);
      // Verify-AND-attest the bootstrap through the SAME TrustedVerifier built for
      // this chainId. eth_chainId is itself a vRPC call: its response is verified
      // self-consistently (the signature must bind its OWN claimed chainId C) AND
      // the signing pubkey is attested (first-unseen pubkey → lazy TDX attestation,
      // cached so the first real read reuses it). A tampered/forged/unsigned
      // bootstrap, or an unattested signer, fails FAST here — fail-closed: #chainId
      // is NOT set and there is no unverified fallback.
      try {
        await this.#getTrustedVerifier(chainId).verify(
          requestBytes,
          rawResponseBytes,
          response.headers,
        );
      } catch (err) {
        if (err instanceof VerificationError) {
          err.message = `auto-derived chainId could not be verified (pass \`chainId\` explicitly): ${err.message}`;
        }
        throw err;
      }
      this.#chainId = chainId;
      return chainId;
    })();
    return this.#chainIdPromise;
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
   * Verifying override of the JSON-RPC HTTP chokepoint. Mirrors stock `_send`
   * but verifies the raw response bytes before parsing.
   */
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
    const chainId = this.#chainId ?? (await this.#resolveChainId());
    // Configure a POST connection for the requested method (serialize ONCE so the
    // exact POSTed bytes feed the pre-image).
    const request = this._getConnection();
    const requestBody = JSON.stringify(payload);
    request.body = requestBody;
    request.setHeader("content-type", "application/json");
    const response = await request.send();
    response.assertOk();

    // Verify the RAW content-decoded body BEFORE parsing (stock reads
    // `response.bodyJson`); null body → empty → MissingHeader, fail-closed.
    const rawResponseBytes = response.body ?? new Uint8Array();
    await this.#getTrustedVerifier(chainId).verify(
      toUtf8Bytes(requestBody),
      rawResponseBytes,
      response.headers,
    );
    let resp = JSON.parse(toUtf8String(rawResponseBytes));
    if (!Array.isArray(resp)) {
      resp = [resp];
    }

    return resp;
  }
}
