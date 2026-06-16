// VrpcProvider — verifiable drop-in for ethers' JsonRpcProvider (Phase 30).
//
// The ONLY override is `JsonRpcApiProvider._send`, the single HTTP chokepoint
// every JSON-RPC call funnels through (getBalance, call, getBlock, getLogs,
// broadcastTransaction, polling, batches — all of it). We mirror stock `_send`
// (ethers.js src.ts/providers/provider-jsonrpc.ts:1266-1278) but capture the
// raw, content-decoded `response.body` BEFORE `JSON.parse` and feed it, with the
// exact request bytes ethers POSTed, into vrpc-core's `verifyResponse`. Native
// batching is preserved (we do NOT pin batchMaxCount=1): the single-or-array
// payload is verified once over the whole body, and ethers' drain loop
// correlates the array results back to callers by id.
//
// Verification is fail-closed by default: a `VerificationError` propagates out
// of `_send`. Permissive mode (opt-in) downgrades it to a logged warning and
// passes the parsed body through. Any non-VerificationError (e.g. ethers
// SERVER_ERROR from `assertOk`) always propagates in both modes.

import type { PinnedAllowlist } from "@ankr.com/dstack-verify";
import {
  MalformedHeader,
  TrustedVerifier,
  VerificationError,
  verifyResponse,
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

import type { VrpcOptions, VrpcVerification } from "./options";

const defaultLogger = (msg: string, err: unknown): void => {
  console.warn(`[vrpc-ethers] ${msg}`, err);
};

/** Empty pinned allowlist default — the v5.0 mock verifier never inspects it (A3). */
const EMPTY_ALLOWLIST: PinnedAllowlist = {
  composeHashes: [],
  mrtd: "",
  rtmr0: "",
  rtmr1: "",
  rtmr2: "",
  osImageHashes: [],
  kmsIdentities: [],
};

/** Attestation-routing + forwarding config captured from VrpcOptions (opt-in via attestationBaseUrl+chainSlug). */
interface AttestationRouting {
  sharkBase: string;
  chain: string;
  allowlist: PinnedAllowlist;
  pubkeyCacheTtl?: number;
  tcb?: import("@ankr.com/dstack-verify").TcbPolicy;
  pccsUrl?: string;
  apiKey?: string;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  replayWindowMs?: number;
}

/** Narrow a 2nd constructor arg to a chainId Numeric (vs. an options object). */
function isChainIdArg(value: unknown): value is number | bigint {
  return typeof value === "number" || typeof value === "bigint";
}

/**
 * A `JsonRpcProvider` that Ed25519-verifies every JSON-RPC response over its raw
 * content-decoded bytes before the value reaches the caller.
 *
 * Drop-in: `new VrpcProvider(url)` substitutes for `new JsonRpcProvider(url)`.
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
  readonly #verification: VrpcVerification;
  readonly #replayWindowMs: number | undefined;
  readonly #logger: (msg: string, err: unknown) => void;
  // Opt-in lazy-attestation routing config (set only when attestationBaseUrl+chainSlug present).
  readonly #attestationRouting: AttestationRouting | undefined;
  // ONE TrustedVerifier per provider (cache lives for the provider lifetime).
  // Built synchronously on the explicit-pin path; memoized lazily on the
  // auto-derive path (the seam's chainId is required, so it cannot exist before
  // #resolveChainId runs).
  #trustedVerifier: TrustedVerifier | undefined;

  constructor(url: string | FetchRequest, chainId: number | bigint, options?: VrpcOptions);
  constructor(url: string | FetchRequest, options?: VrpcOptions);
  constructor(
    url: string | FetchRequest,
    chainIdOrOptions?: number | bigint | VrpcOptions,
    maybeOptions: VrpcOptions = {},
  ) {
    // Normalize the overloads: a Numeric 2nd arg is the explicit chainId pin;
    // anything else is the options object (which MAY carry `chainId`).
    let options: VrpcOptions;
    let explicitChainId: number | bigint | undefined;
    if (isChainIdArg(chainIdOrOptions)) {
      explicitChainId = chainIdOrOptions;
      options = maybeOptions;
    } else {
      options = chainIdOrOptions ?? {};
      explicitChainId = options.chainId;
    }

    const {
      verification = "strict",
      replayWindowMs,
      logger,
      chainId: _drop,
      attestationBaseUrl,
      chainSlug,
      pubkeyCacheTtlMs,
      allowlist,
      tcb,
      pccsUrl,
      apiKey,
      headers,
      fetch: attFetch,
      ...ethersOpts
    } = options;

    // Coerce to bigint WITHOUT a number round-trip: EVM chain ids may exceed
    // Number.MAX_SAFE_INTEGER (2^53−1) and the pre-image binds the full u64
    // range, so widening through `number` would lose precision and reject
    // intact responses (false BadSignature). `Network.from` accepts Numeric
    // (number | bigint), so passing the bigint is compatible.
    const chainIdBig = explicitChainId != null ? BigInt(explicitChainId) : undefined;

    if (chainIdBig != null) {
      // Explicit-pin path (unchanged behavior): pin the network so the provider
      // does not fire an eth_chainId round-trip before the first real call —
      // _detectNetwork early-returns and #resolveChainId NEVER runs (ZERO
      // bootstrap fetch). `staticNetwork` only skips the round-trip; it does NOT
      // weaken the signature binding. Spread ethersOpts FIRST so staticNetwork
      // can never be overridden away (LO-01).
      super(url, Network.from(chainIdBig), { ...ethersOpts, staticNetwork: true });
      this.#chainId = chainIdBig;
    } else {
      // Auto-derive path: no network pin, no staticNetwork. The chain id is
      // lazily resolved by #resolveChainId on first verifying _send (and
      // _detectNetwork is overridden to feed the same resolver), so ethers never
      // runs its own eth_chainId through the verifying _send.
      super(url, undefined, ethersOpts);
      this.#chainId = undefined;
    }

    this.#verification = verification;
    this.#replayWindowMs = replayWindowMs;
    this.#logger = logger ?? defaultLogger;

    // Opt-in attestation routing: engage ONLY when BOTH attestationBaseUrl and
    // chainSlug are set. The public surface stays a strict superset — without
    // this pair the provider behaves byte-identically to before (plain
    // verifyResponse).
    if (attestationBaseUrl !== undefined && chainSlug !== undefined) {
      this.#attestationRouting = {
        sharkBase: attestationBaseUrl,
        chain: chainSlug,
        allowlist: allowlist ?? EMPTY_ALLOWLIST,
        ...(pubkeyCacheTtlMs === undefined ? {} : { pubkeyCacheTtl: pubkeyCacheTtlMs }),
        ...(tcb === undefined ? {} : { tcb }),
        ...(pccsUrl === undefined ? {} : { pccsUrl }),
        ...(apiKey === undefined ? {} : { apiKey }),
        ...(headers === undefined ? {} : { headers }),
        ...(attFetch === undefined ? {} : { fetch: attFetch }),
        ...(replayWindowMs === undefined ? {} : { replayWindowMs }),
      };
      // Explicit-pin path: chainId is known synchronously → build the single
      // TrustedVerifier now (its cache lives for the provider lifetime). On the
      // auto-derive path #chainId is undefined here; defer the build to the
      // first _send after #resolveChainId (see #getTrustedVerifier).
      if (this.#chainId != null) {
        this.#trustedVerifier = this.#buildTrustedVerifier(this.#chainId);
      }
    } else {
      this.#attestationRouting = undefined;
    }
  }

  /** Build the per-instance TrustedVerifier for a resolved chainId. */
  #buildTrustedVerifier(chainId: bigint): TrustedVerifier {
    const routing = this.#attestationRouting as AttestationRouting;
    return new TrustedVerifier({
      chainId,
      attestationBaseUrl: routing.sharkBase,
      chainSlug: routing.chain,
      allowlist: routing.allowlist,
      ...(routing.replayWindowMs === undefined ? {} : { replayWindowMs: routing.replayWindowMs }),
      ...(routing.pubkeyCacheTtl === undefined ? {} : { pubkeyCacheTtlMs: routing.pubkeyCacheTtl }),
      ...(routing.tcb === undefined ? {} : { tcb: routing.tcb }),
      ...(routing.pccsUrl === undefined ? {} : { pccsUrl: routing.pccsUrl }),
      ...(routing.apiKey === undefined ? {} : { apiKey: routing.apiKey }),
      ...(routing.headers === undefined ? {} : { headers: routing.headers }),
      ...(routing.fetch === undefined ? {} : { fetch: routing.fetch }),
    });
  }

  /**
   * Return the memoized per-instance TrustedVerifier when the seam is engaged,
   * building it lazily (auto-derive path) once `chainId` is known. Returns
   * undefined when the seam is not configured (plain verifyResponse path).
   */
  #getTrustedVerifier(chainId: bigint): TrustedVerifier | undefined {
    if (this.#attestationRouting === undefined) {
      return undefined;
    }
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
      const cid = BigInt(parsed.result);
      // Self-consistent verification: verify the eth_chainId response using its
      // OWN claimed result as the chainId binding. It only verifies if the node
      // signed for exactly C — a tampered/forged/unsigned bootstrap fails FAST
      // here. Fail-closed: do NOT set #chainId, do NOT fall back to unverified.
      try {
        await verifyResponse(requestBytes, rawResponseBytes, response.headers, {
          chainId: cid,
          ...(this.#replayWindowMs != null ? { replayWindowMs: this.#replayWindowMs } : {}),
        });
      } catch (err) {
        if (err instanceof VerificationError) {
          err.message = `auto-derived chainId could not be verified (pass \`chainId\` explicitly): ${err.message}`;
        }
        throw err;
      }
      this.#chainId = cid;
      return cid;
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
    // Single choke point: resolve the chain id (cheap memoized read after the
    // first derive, or the synchronously-set pin) BEFORE building the pre-image.
    const chainId = this.#chainId ?? (await this.#resolveChainId());

    // Serialize ONCE: the same bytes are POSTed and fed to verify, so the
    // pre-image reconstruction matches what the sidecar signed.
    const requestBody = JSON.stringify(payload);
    const requestBytes = toUtf8Bytes(requestBody);

    const request = this._getConnection();
    request.body = requestBody;
    request.setHeader("content-type", "application/json");

    const response = await request.send();
    response.assertOk(); // 4xx/5xx → ethers SERVER_ERROR (not a VerificationError).

    // Raw, content-decoded bytes exactly as signed. An empty body carries no
    // vRPC-* headers → MissingHeader fails closed (no bespoke error class).
    const rawResponseBytes = response.body ?? new Uint8Array();

    let downgraded = false;
    try {
      // Route the NORMAL verify call through the lazy-attestation routing when it
      // is engaged (attestationBaseUrl+chainSlug set); otherwise verify directly.
      // The chainId bootstrap (#resolveChainId) ALWAYS stays on plain verifyResponse.
      const verifier = this.#getTrustedVerifier(chainId);
      if (verifier !== undefined) {
        await verifier.verify(requestBytes, rawResponseBytes, response.headers);
      } else {
        await verifyResponse(requestBytes, rawResponseBytes, response.headers, {
          chainId,
          ...(this.#replayWindowMs != null ? { replayWindowMs: this.#replayWindowMs } : {}),
        });
      }
    } catch (err) {
      if (err instanceof VerificationError) {
        if (this.#verification === "strict") {
          throw err;
        }
        downgraded = true;
        this.#logger("verification failed (permissive mode, passing through)", err);
      } else {
        throw err;
      }
    }

    // Parse ONLY after verification. Normalize to the array ethers' drain loop
    // correlates by id (single payload → length-1 array). In permissive mode a
    // body that failed verification may also be invalid JSON (e.g. a truncated
    // response); surface that parse failure through the same logger so the
    // permissive consumer sees one coherent diagnostic rather than an opaque
    // SyntaxError. The error still propagates (fail-closed; no unverified data
    // is returned silently). (LO-03)
    let resp: unknown;
    try {
      resp = JSON.parse(toUtf8String(rawResponseBytes));
    } catch (err) {
      if (downgraded) {
        this.#logger("permissive passthrough: response body is not valid JSON", err);
      }
      throw err;
    }
    if (!Array.isArray(resp)) {
      resp = [resp];
    }
    return resp as Array<JsonRpcResult>;
  }
}
