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

import { VerificationError, verifyResponse } from "@ankr.com/vrpc-core";
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

/**
 * A `JsonRpcProvider` that Ed25519-verifies every JSON-RPC response over its raw
 * content-decoded bytes before the value reaches the caller.
 *
 * Drop-in: `new VrpcProvider(url, chainId)` substitutes for
 * `new JsonRpcProvider(url)` with one extra argument (the chain id bound into
 * the signed pre-image).
 */
export class VrpcProvider extends JsonRpcProvider {
  readonly #chainId: bigint;
  readonly #verification: VrpcVerification;
  readonly #replayWindowMs: number | undefined;
  readonly #logger: (msg: string, err: unknown) => void;

  constructor(url: string | FetchRequest, chainId: number | bigint, options: VrpcOptions = {}) {
    const { verification = "strict", replayWindowMs, logger, ...ethersOpts } = options;
    // Coerce to bigint WITHOUT a number round-trip: EVM chain ids may exceed
    // Number.MAX_SAFE_INTEGER (2^53−1) and the pre-image binds the full u64
    // range, so widening through `number` would lose precision and reject
    // intact responses (false BadSignature). `Network.from` accepts Numeric
    // (number | bigint), so passing the bigint is compatible.
    const chainIdBig = BigInt(chainId);
    // Pin the network so the provider does not fire an eth_chainId round-trip
    // before the first real call — keeps the one-line ergonomics while still
    // binding chainId into the verify pre-image below. `staticNetwork` only
    // skips the round-trip; it does NOT weaken the signature binding. Spread
    // ethersOpts FIRST so staticNetwork can never be overridden away (LO-01).
    super(url, Network.from(chainIdBig), { ...ethersOpts, staticNetwork: true });

    this.#chainId = chainIdBig;
    this.#verification = verification;
    this.#replayWindowMs = replayWindowMs;
    this.#logger = logger ?? defaultLogger;
  }

  /**
   * Verifying override of the JSON-RPC HTTP chokepoint. Mirrors stock `_send`
   * but verifies the raw response bytes before parsing.
   */
  override async _send(
    payload: JsonRpcPayload | Array<JsonRpcPayload>,
  ): Promise<Array<JsonRpcResult>> {
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

    try {
      await verifyResponse(requestBytes, rawResponseBytes, response.headers, {
        chainId: this.#chainId,
        ...(this.#replayWindowMs != null ? { replayWindowMs: this.#replayWindowMs } : {}),
      });
    } catch (err) {
      if (err instanceof VerificationError) {
        if (this.#verification === "strict") {
          throw err;
        }
        this.#logger("verification failed (permissive mode, passing through)", err);
      } else {
        throw err;
      }
    }

    // Parse ONLY after verification. Normalize to the array ethers' drain loop
    // correlates by id (single payload → length-1 array).
    let resp = JSON.parse(toUtf8String(rawResponseBytes));
    if (!Array.isArray(resp)) {
      resp = [resp];
    }
    return resp;
  }
}
