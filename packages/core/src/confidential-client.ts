// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client: attest and pin a node, seal each request to it, verify and open the answer.

import type { HardwareVerifier } from "@w3tech.io/dstack-verify";

import {
  decodeInnerResponse,
  encodeInnerRequest,
  type InnerRequest,
  type InnerResponse,
  NULL_BODY_STATUSES,
} from "./bhttp";
import {
  ConfidentialSignerMismatch,
  InternalError,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
  VrpcError,
} from "./errors";
import type { Logger } from "./logger";
import { attestPin, errorKind, type Pin, PinSlot } from "./node-session";
import { openResponse, type SealedRequest, sealRequest } from "./ohttp";
import { checkOptions, resolveSeams, withoutContentType } from "./options";
import { type ConfidentialTransport, guardedSend, MAX_RESPONSE_BYTES } from "./transport";
import { getHeader, type VerifyResponseOptions, verifyResponse } from "./verify";

export interface ConfidentialClientOptions {
  /** The vRPC endpoint, with the API key in the path or passed in `headers`. */
  url: string;
  chainId: string;
  /** Sent on every outer request; a `content-type` entry is ignored. */
  headers?: Record<string, string> | undefined;
  /** Positive, finite integer milliseconds; anything else throws `InvalidOption`. */
  replayWindowMs?: number | undefined;
  /**
   * Positive, finite integer milliseconds; anything else, `Infinity` included, throws `InvalidOption`.
   * Use a large value for a long-lived pin.
   */
  pubkeyCacheTtlMs?: number | undefined;
  logger?: Logger | undefined;
  hardwareVerifier?: HardwareVerifier | undefined;
  /**
   * Carries the attestation GET, the sealed requests and the default hardware verifier's call;
   * `transport` and `hardwareVerifier` replace it for their legs.
   */
  fetch?: typeof fetch | undefined;
  transport?: ConfidentialTransport | undefined;
}

/** The node the client is pinned to. */
export interface ConfidentialInfo {
  nodeId: string;
  /** Lowercase `0x` hex Ed25519 key the node signs with. */
  pubkey: string;
  /**
   * Reported by the node. The default hardware verifier checks it against the quote's `mr_config_id`;
   * with a custom `hardwareVerifier` it is checked only if that verifier does.
   */
  composeHash: string;
  /** Unix ms when the attestation was verified. */
  attestedAt: number;
}

export type ConfidentialResponse = InnerResponse;

const OHTTP_REQUEST = "message/ohttp-req";
const OHTTP_RESPONSE = "message/ohttp-res";

// After a send, only an answer that blames the node or its key drops the pin.
function evictsPin(err: VrpcError): boolean {
  if (err instanceof TransportFailed || err instanceof StaleTimestamp) return false;
  if (err instanceof RequestRejected) return err.status !== 413 && err.status !== 429;
  return true;
}

function infoOf(pin: Pin): ConfidentialInfo {
  return {
    nodeId: pin.nodeId,
    pubkey: pin.pubkeyHex,
    composeHash: pin.composeHash,
    attestedAt: pin.attestedAt,
  };
}

function mediaType(value: string | null): string {
  return (value?.split(";", 1)[0] ?? "").trim().toLowerCase();
}

/** Client for Ankr Confidential RPC: only ciphertext leaves the process, and only answers signed by the attested node are opened. */
export class ConfidentialClient {
  readonly #confidentialUrl: string;
  readonly #headers: Record<string, string>;
  readonly #transport: ConfidentialTransport;
  readonly #logger: Logger | undefined;
  readonly #verifyOptions: VerifyResponseOptions;
  readonly #slot: PinSlot;

  constructor(options: ConfidentialClientOptions) {
    this.#headers = withoutContentType(options.headers);
    const { urls, chainId, replayWindowMs, pubkeyCacheTtlMs } = checkOptions(
      { ...options, headers: this.#headers },
      ["url", "chainId"],
    );
    this.#confidentialUrl = urls.confidentialUrl;
    const { transport, hardwareVerifier, logger, verifyOptions } = resolveSeams(
      options,
      chainId,
      replayWindowMs,
    );
    this.#transport = transport;
    this.#logger = logger;
    this.#verifyOptions = verifyOptions;
    const headers = this.#headers;
    this.#slot = new PinSlot(
      () =>
        attestPin({
          transport,
          attestationUrl: urls.attestationUrl,
          headers: { ...headers },
          hardwareVerifier,
          logger,
        }),
      pubkeyCacheTtlMs,
    );
  }

  /** Attests now unless a valid pin exists, and returns the pinned node. */
  async ready(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo> {
    return infoOf(await this.#slot.acquire(options?.signal));
  }

  /** The pinned node, or `undefined` before the first attestation and after the pin expired or was dropped. */
  getConfidentialInfo(): ConfidentialInfo | undefined {
    const pin = this.#slot.current();
    return pin === undefined ? undefined : infoOf(pin);
  }

  /**
   * Sends one inner request sealed to the pinned node; any inner status is returned, not thrown.
   * An abort rejects with `signal.reason`; aborting after the request was sent leaves the outcome unknown.
   * Any other failure that is not a `VrpcError` is `InternalError`, with the original value as `cause`.
   * Every failure raised before the request was handed to the transport has `executed: "no"`.
   */
  async request(
    inner: InnerRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ConfidentialResponse> {
    const signal = options?.signal;
    let pin: Pin | undefined;
    let sent = false;
    try {
      if (signal?.aborted) throw signal.reason;
      const bhttp = await encodeInnerRequest(inner);
      pin = await this.#slot.acquire(signal);
      const sealed = await sealRequest(pin.nodeKey, bhttp);
      if (signal?.aborted) throw signal.reason;
      sent = true;
      return await this.#exchange(pin, sealed, signal);
    } catch (err) {
      if (signal?.aborted && err === signal.reason) throw err;
      const e = err instanceof VrpcError ? err : new InternalError({ cause: err });
      if (!sent) e.executed = "no";
      else if (pin !== undefined && evictsPin(e)) {
        this.#slot.evict(pin);
        this.#logger?.debug("confidential.evict", { nodeId: pin.nodeId, kind: errorKind(e) });
      }
      throw e;
    }
  }

  async #exchange(
    pin: Pin,
    sealed: SealedRequest,
    signal: AbortSignal | undefined,
  ): Promise<ConfidentialResponse> {
    const started = Date.now();
    this.#logger?.debug("confidential.request", {
      nodeId: pin.nodeId,
      requestBytes: sealed.body.byteLength,
    });
    const response = await guardedSend(
      this.#transport,
      {
        method: "POST",
        url: `${this.#confidentialUrl}?node_id=${encodeURIComponent(pin.nodeId)}`,
        headers: { ...this.#headers, "content-type": OHTTP_REQUEST },
        body: sealed.body,
        ...(signal === undefined ? {} : { signal }),
        maxBytes: MAX_RESPONSE_BYTES,
      },
      (tooLarge, cause) =>
        new TransportFailed(tooLarge ? "too-large" : "network", pin.nodeId, { cause }),
    );
    const contentType = mediaType(getHeader(response.headers, "content-type"));
    this.#logger?.debug("confidential.response", {
      nodeId: pin.nodeId,
      status: response.status,
      contentType,
      responseBytes: response.body.byteLength,
      durationMs: Date.now() - started,
    });

    const { status } = response;
    const reported = contentType === "" ? undefined : contentType;
    if (
      !Number.isInteger(status) ||
      status < 200 ||
      (status >= 300 && status <= 399) ||
      status > 599 ||
      NULL_BODY_STATUSES.has(status)
    ) {
      throw new UnexpectedResponse(status, pin.nodeId, reported);
    }
    if (contentType !== OHTTP_RESPONSE) {
      if (status >= 400 && status <= 499) throw new RequestRejected(status, pin.nodeId, reported);
      throw new UnexpectedResponse(status, pin.nodeId, reported);
    }
    const verified = await verifyResponse(
      sealed.body,
      response.body,
      response.headers,
      this.#verifyOptions,
    );
    if (verified.verification.pubkeyHex !== pin.pubkeyHex) {
      throw new ConfidentialSignerMismatch(pin.pubkeyHex, verified.verification.pubkeyHex);
    }

    return decodeInnerResponse(await openResponse(sealed.opener, response.body));
  }
}
