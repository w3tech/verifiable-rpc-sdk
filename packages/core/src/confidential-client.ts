// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client: attest and pin a node, seal each request to it, verify and open the answer.

import { createCloudVerifier, type HardwareVerifier } from "@w3tech.io/dstack-verify";

import {
  decodeInnerResponse,
  encodeInnerRequest,
  type InnerRequest,
  type InnerResponse,
  MalformedInnerResponse,
  NULL_BODY_STATUSES,
} from "./bhttp";
import {
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  InternalError,
  MalformedConfidentialResponse,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
  VrpcError,
} from "./errors";
import { defaultLogger, type Logger, safeLogger } from "./logger";
import { attestPin, errorKind, type Pin, PinSlot } from "./node-session";
import {
  OhttpError,
  openResponse,
  type ResponseOpener,
  type SealedRequest,
  sealRequest,
} from "./ohttp";
import { checkOptions, withoutContentType } from "./options";
import {
  type ConfidentialTransport,
  defaultTransport,
  guardedSend,
  MAX_RESPONSE_BYTES,
} from "./transport";
import { getHeader, verifyResponse } from "./verify";

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
  /** Used by the default hardware verifier's call; ignored with a custom `hardwareVerifier`. */
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

async function open(opener: ResponseOpener, body: Uint8Array): Promise<InnerResponse> {
  let inner: Uint8Array;
  try {
    inner = await openResponse(opener, body);
  } catch (err) {
    if (err instanceof OhttpError) {
      if (err.reason === "response-too-short") throw new MalformedConfidentialResponse("too-short");
      throw new ConfidentialDecryptFailed();
    }
    throw err;
  }
  try {
    return await decodeInnerResponse(inner);
  } catch (err) {
    if (err instanceof MalformedInnerResponse) throw new MalformedConfidentialResponse(err.reason);
    throw err;
  }
}

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
  readonly #chainId: string;
  readonly #replayWindowMs: number | undefined;
  readonly #confidentialUrl: string;
  readonly #headers: Record<string, string>;
  readonly #transport: ConfidentialTransport;
  readonly #logger: Logger;
  readonly #slot: PinSlot;

  constructor(options: ConfidentialClientOptions) {
    this.#headers = withoutContentType(options.headers);
    const { urls, chainId, replayWindowMs, pubkeyCacheTtlMs } = checkOptions(
      { ...options, headers: this.#headers },
      ["url", "chainId"],
    );
    this.#chainId = chainId;
    this.#replayWindowMs = replayWindowMs;
    this.#confidentialUrl = urls.confidentialUrl;
    const transport = options.transport ?? defaultTransport;
    this.#transport = transport;
    const hardwareVerifier =
      options.hardwareVerifier ??
      createCloudVerifier(options.fetch === undefined ? {} : { fetch: options.fetch });
    const logger = options.logger ? safeLogger(options.logger) : defaultLogger;
    this.#logger = logger;
    const headers = this.#headers;
    this.#slot = new PinSlot(
      (signal) =>
        attestPin({
          transport,
          attestationUrl: urls.attestationUrl,
          headers: { ...headers },
          hardwareVerifier,
          logger,
          ...(signal === undefined ? {} : { signal }),
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
        this.#logger.debug("confidential.evict", { nodeId: pin.nodeId, kind: errorKind(e) });
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
    this.#logger.debug("confidential.request", {
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
      },
      MAX_RESPONSE_BYTES,
      (reason, cause) => new TransportFailed(reason, pin.nodeId, { cause }),
    );
    const contentType = mediaType(getHeader(response.headers, "content-type"));
    this.#logger.debug("confidential.response", {
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
    const verified = await verifyResponse(sealed.body, response.body, response.headers, {
      chainId: this.#chainId,
      ...(this.#replayWindowMs === undefined ? {} : { replayWindowMs: this.#replayWindowMs }),
      ...(this.#logger === defaultLogger ? {} : { logger: this.#logger }),
    });
    if (verified.verification.pubkeyHex !== pin.pubkeyHex) {
      throw new ConfidentialSignerMismatch(pin.pubkeyHex, verified.verification.pubkeyHex);
    }

    return open(sealed.opener, response.body);
  }
}
