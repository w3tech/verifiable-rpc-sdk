// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client: attest and pin a node, seal each request to it, verify and open the answer.

import { createCloudVerifier, type HardwareVerifier } from "@w3tech.io/dstack-verify";

import {
  decodeInnerResponse,
  InvalidInnerRequest as EncoderRejected,
  encodeInnerRequest,
  type InnerRequest,
  type InnerResponse,
  MalformedInnerResponse,
} from "./bhttp";
import {
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  InvalidInnerRequest,
  MalformedAttestationResponse,
  MalformedConfidentialResponse,
  RequestRejected,
  TransportFailed,
  UnexpectedResponse,
} from "./errors";
import { defaultLogger, type Logger, safeLogger } from "./logger";
import { InvalidNodeKey } from "./node-key";
import { attestNode, type Pin, PinSlot } from "./node-session";
import {
  OhttpError,
  openResponse,
  type ResponseOpener,
  type SealedRequest,
  sealRequest,
} from "./ohttp";
import { validateChainId } from "./preimage";
import {
  type ConfidentialTransport,
  defaultTransport,
  MAX_RESPONSE_BYTES,
  type OuterResponse,
} from "./transport";
import { DEFAULT_PUBKEY_CACHE_TTL_MS } from "./trusted-verifier";
import { getHeader, PUBKEY_HEX_RE, verifyResponse } from "./verify";
import { deriveVrpcUrls, type VrpcUrls } from "./vrpc-url";

export interface ConfidentialClientOptions {
  /** The vRPC endpoint, with the API key in the path or passed in `headers`. */
  url: string;
  chainId: string;
  /** Sent on every outer request; a `content-type` entry is ignored. */
  headers?: Record<string, string>;
  replayWindowMs?: number;
  pubkeyCacheTtlMs?: number;
  logger?: Logger;
  hardwareVerifier?: HardwareVerifier;
  transport?: ConfidentialTransport;
}

export interface ConfidentialResponse {
  status: number;
  contentType?: string;
  body: Uint8Array;
}

const OHTTP_REQUEST = "message/ohttp-req";
const OHTTP_RESPONSE = "message/ohttp-res";
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

function withoutContentType(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => name.toLowerCase() !== "content-type"),
  );
}

async function encode(inner: InnerRequest): Promise<Uint8Array> {
  try {
    return await encodeInnerRequest(inner);
  } catch (err) {
    if (err instanceof EncoderRejected) throw new InvalidInnerRequest(err.reason);
    throw err;
  }
}

async function seal(nodeKey: Uint8Array, bhttp: Uint8Array): Promise<SealedRequest> {
  try {
    return await sealRequest(nodeKey, bhttp);
  } catch (err) {
    if (err instanceof InvalidNodeKey) {
      throw new MalformedAttestationResponse("attested pubkey is not a usable encryption key");
    }
    throw err;
  }
}

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
  readonly #slot: PinSlot;

  constructor(options: ConfidentialClientOptions) {
    this.#chainId = validateChainId(options.chainId);
    const ttlMs = options.pubkeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS;
    if (ttlMs <= 0) {
      throw new RangeError("pubkeyCacheTtlMs must be a positive number of milliseconds");
    }
    let urls: VrpcUrls;
    try {
      urls = deriveVrpcUrls(options.url);
    } catch {
      // The platform error echoes the URL, which may carry the API key.
      throw new TypeError("Invalid vRPC URL");
    }
    this.#replayWindowMs = options.replayWindowMs;
    this.#confidentialUrl = urls.confidentialUrl;
    this.#headers = withoutContentType(options.headers ?? {});
    const transport = options.transport ?? defaultTransport;
    this.#transport = transport;
    const hardwareVerifier = options.hardwareVerifier ?? createCloudVerifier();
    const logger = options.logger ? safeLogger(options.logger) : defaultLogger;
    const headers = this.#headers;
    this.#slot = new PinSlot(
      (signal) =>
        attestNode({
          transport,
          attestationUrl: urls.attestationUrl,
          headers: { ...headers },
          hardwareVerifier,
          logger,
          ...(signal === undefined ? {} : { signal }),
        }),
      ttlMs,
    );
  }

  /** Sends one inner request sealed to the pinned node; any inner status is returned, not thrown. */
  async request(
    inner: InnerRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ConfidentialResponse> {
    const bhttp = await encode(inner);
    const pin = await this.#slot.acquire();
    try {
      return await this.#exchange(pin, bhttp, options?.signal);
    } catch (err) {
      this.#slot.evict(pin);
      throw err;
    }
  }

  async #exchange(
    pin: Pin,
    bhttp: Uint8Array,
    signal: AbortSignal | undefined,
  ): Promise<ConfidentialResponse> {
    const sealed = await seal(pin.nodeKey, bhttp);
    let response: OuterResponse;
    try {
      response = await this.#transport({
        method: "POST",
        url: `${this.#confidentialUrl}?node_id=${encodeURIComponent(pin.nodeId)}`,
        headers: { ...this.#headers, "content-type": OHTTP_REQUEST },
        body: sealed.body,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      throw new TransportFailed("network", pin.nodeId, { cause });
    }
    if (response.body.byteLength > MAX_RESPONSE_BYTES) {
      throw new TransportFailed("too-large", pin.nodeId);
    }

    const { status } = response;
    const contentType = mediaType(getHeader(response.headers, "content-type"));
    const reported = contentType === "" ? undefined : contentType;
    if (
      !Number.isInteger(status) ||
      status < 200 ||
      status > 599 ||
      NULL_BODY_STATUSES.has(status)
    ) {
      throw new UnexpectedResponse(status, pin.nodeId, reported);
    }
    if (contentType !== OHTTP_RESPONSE) {
      if (status >= 400 && status <= 499) throw new RequestRejected(status, pin.nodeId, reported);
      throw new UnexpectedResponse(status, pin.nodeId, reported);
    }
    const signer = getHeader(response.headers, "vRPC-Pubkey");
    if (signer !== null && PUBKEY_HEX_RE.test(signer) && signer !== pin.pubkeyHex) {
      throw new ConfidentialSignerMismatch(pin.pubkeyHex, signer);
    }
    await verifyResponse(sealed.body, response.body, response.headers, {
      chainId: this.#chainId,
      ...(this.#replayWindowMs === undefined ? {} : { replayWindowMs: this.#replayWindowMs }),
    });

    const decoded = await open(sealed.opener, response.body);
    return decoded.contentType === null
      ? { status: decoded.status, body: decoded.body }
      : { status: decoded.status, contentType: decoded.contentType, body: decoded.body };
  }
}
