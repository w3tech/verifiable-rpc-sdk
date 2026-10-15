// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client: attest and pin a node, seal each request to it, verify and open the answer.

import { createCloudVerifier, type HardwareVerifier } from "@w3tech.io/dstack-verify";

import { decodeInnerResponse, encodeInnerRequest, type InnerRequest } from "./bhttp";
import { ConfidentialSignerMismatch, UnexpectedResponse } from "./errors";
import { defaultLogger, type Logger, safeLogger } from "./logger";
import { attestNode, PinSlot } from "./node-session";
import { openResponse, sealRequest } from "./ohttp";
import { validateChainId } from "./preimage";
import { type ConfidentialTransport, defaultTransport } from "./transport";
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

function withoutContentType(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => name.toLowerCase() !== "content-type"),
  );
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
    const bhttp = await encodeInnerRequest(inner);
    const pin = await this.#slot.acquire();
    const sealed = await sealRequest(pin.nodeKey, bhttp);
    const signal = options?.signal;
    const response = await this.#transport({
      method: "POST",
      url: `${this.#confidentialUrl}?node_id=${encodeURIComponent(pin.nodeId)}`,
      headers: { ...this.#headers, "content-type": OHTTP_REQUEST },
      body: sealed.body,
      ...(signal === undefined ? {} : { signal }),
    });

    const contentType = mediaType(getHeader(response.headers, "content-type"));
    if (contentType !== OHTTP_RESPONSE) {
      throw new UnexpectedResponse(
        response.status,
        pin.nodeId,
        contentType === "" ? undefined : contentType,
      );
    }
    const signer = getHeader(response.headers, "vRPC-Pubkey");
    if (signer !== null && PUBKEY_HEX_RE.test(signer) && signer !== pin.pubkeyHex) {
      throw new ConfidentialSignerMismatch(pin.pubkeyHex, signer);
    }
    await verifyResponse(sealed.body, response.body, response.headers, {
      chainId: this.#chainId,
      ...(this.#replayWindowMs === undefined ? {} : { replayWindowMs: this.#replayWindowMs }),
    });

    const decoded = await decodeInnerResponse(await openResponse(sealed.opener, response.body));
    return decoded.contentType === null
      ? { status: decoded.status, body: decoded.body }
      : { status: decoded.status, contentType: decoded.contentType, body: decoded.body };
  }
}
