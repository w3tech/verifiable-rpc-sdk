// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Binary HTTP (RFC 9292) encoding of inner requests and decoding of inner responses.

import { BHttpDecoder, BHttpEncoder } from "bhttp-ts";

export interface InnerRequest {
  method: string;
  path: string;
  contentType?: string;
  accept?: string;
  body?: Uint8Array;
}

export interface InnerResponse {
  status: number;
  contentType: string | null;
  body: Uint8Array;
}

export type InvalidInnerRequestReason =
  | "method"
  | "path"
  | "header"
  | "content-type-required"
  | "encode-failed";

export class InvalidInnerRequest extends Error {
  readonly kind = "InvalidInnerRequest" as const;

  constructor(
    readonly reason: InvalidInnerRequestReason,
    options?: { cause?: unknown },
  ) {
    super(`Inner request rejected: ${reason}`, options);
    this.name = "InvalidInnerRequest";
  }
}

export type MalformedInnerResponseReason = "framing" | "informational" | "decode-failed";

export class MalformedInnerResponse extends Error {
  readonly kind = "MalformedInnerResponse" as const;

  constructor(
    readonly reason: MalformedInnerResponseReason,
    options?: { cause?: unknown },
  ) {
    super(`Inner response malformed: ${reason}`, options);
    this.name = "MalformedInnerResponse";
  }
}

export async function encodeInnerRequest(request: InnerRequest): Promise<Uint8Array> {
  if (!request.path.startsWith("/")) throw new InvalidInnerRequest("path");
  if (request.body !== undefined && request.contentType === undefined) {
    throw new InvalidInnerRequest("content-type-required");
  }
  try {
    const headers = new Headers();
    if (request.contentType !== undefined) headers.set("content-type", request.contentType);
    if (request.accept !== undefined) headers.set("accept", request.accept);
    const init: RequestInit = { method: request.method, headers };
    if (request.body !== undefined) init.body = request.body;
    return await new BHttpEncoder().encodeRequest(
      new Request(`https://localhost${request.path}`, init),
    );
  } catch (cause) {
    throw new InvalidInnerRequest("encode-failed", { cause });
  }
}

export async function decodeInnerResponse(bytes: Uint8Array): Promise<InnerResponse> {
  try {
    const response = new BHttpDecoder().decodeResponse(bytes);
    const body =
      response.body === null ? new Uint8Array(0) : new Uint8Array(await response.arrayBuffer());
    return { status: response.status, contentType: response.headers.get("content-type"), body };
  } catch (cause) {
    throw new MalformedInnerResponse("decode-failed", { cause });
  }
}
