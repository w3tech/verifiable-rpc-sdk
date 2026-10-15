// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Binary HTTP (RFC 9292) encoding of inner requests and decoding of inner responses.

import { BHttpDecoder, BHttpEncoder, decodeVli, vliEncodedLength } from "bhttp-ts";

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

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORBIDDEN_METHODS = new Set(["CONNECT", "TRACE", "TRACK"]);
// Fetch uppercases the first six in any case; undici warns on a lowercase `patch`.
const UPPERCASE_ONLY_METHODS = new Set([
  "DELETE",
  "GET",
  "HEAD",
  "OPTIONS",
  "POST",
  "PUT",
  "PATCH",
]);
const FIELD_VALUE = /^[\t\x20-\x7e]+$/;
const MAX_PATH_LENGTH = 65534;
const MAX_HEADER_SECTION = 65536;

function validMethod(method: string): boolean {
  if (!TOKEN.test(method)) return false;
  const upper = method.toUpperCase();
  if (FORBIDDEN_METHODS.has(upper)) return false;
  return !UPPERCASE_ONLY_METHODS.has(upper) || method === upper;
}

function validPath(path: string): boolean {
  if (!path.startsWith("/") || path.startsWith("//") || path.length > MAX_PATH_LENGTH) {
    return false;
  }
  try {
    const url = new URL(`https://localhost${path}`);
    return url.host === "localhost" && url.pathname + url.search === path;
  } catch {
    return false;
  }
}

function validFieldValue(value: string): boolean {
  return FIELD_VALUE.test(value) && value.trim() === value;
}

function fieldSize(name: string, value: string): number {
  return (
    vliEncodedLength(name.length) + name.length + vliEncodedLength(value.length) + value.length
  );
}

export async function encodeInnerRequest(request: InnerRequest): Promise<Uint8Array> {
  if (!validMethod(request.method)) throw new InvalidInnerRequest("method");
  if (!validPath(request.path)) throw new InvalidInnerRequest("path");
  const fields: [string, string][] = [];
  if (request.contentType !== undefined) fields.push(["content-type", request.contentType]);
  if (request.accept !== undefined) fields.push(["accept", request.accept]);
  let headerSection = 0;
  for (const [name, value] of fields) {
    if (!validFieldValue(value)) throw new InvalidInnerRequest("header");
    headerSection += fieldSize(name, value);
  }
  if (headerSection > MAX_HEADER_SECTION) throw new InvalidInnerRequest("header");
  if (request.body !== undefined && request.contentType === undefined) {
    throw new InvalidInnerRequest("content-type-required");
  }
  try {
    const init: RequestInit = { method: request.method, headers: fields };
    if (request.body !== undefined) init.body = request.body;
    return await new BHttpEncoder().encodeRequest(
      new Request(`https://localhost${request.path}`, init),
    );
  } catch (cause) {
    throw new InvalidInnerRequest("encode-failed", { cause });
  }
}

const KNOWN_LENGTH_RESPONSE = 0x01;
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

function firstStatus(bytes: Uint8Array): number {
  let status: ReturnType<typeof decodeVli>;
  try {
    status = decodeVli(bytes, 1);
  } catch (cause) {
    throw new MalformedInnerResponse("decode-failed", { cause });
  }
  if (status === undefined) throw new MalformedInnerResponse("decode-failed");
  return status.value;
}

export async function decodeInnerResponse(bytes: Uint8Array): Promise<InnerResponse> {
  if (bytes[0] !== KNOWN_LENGTH_RESPONSE) throw new MalformedInnerResponse("framing");
  // bhttp-ts skips 1xx responses silently, so the first status is checked here.
  if (firstStatus(bytes) < 200) throw new MalformedInnerResponse("informational");
  try {
    const response = new BHttpDecoder().decodeResponse(bytes);
    const body =
      NULL_BODY_STATUSES.has(response.status) || response.body === null
        ? new Uint8Array(0)
        : new Uint8Array(await response.arrayBuffer());
    return { status: response.status, contentType: response.headers.get("content-type"), body };
  } catch (cause) {
    throw new MalformedInnerResponse("decode-failed", { cause });
  }
}
