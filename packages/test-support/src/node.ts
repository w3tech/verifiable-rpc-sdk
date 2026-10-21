// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// In-test node that attests and answers sealed requests with signed, sealed responses.

import { bytesToHex } from "@noble/hashes/utils.js";
import { attestationBody } from "./attestation";
import { CHAIN_ID, NODE_ID, NODE_SEED } from "./fixtures";
import { createRecipient } from "./recipient";
import { type SignOptions, signResponse } from "./sign";

export interface TestOuterRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
  signal?: AbortSignal;
}

export interface TestOuterResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface TestUpstreamResponse {
  status: number;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
}

export type TestUpstream = (
  request: Request,
) => TestUpstreamResponse | Promise<TestUpstreamResponse>;

export interface TestNodeOptions {
  /** Default `NODE_SEED`. */
  seed?: Uint8Array;
  /** Default `CHAIN_ID`. */
  chainId?: string;
  /** Sent as `vRPC-NodeId`; `null` omits the header. Default `NODE_ID`. */
  nodeId?: string | null;
  upstream?: TestUpstream | undefined;
}

type TestSignOptions = Omit<SignOptions, "nodeId">;

export interface ConfidentialContext {
  readonly request: TestOuterRequest;
  /** The standard sealed and signed answer for this request. */
  normal(): Promise<TestOuterResponse>;
  /** `vRPC-*` headers signing this request's body and `responseBody`. */
  sign(responseBody: Uint8Array, options?: TestSignOptions): Record<string, string>;
  /** Arbitrary inner bytes sealed for this request. */
  seal(innerBhttp: Uint8Array): Promise<Uint8Array>;
}

export type ConfidentialHandler = (
  context: ConfidentialContext,
) => TestOuterResponse | Promise<TestOuterResponse>;

export interface AttestationContext {
  readonly request: TestOuterRequest;
  readonly nonceHex: string;
  /** The standard attestation answer for this request. */
  normal(): Promise<TestOuterResponse>;
}

type AttestationHandler = (
  context: AttestationContext,
) => TestOuterResponse | Promise<TestOuterResponse>;

export interface TestNode {
  readonly pubkeyHex: string;
  readonly requests: TestOuterRequest[];
  attestations(): number;
  transport(request: TestOuterRequest): Promise<TestOuterResponse>;
  /** Overrides the `/confidential` answer; no argument restores the default. */
  setConfidential(handler?: ConfidentialHandler): void;
  /** Overrides the `/attestation` answer; no argument restores the default. */
  setAttestation(handler?: AttestationHandler): void;
}

export const isGet = (request: { method: string }) => request.method === "GET";
export const isPost = (request: { method: string }) => request.method === "POST";

/** Requests of a test node or its server that `match`. */
export const countOf = <R>(source: { requests: readonly R[] }, match: (request: R) => boolean) =>
  source.requests.filter(match).length;

const utf8 = new TextEncoder();
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

export interface RpcCall {
  jsonrpc: string;
  id: number;
  method: string;
  params: unknown[];
}

export function jsonResponse(value: unknown, status = 200): TestUpstreamResponse {
  return { status, headers: { "content-type": "application/json" }, body: JSON.stringify(value) };
}

/** The JSON-RPC answer to a call or a batch, with `result(call)` for each call. */
export function rpcAnswer(
  parsed: RpcCall | RpcCall[],
  result: (call: RpcCall) => unknown,
): unknown {
  const answer = (call: RpcCall) => ({ jsonrpc: "2.0", id: call.id, result: result(call) });
  return Array.isArray(parsed) ? parsed.map(answer) : answer(parsed);
}

/** An upstream answering every JSON-RPC call, alone or in a batch, with `result(call)`. */
export function rpcUpstream(result: (call: RpcCall) => unknown): TestUpstream {
  return async (request) =>
    jsonResponse(rpcAnswer((await request.json()) as RpcCall | RpcCall[], result));
}

const defaultUpstream = rpcUpstream(() => "0x10");

export function createTestNode(options: TestNodeOptions = {}): TestNode {
  const seed = options.seed ?? NODE_SEED;
  const chainId = options.chainId ?? CHAIN_ID;
  const recipient = createRecipient(seed);
  const pubkeyHex = `0x${bytesToHex(recipient.ed25519PublicKey)}`;
  const nodeId = options.nodeId === undefined ? NODE_ID : options.nodeId;
  const nodeIdHeader: Record<string, string> = nodeId === null ? {} : { "vRPC-NodeId": nodeId };
  const upstream = options.upstream ?? defaultUpstream;
  const requests: TestOuterRequest[] = [];
  let attestationCount = 0;
  let confidential: ConfidentialHandler = (context) => context.normal();
  let attestation: AttestationHandler = (context) => context.normal();

  function attestationResponse(nonceHex: string): TestOuterResponse {
    return {
      status: 200,
      headers: { "content-type": "application/json", ...nodeIdHeader },
      body: utf8.encode(attestationBody(nonceHex, { seed })),
    };
  }

  function sign(
    requestBody: Uint8Array,
    responseBody: Uint8Array,
    signOptions: TestSignOptions = {},
  ): Record<string, string> {
    return signResponse(chainId, requestBody, responseBody, {
      seed: signOptions.seed ?? seed,
      timestampMs: signOptions.timestampMs,
      pubkeyHex: signOptions.pubkeyHex ?? (signOptions.seed === undefined ? pubkeyHex : undefined),
      nodeId: nodeId ?? undefined,
    });
  }

  function contextFor(request: TestOuterRequest, body: Uint8Array): ConfidentialContext {
    let opened: ReturnType<typeof recipient.openRequest> | undefined;
    const open = () => {
      opened ??= recipient.openRequest(body);
      return opened;
    };
    return {
      request,
      async normal() {
        const openedRequest = await open();
        const answer = await upstream(openedRequest.request);
        const sealed = await openedRequest.respond({
          status: answer.status,
          ...(answer.headers === undefined ? {} : { headers: answer.headers }),
          ...(answer.body === undefined ? {} : { body: answer.body }),
        });
        return {
          status: NULL_BODY_STATUSES.has(answer.status) ? 200 : answer.status,
          headers: { "content-type": "message/ohttp-res", ...sign(body, sealed) },
          body: sealed,
        };
      },
      sign: (responseBody, signOptions) => sign(body, responseBody, signOptions),
      seal: async (innerBhttp) => (await open()).sealResponse(innerBhttp),
    };
  }

  async function serve(request: TestOuterRequest): Promise<TestOuterResponse> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.endsWith("/attestation")) {
      attestationCount += 1;
      const nonceHex = url.searchParams.get("nonce") ?? "";
      return attestation({
        request,
        nonceHex,
        normal: async () => attestationResponse(nonceHex),
      });
    }
    if (
      request.method === "POST" &&
      url.pathname.endsWith("/confidential") &&
      request.body !== undefined
    ) {
      return confidential(contextFor(request, request.body));
    }
    return { status: 404, headers: {}, body: new Uint8Array(0) };
  }

  function transport(request: TestOuterRequest): Promise<TestOuterResponse> {
    requests.push({
      method: request.method,
      url: request.url,
      headers: { ...request.headers },
      ...(request.body === undefined ? {} : { body: request.body.slice() }),
    });
    const signal = request.signal;
    if (signal === undefined) return serve(request);
    if (signal.aborted) return Promise.reject(signal.reason);
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
      serve(request).then(
        (response) => {
          signal.removeEventListener("abort", onAbort);
          resolve(response);
        },
        (err: unknown) => {
          signal.removeEventListener("abort", onAbort);
          reject(err);
        },
      );
    });
  }

  return {
    pubkeyHex,
    requests,
    attestations: () => attestationCount,
    transport,
    setConfidential(handler) {
      confidential = handler ?? ((context) => context.normal());
    },
    setAttestation(handler) {
      attestation = handler ?? ((context) => context.normal());
    },
  };
}
