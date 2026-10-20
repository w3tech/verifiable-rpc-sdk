// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// In-test node that attests and answers sealed requests with signed, sealed responses.

import { bytesToHex } from "@noble/hashes/utils.js";
import { createRecipient } from "./recipient";
import { signResponse } from "./sign";

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

export interface TestNodeOptions {
  seed: Uint8Array;
  chainId: string;
  /** Sent as `vRPC-NodeId`; `null` omits the header. Default `test-node-1`. */
  nodeId?: string | null;
  upstream?: (request: Request) => TestUpstreamResponse | Promise<TestUpstreamResponse>;
}

interface TestSignOptions {
  seed?: Uint8Array;
  timestampMs?: number;
  pubkeyHex?: string;
}

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

const utf8 = new TextEncoder();
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

function defaultUpstream(): TestUpstreamResponse {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"result":"0x10"}',
  };
}

export function createTestNode(options: TestNodeOptions): TestNode {
  const recipient = createRecipient(options.seed);
  const pubkeyHex = `0x${bytesToHex(recipient.ed25519PublicKey)}`;
  const nodeId = options.nodeId === undefined ? "test-node-1" : options.nodeId;
  const nodeIdHeader: Record<string, string> = nodeId === null ? {} : { "vRPC-NodeId": nodeId };
  const upstream = options.upstream ?? defaultUpstream;
  const requests: TestOuterRequest[] = [];
  let attestationCount = 0;
  let confidential: ConfidentialHandler = (context) => context.normal();
  let attestation: AttestationHandler = (context) => context.normal();

  function attestationAnswer(nonceHex: string): TestOuterResponse {
    const body = {
      quote: {
        quote: "00",
        event_log: "00",
        report_data: `${pubkeyHex.slice(2)}${nonceHex}`,
        vm_config: "",
      },
      pubkey: pubkeyHex,
      composeHash: "deadbeef",
    };
    return {
      status: 200,
      headers: { "content-type": "application/json", ...nodeIdHeader },
      body: utf8.encode(JSON.stringify(body)),
    };
  }

  function sign(
    requestBody: Uint8Array,
    responseBody: Uint8Array,
    signOptions: TestSignOptions = {},
  ): Record<string, string> {
    return signResponse(options.chainId, requestBody, responseBody, {
      seed: options.seed,
      ...signOptions,
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
        normal: async () => attestationAnswer(nonceHex),
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
