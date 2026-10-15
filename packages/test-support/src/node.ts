// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// In-test node that attests and answers sealed requests with signed, sealed responses.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { createRecipient } from "./recipient";

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

export interface TestNode {
  readonly pubkeyHex: string;
  readonly requests: TestOuterRequest[];
  attestations(): number;
  transport(request: TestOuterRequest): Promise<TestOuterResponse>;
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

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

export function createTestNode(options: TestNodeOptions): TestNode {
  const recipient = createRecipient(options.seed);
  const pubkeyHex = `0x${bytesToHex(recipient.ed25519PublicKey)}`;
  const nodeId = options.nodeId === undefined ? "test-node-1" : options.nodeId;
  const nodeIdHeader: Record<string, string> = nodeId === null ? {} : { "vRPC-NodeId": nodeId };
  const upstream = options.upstream ?? defaultUpstream;
  const chainHash = sha256(utf8.encode(options.chainId));
  const requests: TestOuterRequest[] = [];
  let attestationCount = 0;

  async function serve(request: TestOuterRequest): Promise<TestOuterResponse> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.endsWith("/attestation")) {
      attestationCount += 1;
      const nonceHex = url.searchParams.get("nonce") ?? "";
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
    if (
      request.method === "POST" &&
      url.pathname.endsWith("/confidential") &&
      request.body !== undefined
    ) {
      const opened = await recipient.openRequest(request.body);
      const answer = await upstream(opened.request);
      const sealed = await opened.respond({
        status: answer.status,
        ...(answer.headers === undefined ? {} : { headers: answer.headers }),
        ...(answer.body === undefined ? {} : { body: answer.body }),
      });
      const timestamp = BigInt(Date.now());
      const preImage = concatBytes(
        chainHash,
        sha256(request.body),
        sha256(sealed),
        u64le(timestamp),
      );
      return {
        status: NULL_BODY_STATUSES.has(answer.status) ? 200 : answer.status,
        headers: {
          "content-type": "message/ohttp-res",
          "vRPC-Signature": `0x${bytesToHex(ed25519.sign(preImage, options.seed))}`,
          "vRPC-Timestamp": timestamp.toString(),
          "vRPC-Pubkey": pubkeyHex,
          ...nodeIdHeader,
        },
        body: sealed,
      };
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
  };
}
