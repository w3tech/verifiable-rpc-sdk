import { hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createTestNode, type TestOuterResponse } from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import { AttestationUnavailable } from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const NODE_ID = "alpha-vrpc-1";
const KEYED_URL = "https://rpc.example/eth_vrpc/0123456789abcdefghijABCDEFGHIJkl";
const utf8 = new TextEncoder();

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

function testNode() {
  return createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
}

function clientFor(
  transport: ConfidentialTransport,
  overrides: Partial<ConfidentialClientOptions> = {},
): ConfidentialClient {
  return new ConfidentialClient({
    url: KEYED_URL,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport,
    ...overrides,
  });
}

function posts(node: ReturnType<typeof testNode>): number {
  return node.requests.filter((request) => request.method === "POST").length;
}

function plain(status: number, contentType?: string): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body: new Uint8Array(0),
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ready and getConfidentialInfo", () => {
  test("a cold client has no info; ready attests once and returns the pinned node", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    expect(client.getConfidentialInfo()).toBeUndefined();

    const before = Date.now();
    const info = await client.ready();
    const after = Date.now();

    expect(info).toEqual({
      nodeId: NODE_ID,
      pubkey: node.pubkeyHex,
      composeHash: "deadbeef",
      attestedAt: info.attestedAt,
    });
    expect(Object.keys(info).sort()).toEqual(["attestedAt", "composeHash", "nodeId", "pubkey"]);
    expect(info.pubkey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(typeof info.attestedAt).toBe("number");
    expect(info.attestedAt).toBeGreaterThanOrEqual(before);
    expect(info.attestedAt).toBeLessThanOrEqual(after);
    expect(node.attestations()).toBe(1);
  });

  test("a second ready and a following request reuse the pin", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    const first = await client.ready();
    const second = await client.ready();

    expect(second).toEqual(first);
    expect(client.getConfidentialInfo()).toEqual(first);
    expect(node.attestations()).toBe(1);

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(1);
    expect(node.requests.filter((request) => request.method === "GET")).toHaveLength(1);
  });
});

describe("single flight", () => {
  test("50 concurrent cold calls share one attestation", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    const responses = await Promise.all(
      Array.from({ length: 50 }, () => client.request(jsonRpcCall())),
    );

    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(50);
    expect(responses.every((response) => response.status === 200)).toBe(true);
  });

  test("a failed shared attestation rejects every caller with one error and is not kept", async () => {
    const node = testNode();
    node.setAttestation(() => plain(503, "text/plain"));
    const client = clientFor(node.transport);
    const results = await Promise.allSettled(
      Array.from({ length: 50 }, () => client.request(jsonRpcCall())),
    );

    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(0);
    const reasons = results.map((result) => {
      expect(result.status).toBe("rejected");
      return (result as PromiseRejectedResult).reason as unknown;
    });
    const first = reasons[0];
    expect(first).toBeInstanceOf(AttestationUnavailable);
    expect((first as AttestationUnavailable).status).toBe(503);
    for (const reason of reasons) expect(reason).toBe(first);
    expect(client.getConfidentialInfo()).toBeUndefined();

    node.setAttestation();
    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(node.attestations()).toBe(2);
  });
});
