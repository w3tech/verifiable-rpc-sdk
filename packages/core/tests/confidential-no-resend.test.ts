// The client with its default transport puts exactly one request on the wire per call whatever
// the gateway answers, follows no redirect, and only re-attests on the next call.

import { hexToBytes } from "@noble/hashes/utils.js";
import {
  createTestNode,
  mockHardwareVerifier,
  rejectionOf,
  type ServedAnswer,
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import { AttestationUnavailable, RequestRejected, UnexpectedResponse } from "../src/errors";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const NODE_ID = "alpha-vrpc-1";
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const utf8 = new TextEncoder();
const text = new TextDecoder();

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function serve(options: TestNodeServerOptions = {}): Promise<TestNodeServer> {
  const node = createTestNode({
    seed: SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    upstream: () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: UPSTREAM_BODY,
    }),
  });
  const server = await serveTestNode(node, options);
  cleanups.push(() => server.close());
  return server;
}

function clientAt(server: TestNodeServer): ConfidentialClient {
  return new ConfidentialClient({
    url: `${server.url}/eth_vrpc/${KEY}`,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
  });
}

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

const count = (server: TestNodeServer, match: (r: ServedRequest) => boolean) =>
  server.requests.filter(match).length;
const isPost = (r: ServedRequest) => r.method === "POST";
const isGet = (r: ServedRequest) => r.method === "GET";
const isElsewhere = (r: ServedRequest) => r.path === "/elsewhere";

function answerFor(server: TestNodeServer, status: number): ServedAnswer {
  if (status === 429) {
    return { status, headers: { "content-type": "text/plain", "retry-after": "1" }, body: "slow" };
  }
  if (status >= 300 && status < 400) {
    return { status, headers: { location: `${server.url}/elsewhere` } };
  }
  return { status, headers: { "content-type": "text/plain" }, body: "gateway failure" };
}

describe("one request per call with the default transport", () => {
  test.each([
    429, 301, 302, 303, 307, 308, 500, 502, 503, 504,
  ])("the sealed POST answered %i is sent once, then the next call re-attests", async (status) => {
    const server = await serve();
    const client = clientAt(server);
    await client.ready();
    server.requests.splice(0);
    server.answer((request) => (isPost(request) ? answerFor(server, status) : undefined));

    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(server.requests).toHaveLength(1);
    expect(count(server, isPost)).toBe(1);
    expect(count(server, isElsewhere)).toBe(0);
    if (status === 429) {
      expect(err).toBeInstanceOf(RequestRejected);
      expect((err as RequestRejected).status).toBe(429);
      expect((err as RequestRejected).executed).toBe("no");
    } else {
      expect(err).toBeInstanceOf(UnexpectedResponse);
      expect((err as UnexpectedResponse).status).toBe(status);
    }
    expect(client.getConfidentialInfo()).toBeUndefined();

    server.answer();
    server.requests.splice(0);
    const response = await client.request(jsonRpcCall());

    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST"]);
  });

  test.each([
    429, 302, 307, 502,
  ])("the cold attestation answered %i is sent once and nothing is sealed", async (status) => {
    const server = await serve();
    const client = clientAt(server);
    server.answer((request) => (isGet(request) ? answerFor(server, status) : undefined));

    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(count(server, isGet)).toBe(1);
    expect(count(server, isPost)).toBe(0);
    expect(count(server, isElsewhere)).toBe(0);
    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("status");
    expect((err as AttestationUnavailable).status).toBe(status);
  });
});

describe("encoding", () => {
  test("gzipped answers are decoded before verification", async () => {
    const server = await serve({ gzipWhenAccepted: true });
    const client = clientAt(server);

    const response = await client.request(jsonRpcCall());

    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
    expect(server.requests.some((r) => r.gzipped)).toBe(true);
  });
});
