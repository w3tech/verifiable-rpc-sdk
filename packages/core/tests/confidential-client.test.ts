import { getPublicKeyAsync } from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  createTestNode,
  mockHardwareVerifier,
  rejectionOf,
  signResponse,
  type TestNodeOptions,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import {
  AttestationUnavailable,
  ConfidentialSignerMismatch,
  InvalidChainId,
  InvalidInnerRequest,
  UnavailableError,
  UnexpectedResponse,
  VerificationError,
} from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const OTHER_SEED = new Uint8Array(32).fill(0x42);
const CHAIN_ID = "42161";
const BASE_URL = "https://rpc.example/eth_vrpc";
// Fake key literal, never a real key.
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const KEYED_URL = `${BASE_URL}/${KEY}`;
const NODE_ID = "alpha-vrpc-1";
const utf8 = new TextEncoder();
const JSON_RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const DEFAULT_UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode(JSON_RPC_BODY),
  };
}

function testNode(overrides: Partial<TestNodeOptions> = {}) {
  return createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID, ...overrides });
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

describe("ConfidentialClient", () => {
  test("a JSON-RPC call returns the upstream's status, content-type and body", async () => {
    const node = testNode();
    const response = await clientFor(node.transport).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(response.contentType).toBe("application/json");
    expect(new TextDecoder().decode(response.body)).toBe(DEFAULT_UPSTREAM_BODY);
  });

  test("a transport answering with a Headers look-alike is read like native Headers", async () => {
    class ForeignHeaders {
      readonly #headers: Headers;
      constructor(init: Record<string, string>) {
        this.#headers = new Headers(init);
      }
      get(name: string): string | null {
        return this.#headers.get(name);
      }
    }
    const node = testNode();
    const transport: ConfidentialTransport = async (request) => {
      const answer = await node.transport(request);
      return { ...answer, headers: new ForeignHeaders(answer.headers) as unknown as Headers };
    };
    const client = clientFor(transport);

    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(client.getConfidentialInfo()?.nodeId).toBe(NODE_ID);
  });

  test("the first call attests then posts ciphertext; the second call only posts", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    await client.request(jsonRpcCall());

    expect(node.requests).toHaveLength(2);
    const [attestation, call] = node.requests;
    expect(attestation?.method).toBe("GET");
    expect(attestation?.url.startsWith(`${KEYED_URL}/attestation?nonce=`)).toBe(true);
    expect(attestation?.url.slice(`${KEYED_URL}/attestation?nonce=`.length)).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(attestation?.url).not.toContain("node_id");
    expect(attestation?.body).toBeUndefined();

    expect(call?.method).toBe("POST");
    expect(call?.url).toBe(`${KEYED_URL}/confidential?node_id=${NODE_ID}`);
    expect(call?.headers).toEqual({ "content-type": "message/ohttp-req" });
    expect(bytesToHex(call?.body ?? new Uint8Array(0)).startsWith("00002000010002")).toBe(true);

    await client.request(jsonRpcCall());
    expect(node.requests).toHaveLength(3);
    expect(node.requests[2]?.method).toBe("POST");
    expect(node.attestations()).toBe(1);
  });

  test.each([
    ["absent", null],
    ["empty", ""],
  ])("a %s vRPC-NodeId on the attestation answer is AttestationUnavailable and nothing is posted", async (_label, nodeId) => {
    const node = testNode({ nodeId });
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err).not.toBeInstanceOf(VerificationError);
    const unavailable = err as AttestationUnavailable;
    expect(unavailable.kind).toBe("AttestationUnavailable");
    expect(unavailable.reason).toBe("node-id-missing");
    expect(unavailable.executed).toBe("no");
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  test("a header object whose get returns undefined on a miss still reports a missing vRPC-NodeId", async () => {
    const node = testNode({ nodeId: null });
    const transport: ConfidentialTransport = async (request) => {
      const answer = await node.transport(request);
      const headers = new Map(Object.entries(answer.headers).map(([k, v]) => [k.toLowerCase(), v]));
      const mapLike = { get: (name: string) => headers.get(name.toLowerCase()) };
      return { ...answer, headers: mapLike as unknown as Headers };
    };
    const client = clientFor(transport);
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("node-id-missing");
    expect(client.getConfidentialInfo()).toBeUndefined();
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  test("a plain-text gateway answer is UnexpectedResponse and is never opened", async () => {
    const node = testNode();
    const transport: ConfidentialTransport = async (request) =>
      request.method === "POST"
        ? {
            status: 502,
            headers: { "content-type": "text/plain" },
            body: utf8.encode("upstream down"),
          }
        : node.transport(request);
    const err = await rejectionOf(clientFor(transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect(err).toBeInstanceOf(UnavailableError);
    const unexpected = err as UnexpectedResponse;
    expect(unexpected.kind).toBe("UnexpectedResponse");
    expect(unexpected.status).toBe(502);
    expect(unexpected.contentType).toBe("text/plain");
    expect(unexpected.executed).toBe("unknown");
    expect(unexpected.nodeId).toBe(NODE_ID);
  });

  test("a sealed answer signed by another key is ConfidentialSignerMismatch", async () => {
    const node = testNode();
    const otherPubkey = `0x${bytesToHex(await getPublicKeyAsync(OTHER_SEED))}`;
    const transport: ConfidentialTransport = async (request) => {
      const response = await node.transport(request);
      if (request.method !== "POST" || request.body === undefined) return response;
      return {
        status: response.status,
        headers: {
          "content-type": "message/ohttp-res",
          ...signResponse(CHAIN_ID, request.body, response.body, {
            seed: OTHER_SEED,
            nodeId: NODE_ID,
          }),
        },
        body: response.body,
      };
    };
    const err = await rejectionOf(clientFor(transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(ConfidentialSignerMismatch);
    expect(err).toBeInstanceOf(VerificationError);
    const mismatch = err as ConfidentialSignerMismatch;
    expect(mismatch.kind).toBe("ConfidentialSignerMismatch");
    expect(mismatch.expectedPubkey).toBe(node.pubkeyHex);
    expect(mismatch.actualPubkey).toBe(otherPubkey);
  });
});

describe("ConfidentialClient call surface", () => {
  test.each<[string, InnerRequest, string]>([
    ["a path without a leading slash", { method: "GET", path: "x" }, "path"],
    ["a scheme-relative path", { method: "GET", path: "//evil.example/x" }, "path"],
    ["CONNECT", { method: "CONNECT", path: "/" }, "method"],
    [
      "a body without content-type",
      { method: "POST", path: "/", body: utf8.encode(JSON_RPC_BODY) },
      "content-type-required",
    ],
    [
      "an empty body without content-type",
      { method: "POST", path: "/", body: new Uint8Array(0) },
      "content-type-required",
    ],
  ])("%s is rejected as InvalidInnerRequest before any request", async (_label, inner, reason) => {
    const node = testNode();
    const err = await rejectionOf(clientFor(node.transport).request(inner));

    expect(err).toBeInstanceOf(InvalidInnerRequest);
    expect(err).toBeInstanceOf(VerificationError);
    const invalid = err as InvalidInnerRequest;
    expect(invalid.kind).toBe("InvalidInnerRequest");
    expect(invalid.reason).toBe(reason);
    expect(invalid.message).not.toContain(inner.path);
    expect(node.requests).toHaveLength(0);
  });

  test("an API key in headers goes on both legs and the caller's content-type is dropped", async () => {
    const node = testNode();
    const client = clientFor(node.transport, {
      url: BASE_URL,
      headers: { "x-api-key": KEY, "Content-Type": "application/json" },
    });
    await client.request(jsonRpcCall());

    const [attestation, call] = node.requests;
    expect(attestation?.url.startsWith(`${BASE_URL}/attestation?nonce=`)).toBe(true);
    expect(attestation?.headers).toEqual({ "x-api-key": KEY });
    expect(call?.url).toBe(`${BASE_URL}/confidential?node_id=${NODE_ID}`);
    expect(call?.headers).toEqual({ "x-api-key": KEY, "content-type": "message/ohttp-req" });
  });

  test("an API key in the path stays in the path; the caller's query and hash are dropped", async () => {
    const node = testNode();
    await clientFor(node.transport, { url: `${KEYED_URL}?debug=1#top` }).request(jsonRpcCall());

    const [attestation, call] = node.requests;
    expect(attestation?.url.startsWith(`${KEYED_URL}/attestation?nonce=`)).toBe(true);
    expect(call?.url).toBe(`${KEYED_URL}/confidential?node_id=${NODE_ID}`);
  });

  test("a client without headers sends only content-type on the POST and nothing on the GET", async () => {
    const node = testNode();
    await clientFor(node.transport).request(jsonRpcCall());

    expect(node.requests[0]?.headers).toEqual({});
    expect(node.requests[1]?.headers).toEqual({ "content-type": "message/ohttp-req" });
  });

  test("the node id is sent opaque and percent-encoded", async () => {
    const nodeId = "node 1/\u00fc?&=#";
    const node = testNode({ nodeId });
    await clientFor(node.transport).request(jsonRpcCall());

    const url = node.requests[1]?.url ?? "";
    expect(url.endsWith("?node_id=node%201%2F%C3%BC%3F%26%3D%23")).toBe(true);
    expect(new URL(url).searchParams.get("node_id")).toBe(nodeId);
  });

  test("a REST-shaped GET reaches the upstream with its method, path, query and accept", async () => {
    let seen: Request | undefined;
    const node = testNode({
      upstream: (request) => {
        seen = request;
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: '{"height":16}',
        };
      },
    });
    const response = await clientFor(node.transport).request({
      method: "GET",
      path: "/blocks/latest?full=true",
      accept: "application/json",
    });

    expect(seen?.method).toBe("GET");
    const url = new URL(seen?.url ?? "https://invalid.example/");
    expect(`${url.pathname}${url.search}`).toBe("/blocks/latest?full=true");
    expect(seen?.headers.get("accept")).toBe("application/json");
    expect(response.status).toBe(200);
    expect(response.contentType).toBe("application/json");
    expect(new TextDecoder().decode(response.body)).toBe('{"height":16}');
  });

  test("a GET without body or content-type is sealed and answered", async () => {
    let seen: Request | undefined;
    const node = testNode({
      upstream: (request) => {
        seen = request;
        return { status: 200, headers: { "content-type": "text/plain" }, body: "ok" };
      },
    });
    const response = await clientFor(node.transport).request({ method: "GET", path: "/" });

    expect(seen?.headers.get("content-type")).toBeNull();
    expect(await seen?.text()).toBe("");
    expect(response.status).toBe(200);
    expect(new TextDecoder().decode(response.body)).toBe("ok");
  });

  test("an inner 404 is returned, not thrown", async () => {
    const node = testNode({
      upstream: () => ({
        status: 404,
        headers: { "content-type": "text/plain" },
        body: "not found",
      }),
    });
    const outerStatuses: number[] = [];
    const transport: ConfidentialTransport = async (request) => {
      const response = await node.transport(request);
      if (request.method === "POST") outerStatuses.push(response.status);
      return response;
    };
    const response = await clientFor(transport).request(jsonRpcCall());

    expect(outerStatuses).toEqual([404]);
    expect(response.status).toBe(404);
    expect(response.contentType).toBe("text/plain");
    expect(new TextDecoder().decode(response.body)).toBe("not found");
  });

  test("no inner metadata or plaintext appears on the wire", async () => {
    const node = testNode();
    await clientFor(node.transport, { headers: { "x-api-key": KEY } }).request({
      method: "POST",
      path: "/sentinel-path?q=sentinel-query",
      accept: "application/sentinel-accept",
      contentType: "application/sentinel-type",
      body: utf8.encode('{"note":"sentinel-plaintext"}'),
    });

    expect(node.requests).toHaveLength(2);
    const needles = ["sentinel", "73656e74696e656c"];
    for (const request of node.requests) {
      const body = request.body ?? new Uint8Array(0);
      const surfaces = [
        request.url,
        ...Object.keys(request.headers),
        ...Object.values(request.headers),
        new TextDecoder().decode(body),
        bytesToHex(body),
      ];
      for (const surface of surfaces) {
        for (const needle of needles) expect(surface).not.toContain(needle);
      }
    }
  });

  test("concurrent calls on one client each use their own sealing context", async () => {
    const node = testNode({
      upstream: async (request) => ({
        status: 200,
        headers: { "content-type": "application/json" },
        body: new Uint8Array(await request.arrayBuffer()),
      }),
    });
    const client = clientFor(node.transport);
    await client.request(jsonRpcCall());
    const before = node.requests.length;

    const bodies = Array.from({ length: 20 }, (_, i) => `{"jsonrpc":"2.0","id":${i},"method":"m"}`);
    const responses = await Promise.all(
      bodies.map((body) =>
        client.request({
          method: "POST",
          path: "/",
          contentType: "application/json",
          body: utf8.encode(body),
        }),
      ),
    );

    responses.forEach((response, i) => {
      expect(new TextDecoder().decode(response.body)).toBe(bodies[i]);
    });
    const posts = node.requests.slice(before);
    expect(posts).toHaveLength(20);
    expect(posts.every((request) => request.method === "POST")).toBe(true);
    const encs = new Set(
      posts.map((request) => bytesToHex((request.body ?? new Uint8Array(0)).slice(7, 39))),
    );
    expect(encs.size).toBe(20);
    expect(node.attestations()).toBe(1);
  });

  test("the constructor validates synchronously and sends nothing", () => {
    const node = testNode();
    expect(() => clientFor(node.transport, { chainId: "" })).toThrow(InvalidChainId);
    expect(() => clientFor(node.transport, { pubkeyCacheTtlMs: 0 })).toThrow(RangeError);
    expect(() => clientFor(node.transport, { pubkeyCacheTtlMs: -1 })).toThrow(RangeError);

    let err: unknown;
    try {
      clientFor(node.transport, { url: "not a url with sentinel-key" });
    } catch (caught) {
      err = caught;
    }
    expect(err).toBeInstanceOf(TypeError);
    const typeError = err as TypeError;
    expect(typeError.message).not.toContain("sentinel-key");
    expect(String(typeError)).not.toContain("sentinel-key");
    expect(JSON.stringify(typeError)).not.toContain("sentinel-key");
    for (const value of Object.values(typeError)) {
      expect(String(value)).not.toContain("sentinel-key");
    }
    expect(typeError.cause).toBeUndefined();

    clientFor(node.transport);
    expect(node.requests).toHaveLength(0);
  });

  test.each([
    1.5,
    Number.NaN,
    -1,
    0,
    Number.POSITIVE_INFINITY,
  ])("replayWindowMs %d throws RangeError at construction and sends nothing", (replayWindowMs) => {
    const node = testNode();
    expect(() => clientFor(node.transport, { replayWindowMs })).toThrow(RangeError);
    expect(node.requests).toHaveLength(0);
  });
});
