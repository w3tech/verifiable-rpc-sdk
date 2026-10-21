import { bytesToHex } from "@noble/hashes/utils.js";
import { DEFAULT_PHALA_VERIFY_ENDPOINT } from "@w3tech.io/dstack-verify";
import {
  CHAIN_ID,
  countOf,
  createTestNode,
  isPost,
  jsonRpcCall,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  signResponse,
  TEST_PUBKEY_HEX,
  TEST_SEED,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import {
  AttestationUnavailable,
  ConfidentialSignerMismatch,
  InvalidInnerRequest,
  InvalidOption,
  UnavailableError,
  VerificationError,
} from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";

const BASE_URL = "https://rpc.example/eth_vrpc";
const KEYED_URL = `${BASE_URL}/${KEY}`;
const utf8 = new TextEncoder();
const JSON_RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const DEFAULT_UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';

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
    const node = createTestNode();
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
    const node = createTestNode();
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
    const node = createTestNode();
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
    const node = createTestNode({ nodeId });
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err).not.toBeInstanceOf(VerificationError);
    const unavailable = err as AttestationUnavailable;
    expect(unavailable.kind).toBe("AttestationUnavailable");
    expect(unavailable.reason).toBe("node-id-missing");
    expect(unavailable.executed).toBe("no");
    expect(countOf(node, isPost)).toBe(0);
  });

  test("a header object whose get returns undefined on a miss still reports a missing vRPC-NodeId", async () => {
    const node = createTestNode({ nodeId: null });
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
    expect(countOf(node, isPost)).toBe(0);
  });

  test("a sealed answer signed by another key is ConfidentialSignerMismatch", async () => {
    const node = createTestNode();
    const transport: ConfidentialTransport = async (request) => {
      const response = await node.transport(request);
      if (request.method !== "POST" || request.body === undefined) return response;
      return {
        status: response.status,
        headers: {
          "content-type": "message/ohttp-res",
          ...signResponse(CHAIN_ID, request.body, response.body, {
            seed: TEST_SEED,
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
    expect(mismatch.actualPubkey).toBe(TEST_PUBKEY_HEX);
  });

  test("without a hardware verifier the given fetch makes the cloud verify call", async () => {
    const seen: string[] = [];
    const fetchStub = (async (input: string | URL | Request) => {
      seen.push(String(input));
      return new Response("unavailable", { status: 503 });
    }) as typeof fetch;
    const client = clientFor(createTestNode().transport, {
      hardwareVerifier: undefined,
      fetch: fetchStub,
    });

    expect(await rejectionOf(client.ready())).toMatchObject({ reason: "verifier" });
    expect(seen).toEqual([DEFAULT_PHALA_VERIFY_ENDPOINT]);
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
    const node = createTestNode();
    const err = await rejectionOf(clientFor(node.transport).request(inner));

    expect(err).toBeInstanceOf(InvalidInnerRequest);
    expect(err).not.toBeInstanceOf(VerificationError);
    const invalid = err as InvalidInnerRequest;
    expect(invalid.kind).toBe("InvalidInnerRequest");
    expect(invalid.reason).toBe(reason);
    expect(invalid.message).not.toContain(inner.path);
    expect(node.requests).toHaveLength(0);
  });

  test("an API key in headers goes on both legs and the caller's content-type is dropped", async () => {
    const node = createTestNode();
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
    const node = createTestNode();
    await clientFor(node.transport, { url: `${KEYED_URL}?debug=1#top` }).request(jsonRpcCall());

    const [attestation, call] = node.requests;
    expect(attestation?.url.startsWith(`${KEYED_URL}/attestation?nonce=`)).toBe(true);
    expect(call?.url).toBe(`${KEYED_URL}/confidential?node_id=${NODE_ID}`);
  });

  test("a client without headers sends only content-type on the POST and nothing on the GET", async () => {
    const node = createTestNode();
    await clientFor(node.transport).request(jsonRpcCall());

    expect(node.requests[0]?.headers).toEqual({});
    expect(node.requests[1]?.headers).toEqual({ "content-type": "message/ohttp-req" });
  });

  test("the node id is sent opaque and percent-encoded", async () => {
    const nodeId = "node 1/\u00fc?&=#";
    const node = createTestNode({ nodeId });
    await clientFor(node.transport).request(jsonRpcCall());

    const url = node.requests[1]?.url ?? "";
    expect(url.endsWith("?node_id=node%201%2F%C3%BC%3F%26%3D%23")).toBe(true);
    expect(new URL(url).searchParams.get("node_id")).toBe(nodeId);
  });

  test("a REST-shaped GET reaches the upstream with its method, path, query and accept", async () => {
    let seen: Request | undefined;
    const node = createTestNode({
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
    const node = createTestNode({
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
    const node = createTestNode({
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
    const node = createTestNode();
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
    const node = createTestNode({
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

  test.each([
    "url",
    "chainId",
  ] as const)("a missing %s throws InvalidOption at construction and sends nothing", (option) => {
    const node = createTestNode();
    const err = thrownBy(() => clientFor(node.transport, { [option]: undefined }));
    expect(err).toBeInstanceOf(InvalidOption);
    expect(err).toMatchObject({ option, executed: "no" });
    expect(node.requests).toHaveLength(0);
  });
});
