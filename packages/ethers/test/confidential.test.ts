// VrpcProvider in Ankr Confidential RPC mode (`confidential: true`) against an in-test node behind
// a loopback HTTP server: wire shape, results and errors equal to open mode, configuration errors,
// eager attestation and concurrency.

import { type VrpcOptions, VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { FetchRequest } from "ethers";
import { afterEach, describe, expect, test } from "vitest";
import {
  createTestNode,
  serveTestNode,
  type TestNode,
  type TestNodeServer,
  type TestUpstreamResponse,
} from "../../test-support/src/index";
import { CHAIN_ID, TEST_SEED } from "./fixtures";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const NODE_ID = "alpha-vrpc-1";
const KEY = "0123456789abcdefghijABCDEFGHIJkl";

interface RpcCall {
  jsonrpc: string;
  id: number;
  method: string;
  params: unknown[];
}

interface UpstreamSeen {
  method: string;
  path: string;
  contentType: string | null;
  body: string;
}

type Upstream = (request: Request, body: string) => TestUpstreamResponse;

interface Harness {
  node: TestNode;
  server: TestNodeServer;
  seen: UpstreamSeen[];
}

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function json(value: unknown, status = 200): TestUpstreamResponse {
  return { status, headers: { "content-type": "application/json" }, body: JSON.stringify(value) };
}

// Answers single objects and arrays with `results(call)`, like a JSON-RPC node.
function rpc(results: (call: RpcCall) => unknown): Upstream {
  return (_request, body) => {
    const parsed = JSON.parse(body) as RpcCall | RpcCall[];
    const answer = (call: RpcCall) => ({ jsonrpc: "2.0", id: call.id, result: results(call) });
    return json(Array.isArray(parsed) ? parsed.map(answer) : answer(parsed));
  };
}

const blockNumber16 = rpc(() => "0x10");

async function harness(upstream: Upstream = blockNumber16): Promise<Harness> {
  const seen: UpstreamSeen[] = [];
  const node = createTestNode({
    seed: TEST_SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    upstream: async (request) => {
      const body = await request.text();
      seen.push({
        method: request.method,
        path: new URL(request.url).pathname,
        contentType: request.headers.get("content-type"),
        body,
      });
      return upstream(request, body);
    },
  });
  const server = await serveTestNode(node);
  cleanups.push(() => server.close());
  return { node, server, seen };
}

function keyedRequest(server: TestNodeServer): FetchRequest {
  const req = new FetchRequest(`${server.url}/eth_vrpc`);
  req.setHeader("x-api-key", KEY);
  return req;
}

function confidentialProvider(url: string | FetchRequest, options: VrpcOptions = {}): VrpcProvider {
  const provider = new VrpcProvider(url, 42161, {
    confidential: true,
    hardwareVerifier: mockHardwareVerifier(),
    cacheTimeout: -1,
    ...options,
  });
  cleanups.push(() => provider.destroy());
  return provider;
}

describe("a single call", () => {
  test("attests, then sends one sealed POST, and resolves to the upstream's value", async () => {
    const { server, seen } = await harness();
    const provider = confidentialProvider(keyedRequest(server));

    await expect(provider.getBlockNumber()).resolves.toBe(16);

    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST"]);
    const [get, post] = server.requests;
    expect(get?.url).toMatch(/^\/eth_vrpc\/attestation\?nonce=[0-9a-f]{64}$/);
    expect(post?.url).toBe(`/eth_vrpc/confidential?node_id=${NODE_ID}`);
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
    for (const request of server.requests) {
      expect(request.headers["x-api-key"]).toBe(KEY);
      expect(request.headers["accept-encoding"]).toBe("identity");
    }
    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.path).toBe("/");
    expect(seen[0]?.contentType).toBe("application/json");
    expect(JSON.parse(seen[0]?.body ?? "")).toMatchObject({
      jsonrpc: "2.0",
      method: "eth_blockNumber",
    });
  });

  test("a second call adds one POST and no attestation", async () => {
    const { node, server } = await harness();
    const provider = confidentialProvider(keyedRequest(server));

    await provider.getBlockNumber();
    await provider.getBlockNumber();

    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST", "POST"]);
    expect(node.attestations()).toBe(1);
  });

  test("a string URL carrying the key in its path sends both requests under that path", async () => {
    const { server } = await harness();
    const provider = confidentialProvider(`${server.url}/eth_vrpc/${KEY}`);

    await expect(provider.getBlockNumber()).resolves.toBe(16);

    const [get, post] = server.requests;
    expect(server.requests).toHaveLength(2);
    expect(get?.method).toBe("GET");
    expect(get?.url).toMatch(new RegExp(`^/eth_vrpc/${KEY}/attestation\\?nonce=[0-9a-f]{64}$`));
    expect(post?.method).toBe("POST");
    expect(post?.url).toBe(`/eth_vrpc/${KEY}/confidential?node_id=${NODE_ID}`);
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
  });
});
