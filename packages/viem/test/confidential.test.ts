// vrpcHttp in Ankr Confidential RPC mode (`confidential: true`) against an in-test node behind a
// loopback HTTP server: wire shape, results and errors equal to open mode, configuration errors,
// the transport value and attestation sharing.

import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { createPublicClient, defineChain, RpcRequestError } from "viem";
import { afterEach, describe, expect, test } from "vitest";
import {
  createTestNode,
  serveTestNode,
  type TestNode,
  type TestNodeServer,
  type TestUpstreamResponse,
} from "../../test-support/src/index";
import { CHAIN_ID } from "./fixtures";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const NODE_ID = "alpha-vrpc-1";
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const TEST_SEED = new Uint8Array(32).fill(0x42);

const arbitrum = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

interface RpcCall {
  jsonrpc: string;
  id: number;
  method: string;
  params?: unknown[];
}

interface UpstreamSeen {
  method: string;
  path: string;
  contentType: string | null;
  body: string;
}

type Upstream = (call: RpcCall) => TestUpstreamResponse;

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

function rpc(results: (call: RpcCall) => unknown): Upstream {
  return (call) => json({ jsonrpc: "2.0", id: call.id, result: results(call) });
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
        path: new globalThis.URL(request.url).pathname,
        contentType: request.headers.get("content-type"),
        body,
      });
      return upstream(JSON.parse(body) as RpcCall);
    },
  });
  const server = await serveTestNode(node);
  cleanups.push(() => server.close());
  return { node, server, seen };
}

function confidential(server: TestNodeServer, options: Parameters<typeof vrpcHttp>[1] = {}) {
  return vrpcHttp(`${server.url}/eth_vrpc`, {
    headers: { "x-api-key": KEY },
    hardwareVerifier: mockHardwareVerifier(),
    ...options,
    confidential: true,
  });
}

describe("a single call", () => {
  test("attests, then sends one sealed POST, and resolves to the upstream's value", async () => {
    const { server, seen } = await harness();
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });

    await expect(client.request({ method: "eth_blockNumber" })).resolves.toBe("0x10");

    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST"]);
    const [get, post] = server.requests;
    expect(get?.url).toMatch(/^\/eth_vrpc\/attestation\?nonce=[0-9a-f]{64}$/);
    expect(post?.url).toBe(`/eth_vrpc/confidential?node_id=${NODE_ID}`);
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
    for (const request of server.requests) expect(request.headers["x-api-key"]).toBe(KEY);

    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.path).toBe("/");
    expect(seen[0]?.contentType).toBe("application/json");
    expect(JSON.parse(seen[0]?.body ?? "")).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_blockNumber",
    });
  });

  test("a viem action returns the decoded value and a second call reuses the pin", async () => {
    const { server } = await harness();
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });

    await expect(client.getBlockNumber({ cacheTime: 0 })).resolves.toBe(16n);
    await expect(client.getBlockNumber({ cacheTime: 0 })).resolves.toBe(16n);

    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST", "POST"]);
  });

  test("a node JSON-RPC error rejects from the transport as RpcRequestError", async () => {
    const { server } = await harness((call) =>
      json({ jsonrpc: "2.0", id: call.id, error: { code: -32000, message: "boom" } }),
    );
    const { config } = confidential(server)({ chain: arbitrum });

    const err = await config.request({ method: "eth_blockNumber" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RpcRequestError);
    expect((err as RpcRequestError).code).toBe(-32000);
  });
});
