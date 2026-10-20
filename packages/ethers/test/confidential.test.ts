// VrpcProvider in Ankr Confidential RPC mode (`confidential: true`) against an in-test node behind
// a loopback HTTP server: wire shape, results and errors equal to open mode, configuration errors,
// eager attestation and concurrency.

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { UnexpectedResponse } from "@w3tech.io/vrpc-core";
import { InvalidChainId, type VrpcOptions, VrpcProvider } from "@w3tech.io/vrpc-ethers";
import {
  attestationStub,
  CHAIN_ID,
  createTestNode,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  signedJsonHeaders,
  TEST_SEED,
  type TestNode,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import { serveTestNode, type TestNodeServer } from "@w3tech.io/vrpc-test-support/server";
import { AbiCoder, EnsResolver, FetchRequest, isError, toUtf8String } from "ethers";
import { afterEach, describe, expect, test, vi } from "vitest";

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

type Upstream = (body: string) => TestUpstreamResponse;

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
  return (body) => {
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
      return upstream(body);
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

const ADDR = "0x1111111111111111111111111111111111111111";
const TO = "0x2222222222222222222222222222222222222222";
const TX_HASH = `0x${"ab".repeat(32)}`;
const CALL_RESULT = `0x${"00".repeat(31)}2a`;
const ATT = attestationStub();
const utf8 = new TextEncoder();

function address(n: number): string {
  return `0x${n.toString(16).padStart(40, "0")}`;
}

function balanceOf(call: RpcCall): string {
  return `0x${BigInt(String(call.params[0])).toString(16)}`;
}

const chainUpstream = rpc((call) => {
  switch (call.method) {
    case "eth_blockNumber":
      return "0x10";
    case "eth_getBalance":
      return balanceOf(call);
    case "eth_call":
      return CALL_RESULT;
    case "eth_getTransactionByHash":
      return null;
    default:
      throw new Error(`unexpected method ${call.method}`);
  }
});

// Open mode over the same upstream: signed answers through the FetchRequest seam.
function openProvider(upstream: Upstream): VrpcProvider {
  const req = new FetchRequest("http://test.invalid");
  req.getUrlFunc = async (sent) => {
    const requestBytes = sent.body ?? new Uint8Array();
    const answer = upstream(new TextDecoder().decode(requestBytes));
    const body = answer.body ?? new Uint8Array();
    const responseBytes = typeof body === "string" ? utf8.encode(body) : body;
    const headers = signedJsonHeaders(CHAIN_ID, requestBytes, responseBytes, {
      nodeId: "node-abc",
      timestampMs: Date.now(),
    });
    return { statusCode: answer.status, statusMessage: "OK", headers, body: responseBytes };
  };
  const provider = new VrpcProvider(req, 42161, {
    fetch: ATT.fetch,
    hardwareVerifier: mockHardwareVerifier(),
    cacheTimeout: -1,
  });
  cleanups.push(() => provider.destroy());
  return provider;
}

function textForms(err: unknown): string[] {
  return [
    (err as Error).message,
    String(err),
    JSON.stringify(err, (_key, value) => (typeof value === "bigint" ? value.toString() : value)),
  ];
}

function posts(server: TestNodeServer): number {
  return server.requests.filter((r) => r.method === "POST").length;
}

describe("results equal open mode", () => {
  test("single calls, a batch and a null result", async () => {
    const { server } = await harness(chainUpstream);
    const sealed = confidentialProvider(keyedRequest(server));
    const open = openProvider(chainUpstream);

    const run = async (provider: VrpcProvider) => ({
      blockNumber: await provider.getBlockNumber(),
      balance: await provider.getBalance(ADDR),
      call: await provider.call({ to: TO, data: "0x12345678" }),
      batch: await Promise.all([
        provider.getBlockNumber(),
        provider.getBalance(address(7)),
        provider.call({ to: TO, data: "0x12345678" }),
      ]),
      missing: await provider.getTransaction(TX_HASH),
    });

    const expected = await run(open);
    expect(expected.blockNumber).toBe(16);
    expect(expected.missing).toBeNull();
    expect(await run(sealed)).toEqual(expected);
  });
});

describe("batching", () => {
  test("two concurrent calls with batchMaxCount 2 travel as one inner array", async () => {
    const { server, seen } = await harness(chainUpstream);
    const provider = confidentialProvider(keyedRequest(server), { batchMaxCount: 2 });
    await provider.confidentialReady();

    await Promise.all([provider.getBalance(address(1)), provider.getBalance(address(2))]);

    expect(posts(server)).toBe(1);
    const inner = JSON.parse(seen[0]?.body ?? "") as unknown;
    expect(Array.isArray(inner) && inner.length).toBe(2);
  });

  test("three concurrent calls with batchMaxCount 2 make two requests", async () => {
    const { server } = await harness(chainUpstream);
    const provider = confidentialProvider(keyedRequest(server), { batchMaxCount: 2 });
    await provider.confidentialReady();

    const balances = await Promise.all([1, 2, 3].map((n) => provider.getBalance(address(n))));

    expect(balances).toEqual([1n, 2n, 3n]);
    expect(posts(server)).toBe(2);
  });

  test("a lone call is a single JSON object, as in open mode", async () => {
    const { seen, server } = await harness(chainUpstream);
    const provider = confidentialProvider(keyedRequest(server));

    await provider.getBalance(ADDR);

    const inner = JSON.parse(seen[0]?.body ?? "") as unknown;
    expect(Array.isArray(inner)).toBe(false);
    expect(inner).toMatchObject({ method: "eth_getBalance" });
  });

  test("answers in reverse order reach the caller with the matching id", async () => {
    const reversed: Upstream = (body) => {
      const calls = JSON.parse(body) as RpcCall[];
      return json(
        calls.map((call) => ({ jsonrpc: "2.0", id: call.id, result: balanceOf(call) })).reverse(),
      );
    };
    const { server, seen } = await harness(reversed);
    const provider = confidentialProvider(keyedRequest(server));

    const balances = await Promise.all([4, 5, 6].map((n) => provider.getBalance(address(n))));

    expect(balances).toEqual([4n, 5n, 6n]);
    expect((JSON.parse(seen[0]?.body ?? "") as unknown[]).length).toBe(3);
  });
});

describe("errors", () => {
  test.each([
    {
      status: 413,
      contentType: "application/problem+json",
      body: '{"type":"urn:vrpc:error:batch-too-large","title":"sentinel-reply"}',
      marker: "batch-too-large",
    },
    {
      status: 500,
      contentType: "text/plain",
      body: "upstream failed sentinel-reply",
      marker: "failed",
    },
  ])("an inner $status rejects every batch member with one SERVER_ERROR without the body text", async ({
    status,
    contentType,
    body,
    marker,
  }) => {
    const { server } = await harness(() => ({
      status,
      headers: { "content-type": contentType },
      body,
    }));
    const provider = confidentialProvider(keyedRequest(server));

    const errors = await Promise.all(
      [1, 2, 3].map((n) => provider.getBalance(address(n))).map(rejectionOf),
    );

    const [first] = errors;
    for (const err of errors) expect(err).toBe(first);
    expect(isError(first, "SERVER_ERROR")).toBe(true);
    const err = first as Error & {
      shortMessage: string;
      info: { responseStatus: string };
      response: { body: Uint8Array };
    };
    expect(err.shortMessage).toBe(`server response ${status} `);
    expect(err.info.responseStatus).toBe(`${status} `);
    expect(toUtf8String(err.response.body)).toContain(marker);
    for (const form of textForms(err)) {
      expect(form).not.toContain("sentinel-reply");
      expect(form).not.toContain(KEY);
    }
  });

  test("an answer missing a request id rejects every caller with one BAD_DATA", async () => {
    const sentinelAddress = "0x5e17e1a15e17e1a15e17e1a15e17e1a15e17e1a1";
    let answerId: (calls: RpcCall[]) => unknown = (calls) =>
      calls.slice(0, 1).map((call) => ({ jsonrpc: "2.0", id: call.id, result: "0x7e57ab1e" }));
    const { server } = await harness((body) => {
      const parsed = JSON.parse(body) as RpcCall | RpcCall[];
      return json(answerId(Array.isArray(parsed) ? parsed : [parsed]));
    });
    const provider = confidentialProvider(keyedRequest(server));

    const batch = await Promise.all(
      [provider.getBalance(sentinelAddress), provider.getBalance(address(9))].map(rejectionOf),
    );
    answerId = () => ({ jsonrpc: "2.0", id: 999, result: "0x7e57ab1e" });
    const single = await rejectionOf(provider.getBalance(sentinelAddress));
    answerId = () => [null];
    const nullElement = await rejectionOf(provider.getBalance(sentinelAddress));

    expect(batch[0]).toBe(batch[1]);
    for (const err of [...batch, single, nullElement]) {
      expect(isError(err, "BAD_DATA")).toBe(true);
      expect((err as { shortMessage: string }).shortMessage).toBe("missing response for request");
      for (const form of textForms(err)) {
        expect(form).not.toContain("7e57ab1e");
        expect(form).not.toContain("5e17e1a1");
      }
    }
  });

  test.each([
    { name: "an empty body", body: "" },
    { name: "a non-JSON body", body: "not json sentinel-reply" },
  ])("an inner 200 with $name rejects with UNSUPPORTED_OPERATION", async ({ body }) => {
    const { server } = await harness(() => ({ status: 200, body }));
    const provider = confidentialProvider(keyedRequest(server));

    const err = await rejectionOf(provider.getBlockNumber());

    expect(isError(err, "UNSUPPORTED_OPERATION")).toBe(true);
    for (const form of textForms(err)) expect(form).not.toContain("sentinel-reply");
  });

  test("a gateway error reaches every batch member as the same core error", async () => {
    const { server } = await harness(chainUpstream);
    const provider = confidentialProvider(keyedRequest(server));
    await provider.confidentialReady();
    server.answer((request) =>
      request.method === "POST"
        ? { status: 502, headers: { "content-type": "text/plain" }, body: "bad gateway" }
        : undefined,
    );

    const errors = await Promise.all(
      [provider.getBalance(address(1)), provider.getBlockNumber()].map(rejectionOf),
    );

    expect(errors[0]).toBe(errors[1]);
    expect(errors[0]).toBeInstanceOf(UnexpectedResponse);
    expect((errors[0] as UnexpectedResponse).status).toBe(502);
  });
});

describe("configuration errors", () => {
  test("throw from the constructor and nothing is sent or logged", async () => {
    const { server } = await harness();
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) =>
      vi.spyOn(console, level).mockImplementation(() => {}),
    );
    cleanups.push(() => {
      for (const spy of spies) spy.mockRestore();
    });
    const url = `${server.url}/eth_vrpc/${KEY}`;
    const make = (chainId: number | string | undefined, options: Record<string, unknown>) => () =>
      new VrpcProvider(url, chainId, { hardwareVerifier: mockHardwareVerifier(), ...options });

    expect(make(undefined, { confidential: true })).toThrow(InvalidChainId);
    expect(make("eip155:42161", { confidential: true })).toThrow(InvalidChainId);
    expect(make(-1, { confidential: true })).toThrow(InvalidChainId);
    expect(make(42161, { confidential: "true" })).toThrow(TypeError);
    expect(make(42161, { confidential: 1 })).toThrow(TypeError);
    for (const name of ["replayWindowMs", "pubkeyCacheTtlMs"]) {
      for (const value of [0, -1, 1.5, Number.POSITIVE_INFINITY]) {
        expect(make(42161, { confidential: true, [name]: value })).toThrow(RangeError);
      }
    }

    let urlError: unknown;
    try {
      new VrpcProvider("not a url sentinel-key", 42161, { confidential: true });
    } catch (err) {
      urlError = err;
    }
    expect(urlError).toBeInstanceOf(TypeError);
    expect((urlError as Error).message).toBe("Invalid vRPC URL");
    for (const form of textForms(urlError)) expect(form).not.toContain("sentinel-key");

    await new Promise((resolve) => setTimeout(resolve, 1500));
    expect(server.requests).toHaveLength(0);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  test("confidential false keeps open mode", async () => {
    const { server } = await harness();
    const provider = new VrpcProvider(`${server.url}/eth_vrpc`, 42161, {
      confidential: false,
      hardwareVerifier: mockHardwareVerifier(),
    });
    cleanups.push(() => provider.destroy());

    await expect(provider.getBlockNumber()).rejects.toThrow();

    expect(provider.getConfidentialInfo()).toBeUndefined();
    expect(server.requests[0]?.method).toBe("POST");
    expect(server.requests[0]?.path).toBe("/eth_vrpc");
    expect(toUtf8String(server.requests[0]?.body ?? new Uint8Array())).toContain("eth_blockNumber");
  });
});

describe("eager attestation", () => {
  test("confidentialReady attests once and getConfidentialInfo reports the pinned node", async () => {
    const { node, server } = await harness();
    const provider = confidentialProvider(keyedRequest(server));

    expect(provider.getConfidentialInfo()).toBeUndefined();
    const info = await provider.confidentialReady();

    expect(info).toEqual({
      nodeId: NODE_ID,
      pubkey: node.pubkeyHex,
      composeHash: "deadbeef",
      attestedAt: expect.any(Number),
    });
    expect(provider.getConfidentialInfo()).toEqual(info);
    expect(server.requests.map((r) => r.method)).toEqual(["GET"]);
    await provider.getBlockNumber();
    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST"]);
    expect(typeof provider.ready).toBe("boolean");
  });

  test("in open mode confidentialReady rejects and getConfidentialInfo is undefined", async () => {
    const provider = openProvider(chainUpstream);

    await expect(provider.confidentialReady()).rejects.toThrow(TypeError);
    await expect(provider.confidentialReady()).rejects.toThrow("Ankr Confidential RPC mode");
    expect(provider.getConfidentialInfo()).toBeUndefined();
  });
});

describe("concurrency", () => {
  test("ten concurrent first calls share one attestation", async () => {
    const { server } = await harness(chainUpstream);
    const provider = confidentialProvider(keyedRequest(server), { batchMaxCount: 1 });

    const balances = await Promise.all(
      Array.from({ length: 10 }, (_, n) => provider.getBalance(address(n + 1))),
    );

    expect(balances).toEqual(Array.from({ length: 10 }, (_, n) => BigInt(n + 1)));
    expect(server.requests.filter((r) => r.method === "GET")).toHaveLength(1);
    expect(posts(server)).toBe(10);
  });
});

describe("CCIP-Read", () => {
  const OFFCHAIN_LOOKUP = "0x556f1830";
  const RESOLVER = "0x00000000000000000000000000000000c0ffee01";

  async function gateway(): Promise<{ url: string; hits: string[] }> {
    const hits: string[] = [];
    const server = createServer((req, res) => {
      hits.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"data":"0x"}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const { port } = server.address() as AddressInfo;
    return { url: `http://127.0.0.1:${port}`, hits };
  }

  // Every eth_call reverts with OffchainLookup naming the gateway, as an off-chain resolver does.
  function offchainLookup(gatewayUrl: string): Upstream {
    return (body) => {
      const parsed = JSON.parse(body) as RpcCall | RpcCall[];
      const answer = (call: RpcCall) => {
        if (call.method !== "eth_call") return { jsonrpc: "2.0", id: call.id, result: "0x10" };
        const to = (call.params[0] as { to: string }).to;
        const data =
          OFFCHAIN_LOOKUP +
          AbiCoder.defaultAbiCoder()
            .encode(
              ["address", "string[]", "bytes", "bytes4", "bytes"],
              [to, [`${gatewayUrl}/{sender}/{data}.json`], "0x5e17e1a1", "0x12345678", "0x"],
            )
            .slice(2);
        return {
          jsonrpc: "2.0",
          id: call.id,
          error: { code: 3, message: "execution reverted", data },
        };
      };
      return json(Array.isArray(parsed) ? parsed.map(answer) : answer(parsed));
    };
  }

  test("an OffchainLookup revert fails with CALL_EXCEPTION and nothing is fetched", async () => {
    const { url, hits } = await gateway();
    const { server } = await harness(offchainLookup(url));
    const provider = confidentialProvider(keyedRequest(server));

    const err = await rejectionOf(
      provider.call({ to: RESOLVER, data: "0x5e17e1a1", enableCcipRead: true }),
    );

    expect(hits).toEqual([]);
    expect(isError(err, "CALL_EXCEPTION")).toBe(true);
    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST"]);
  });

  test("an ENS name with an off-chain resolver does not resolve and nothing is fetched", async () => {
    const { url, hits } = await gateway();
    const { server } = await harness(offchainLookup(url));
    const provider = confidentialProvider(keyedRequest(server));

    const resolver = new EnsResolver(provider, RESOLVER, "offchain.eth");

    await expect(resolver.getAddress()).resolves.toBeNull();
    expect(hits).toEqual([]);
    expect(server.requests.every((r) => r.method === "GET" || r.method === "POST")).toBe(true);
    expect(posts(server)).toBeGreaterThan(0);
  });
});
