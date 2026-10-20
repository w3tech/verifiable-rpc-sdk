// vrpcHttp in Ankr Confidential RPC mode (`confidential: true`) against an in-test node behind a
// loopback HTTP server: wire shape, results and errors equal to open mode, configuration errors,
// the transport value and attestation sharing.

import { getEventListeners } from "node:events";
import { RequestRejected } from "@w3tech.io/vrpc-core";
import {
  attestationAnswer,
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
import { InvalidChainId, vrpcHttp } from "@w3tech.io/vrpc-viem";
import {
  BaseError,
  createPublicClient,
  defineChain,
  fallback,
  HttpRequestError,
  RpcRequestError,
} from "viem";
import { afterEach, describe, expect, test, vi } from "vitest";

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

const mainnet = defineChain({ ...arbitrum, id: 1, name: "Ethereum" });
const ADDRESS = "0x1111111111111111111111111111111111111111" as const;
const CALL_RESULT = `0x${"00".repeat(31)}2a` as const;
const TX_HASH = `0x${"ab".repeat(32)}` as const;

const parityUpstream = rpc((call) => {
  switch (call.method) {
    case "eth_blockNumber":
      return "0x10";
    case "eth_getBalance":
      return "0x1bc16d674ec80000";
    case "eth_call":
      return CALL_RESULT;
    case "eth_chainId":
      return "0xa4b1";
    default:
      return null;
  }
});

const APP_COMPOSE = '{"manifest_version":2,"name":"demo"}';

// Open mode answered by the same upstream function, signed over the exact request bytes.
function openFetch(upstream: Upstream) {
  return async (url: string, init: RequestInit): Promise<Response> => {
    if (url.includes("/attestation")) return attestationAnswer(url, { appCompose: APP_COMPOSE });
    const requestBytes = init.body as Uint8Array;
    const answer = upstream(JSON.parse(new TextDecoder().decode(requestBytes)) as RpcCall);
    const responseBody = String(answer.body);
    const responseBytes = new TextEncoder().encode(responseBody);
    const headers = signedJsonHeaders(CHAIN_ID, requestBytes, responseBytes, { nodeId: NODE_ID });
    return new Response(responseBody, { status: answer.status, headers });
  };
}

function unserialisable(value: unknown): string {
  try {
    return JSON.stringify(value, (_, v) => (typeof v === "bigint" ? v.toString() : v)) ?? "";
  } catch {
    return "unserialisable";
  }
}

// message, String form, stack and JSON form of the error and every cause below it.
function texts(err: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<unknown>();
  let current = err;
  while (current instanceof Error && !seen.has(current)) {
    seen.add(current);
    out.push(current.message, String(current), current.stack ?? "", unserialisable(current));
    current = current.cause;
  }
  return out;
}

function walkFind<T>(err: unknown, type: abstract new (...args: never[]) => T): T | undefined {
  if (err instanceof type) return err;
  if (!(err instanceof BaseError)) return undefined;
  return err.walk((e) => e instanceof type) as T | undefined;
}

async function until(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 200 && !predicate(); i++) await new Promise((r) => setTimeout(r, 5));
  expect(predicate()).toBe(true);
}

describe("results equal open mode", () => {
  test("getBlockNumber, getBalance, call and a null result", async () => {
    const { server } = await harness(parityUpstream);
    const sealed = createPublicClient({ chain: arbitrum, transport: confidential(server) });
    const open = createPublicClient({
      chain: arbitrum,
      transport: vrpcHttp("http://open.invalid/eth_vrpc", {
        fetchFn: openFetch(parityUpstream),
        replayWindowMs: Number.MAX_SAFE_INTEGER,
        hardwareVerifier: mockHardwareVerifier(),
      }),
    });

    const run = (client: typeof open) =>
      Promise.all([
        client.getBlockNumber({ cacheTime: 0 }),
        client.getBalance({ address: ADDRESS }),
        client.call({ to: ADDRESS, data: "0x12345678" }),
        client.request({ method: "eth_getTransactionByHash", params: [TX_HASH] }),
      ]);

    const [sealedValues, openValues] = [await run(sealed), await run(open)];
    expect(sealedValues).toEqual(openValues);
    expect(sealedValues).toEqual([16n, 2_000_000_000_000_000_000n, { data: CALL_RESULT }, null]);
  });

  test("the answer is read from the raw bytes, never as text", async () => {
    const { server } = await harness();
    const fetchFn = async (url: string, init: RequestInit): Promise<Response> => {
      const response = await fetch(url, init);
      Object.defineProperty(response, "text", {
        value: () => {
          throw new Error("text() is not used");
        },
      });
      return response;
    };
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server, { fetchFn }),
    });

    await expect(client.getBlockNumber({ cacheTime: 0 })).resolves.toBe(16n);
  });
});

describe("errors", () => {
  const SENTINEL_PARAM = "sentinel-param";
  const request = { method: "eth_blockNumber", params: [SENTINEL_PARAM] } as const;

  function rpcError(code: number, message: string, status = 200): Upstream {
    return (call) => json({ jsonrpc: "2.0", id: call.id, error: { code, message } }, status);
  }

  function raw(status: number, contentType: string, body: string): Upstream {
    return () => ({ status, headers: { "content-type": contentType }, body });
  }

  const cases: Array<{
    name: string;
    upstream: Upstream;
    type: typeof RpcRequestError | typeof HttpRequestError;
    code?: number;
    status?: number;
  }> = [
    {
      name: "an inner 200 with an error member",
      upstream: rpcError(-32603, "m"),
      type: RpcRequestError,
      code: -32603,
    },
    {
      name: "an inner 500 with a JSON-RPC error body",
      upstream: rpcError(-32005, "limit exceeded", 500),
      type: RpcRequestError,
      code: -32005,
    },
    {
      name: "an inner 413 problem document",
      upstream: raw(
        413,
        "application/problem+json",
        '{"type":"urn:vrpc:error:batch-too-large","title":"sentinel-reply"}',
      ),
      type: HttpRequestError,
      status: 413,
    },
    {
      name: "an inner 502 text answer",
      upstream: raw(502, "text/plain", "sentinel-reply bad gateway"),
      type: HttpRequestError,
      status: 502,
    },
    {
      name: "an inner 200 with an empty body",
      upstream: raw(200, "application/json", ""),
      type: HttpRequestError,
      status: 200,
    },
    {
      name: "an inner 200 that is not JSON",
      upstream: raw(200, "application/json", "not json sentinel-reply"),
      type: HttpRequestError,
      status: 200,
    },
    {
      name: "an inner 200 with JSON null",
      upstream: raw(200, "application/json", "null"),
      type: HttpRequestError,
      status: 200,
    },
    {
      name: "an inner 200 whose error member is null",
      upstream: raw(200, "application/json", '{"jsonrpc":"2.0","id":1,"error":null}'),
      type: HttpRequestError,
      status: 200,
    },
    {
      name: "an inner 200 with a JSON array",
      upstream: raw(200, "application/json", '["sentinel-reply"]'),
      type: HttpRequestError,
      status: 200,
    },
  ];

  function expectClean(err: unknown): void {
    for (const text of texts(err)) {
      expect(text).not.toContain("sentinel-reply");
      expect(text).not.toContain(SENTINEL_PARAM);
      expect(text).not.toContain(KEY);
      expect(text).not.toContain("/eth_vrpc");
    }
  }

  test.each(cases)("$name rejects from the transport with the viem class", async (row) => {
    const { server } = await harness(row.upstream);
    const { config } = confidential(server)({ chain: arbitrum });

    const err = await rejectionOf(config.request(request));
    expect(err).toBeInstanceOf(row.type);
    if (row.code !== undefined) expect((err as RpcRequestError).code).toBe(row.code);
    if (row.status !== undefined) expect((err as HttpRequestError).status).toBe(row.status);
    expectClean(err);
  });

  test.each(cases)("$name reaches client.request with the viem class inside", async (row) => {
    const { server } = await harness(row.upstream);
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });

    const err = await rejectionOf(client.request(request as never));
    const found = walkFind(err, row.type);
    expect(found).toBeInstanceOf(row.type);
    if (row.code !== undefined) expect((found as RpcRequestError).code).toBe(row.code);
    if (row.status !== undefined) expect((found as HttpRequestError).status).toBe(row.status);
    expectClean(err);
  });

  test("a core error passes through unchanged", async () => {
    const { server } = await harness();
    server.answer((r) =>
      r.method === "POST"
        ? { status: 429, headers: { "content-type": "text/plain" }, body: "slow down" }
        : undefined,
    );
    const transport = confidential(server);

    const direct = await rejectionOf(transport({ chain: arbitrum }).config.request(request));
    expect(direct).toBeInstanceOf(RequestRejected);

    const client = createPublicClient({ chain: arbitrum, transport });
    const walked = walkFind(await rejectionOf(client.request(request as never)), RequestRejected);
    expect(walked).toBeInstanceOf(RequestRejected);
    expect(walked?.status).toBe(429);
    expect(walked?.executed).toBe("no");
  });
});

describe("headers", () => {
  test("a caller content-type is dropped and the key is sent on both requests", async () => {
    const { server } = await harness();
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server, {
        headers: { "x-api-key": KEY, "Content-Type": "application/json" },
      }),
    });

    await client.getBlockNumber({ cacheTime: 0 });

    const [get, post] = server.requests;
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
    expect(get?.headers["content-type"]).not.toBe("application/json");
    for (const r of server.requests) expect(r.headers["x-api-key"]).toBe(KEY);
  });
});

describe("signals", () => {
  test("a timeout rejects the call with a TimeoutError cause", async () => {
    const { server } = await harness();
    server.answer((r) => (r.method === "POST" ? new Promise(() => {}) : undefined));
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server, { timeout: 200 }),
    });

    const err = await rejectionOf(client.getBlockNumber({ cacheTime: 0 }));
    expect(walkFind(err, DOMException)?.name).toBe("TimeoutError");
  });

  test("a caller abort after the request was sent rejects the call with the caller's reason", async () => {
    const { server } = await harness();
    server.answer((r) => (r.method === "POST" ? new Promise(() => {}) : undefined));
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });
    const controller = new AbortController();
    const reason = new Error("caller abort");

    const pending = rejectionOf(
      client.request({ method: "eth_blockNumber" }, { signal: controller.signal }),
    );
    await until(() => server.requests.some((r) => r.method === "POST"));
    const abortedAt = Date.now();
    controller.abort(reason);
    const err = await pending;

    expect(Date.now() - abortedAt).toBeLessThan(2_000);
    const seen: unknown[] = [];
    for (
      let e: unknown = err;
      e != null && !seen.includes(e);
      e = (e as { cause?: unknown }).cause
    ) {
      seen.push(e);
    }
    expect(seen).toContain(reason);
  });

  test("concurrent calls sharing one caller signal hold one listener and warn nothing", async () => {
    const { server } = await harness();
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });
    await client.transport.ready();
    const warnings: unknown[] = [];
    const onWarning = (warning: unknown) => warnings.push(warning);
    process.on("warning", onWarning);
    cleanups.push(() => process.off("warning", onWarning));
    const controller = new AbortController();
    let peak = 0;
    server.answer((r) => {
      if (r.method === "POST") {
        peak = Math.max(peak, getEventListeners(controller.signal, "abort").length);
      }
      return undefined;
    });

    const calls = Array.from({ length: 20 }, () =>
      client.request({ method: "eth_blockNumber" }, { signal: controller.signal }),
    );
    await expect(Promise.all(calls)).resolves.toEqual(Array(20).fill("0x10"));
    await new Promise((r) => setImmediate(r));

    expect(peak).toBe(1);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
    expect(warnings).toEqual([]);
  });
});

describe("configuration errors", () => {
  const methods = ["log", "info", "warn", "error", "debug"] as const;

  function spyConsole() {
    const spies = methods.map((m) => vi.spyOn(console, m));
    cleanups.push(() => {
      for (const spy of spies) spy.mockRestore();
    });
    return () => spies.reduce((n, spy) => n + spy.mock.calls.length, 0);
  }

  test("a client without a chain throws InvalidChainId synchronously", async () => {
    const { server } = await harness();
    const consoleCalls = spyConsole();

    expect(() => createPublicClient({ transport: confidential(server) })).toThrow(InvalidChainId);
    expect(() => createPublicClient({ transport: fallback([confidential(server)]) })).toThrow(
      InvalidChainId,
    );
    expect(server.requests).toEqual([]);
    expect(consoleCalls()).toBe(0);
  });

  test("a second chain on the same transport throws; the same chain shares one attestation", async () => {
    const { server } = await harness();
    const transport = confidential(server);
    const first = createPublicClient({ chain: arbitrum, transport });

    expect(() => createPublicClient({ chain: mainnet, transport })).toThrow(InvalidChainId);
    const second = createPublicClient({ chain: arbitrum, transport });
    await first.getBlockNumber({ cacheTime: 0 });
    await second.getBlockNumber({ cacheTime: 0 });

    expect(server.requests.map((r) => r.method)).toEqual(["GET", "POST", "POST"]);
  });

  test("a non-boolean confidential option throws TypeError", async () => {
    const { server } = await harness();
    const consoleCalls = spyConsole();

    expect(() => vrpcHttp(`${server.url}/eth_vrpc`, { confidential: "true" } as never)).toThrow(
      TypeError,
    );
    expect(server.requests).toEqual([]);
    expect(consoleCalls()).toBe(0);
  });

  test("an invalid replay window or key cache TTL throws RangeError from vrpcHttp", async () => {
    const { server } = await harness();
    const consoleCalls = spyConsole();

    for (const name of ["replayWindowMs", "pubkeyCacheTtlMs"]) {
      for (const value of [0, -1, 1.5, Number.POSITIVE_INFINITY]) {
        expect(() =>
          vrpcHttp(`${server.url}/eth_vrpc`, { confidential: true, [name]: value }),
        ).toThrow(RangeError);
      }
    }
    expect(server.requests).toEqual([]);
    expect(consoleCalls()).toBe(0);
  });

  test("an unparsable URL throws Invalid vRPC URL without echoing it", () => {
    const consoleCalls = spyConsole();
    let caught: unknown;
    try {
      vrpcHttp("not a url sentinel-key", { confidential: true });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toBe("Invalid vRPC URL");
    for (const text of [(caught as Error).message, String(caught), unserialisable(caught)]) {
      expect(text).not.toContain("sentinel-key");
    }
    expect((caught as Error).cause).toBeUndefined();
    expect(consoleCalls()).toBe(0);
  });
});

describe("transport value", () => {
  test("ready() attests once and getConfidentialInfo() reports the pinned node", async () => {
    const { node, server } = await harness();
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });

    expect(client.transport.getConfidentialInfo()).toBeUndefined();
    const info = await client.transport.ready();
    expect(info).toMatchObject({ nodeId: NODE_ID, pubkey: node.pubkeyHex });
    expect(client.transport.getConfidentialInfo()).toEqual(info);
    await client.transport.ready();

    expect(server.requests.map((r) => r.method)).toEqual(["GET"]);
  });

  test("open mode has neither member", () => {
    const client = createPublicClient({
      chain: arbitrum,
      transport: vrpcHttp("http://open.invalid/eth_vrpc"),
    });

    expect("ready" in client.transport).toBe(false);
    expect("getConfidentialInfo" in client.transport).toBe(false);
  });
});

describe("attestation sharing", () => {
  test("fallback calls the factory per request and the calls still share one attestation", async () => {
    const { server } = await harness();
    const client = createPublicClient({
      chain: arbitrum,
      transport: fallback([confidential(server)], { retryCount: 0 }),
    });

    for (let i = 0; i < 3; i++) await client.getBlockNumber({ cacheTime: 0 });

    expect(server.requests.filter((r) => r.method === "GET")).toHaveLength(1);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(3);
  });

  test("ten concurrent first calls put one attestation and ten sealed requests on the wire", async () => {
    const { server } = await harness(rpc(() => "0x1"));
    const client = createPublicClient({ chain: arbitrum, transport: confidential(server) });

    const addresses = Array.from(
      { length: 10 },
      (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}` as const,
    );
    await expect(
      Promise.all(addresses.map((address) => client.getBalance({ address }))),
    ).resolves.toEqual(Array(10).fill(1n));

    expect(server.requests.filter((r) => r.method === "GET")).toHaveLength(1);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(10);
  });
});
