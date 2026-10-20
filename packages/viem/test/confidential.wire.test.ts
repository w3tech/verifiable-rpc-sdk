// Ankr Confidential RPC mode with viem on the wire: exactly one request per call whatever the
// gateway answers, also under fallback, no redirect followed, decoded answers, no plaintext JSON-RPC,
// and errors without the key, the params, the inner body or body bytes.

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import {
  AttestationUnavailable,
  DEFAULT_PHALA_VERIFY_ENDPOINT,
  RequestRejected,
  TransportFailed,
  UnexpectedResponse,
} from "@w3tech.io/vrpc-core";
import {
  CHAIN_ID,
  createTestNode,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  TEST_SEED,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import {
  type ServedAnswer,
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support/server";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { BaseError, createPublicClient, defineChain, fallback } from "viem";
import { afterEach, describe, expect, test } from "vitest";

const SENTINEL = "5e17e1a1";

const arbitrum = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

type Mode = "client" | "fallback";
const MODES: Mode[] = ["client", "fallback"];

interface RpcCall {
  id: number;
  method: string;
}

type Upstream = (call: RpcCall) => TestUpstreamResponse;

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function result(value: (call: RpcCall) => unknown): Upstream {
  return (call) => ({
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: call.id, result: value(call) }),
  });
}

async function serve(
  options: TestNodeServerOptions = {},
  upstream: Upstream = result(() => "0x10"),
): Promise<TestNodeServer> {
  const node = createTestNode({
    seed: TEST_SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    upstream: async (request) => upstream(JSON.parse(await request.text()) as RpcCall),
  });
  const server = await serveTestNode(node, options);
  cleanups.push(() => server.close());
  return server;
}

function confidential(url: string, options: Parameters<typeof vrpcHttp>[1] = {}) {
  return vrpcHttp(url, {
    headers: { "x-api-key": KEY },
    hardwareVerifier: mockHardwareVerifier(),
    ...options,
    confidential: true,
  });
}

function build(mode: Mode, url: string, options: Parameters<typeof vrpcHttp>[1] = {}) {
  const transport = confidential(url, options);
  if (mode === "client") {
    const client = createPublicClient({ chain: arbitrum, transport });
    return { client, ready: () => client.transport.ready() };
  }
  const client = createPublicClient({
    chain: arbitrum,
    transport: fallback([transport], { retryCount: 0 }),
  });
  const inner = client.transport.transports[0]?.value as { ready(): Promise<unknown> };
  return { client, ready: () => inner.ready() };
}

function walkFind<T>(err: unknown, type: abstract new (...args: never[]) => T): T | undefined {
  if (err instanceof type) return err;
  if (!(err instanceof BaseError)) return undefined;
  return (err.walk((e) => e instanceof type) as T | null) ?? undefined;
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

describe.each(MODES)("one request per call through %s", (mode) => {
  test.each([
    429, 301, 302, 303, 307, 308, 500, 502, 503, 504,
  ])("the sealed POST answered %i is sent once and no redirect is followed", async (status) => {
    const server = await serve();
    const { client, ready } = build(mode, `${server.url}/eth_vrpc`);
    await ready();
    server.requests.splice(0);
    server.answer((request) => (isPost(request) ? answerFor(server, status) : undefined));

    const err = await rejectionOf(client.getBlockNumber({ cacheTime: 0 }));

    expect(count(server, isPost)).toBe(1);
    expect(count(server, isElsewhere)).toBe(0);
    expect(server.requests).toHaveLength(1);
    if (status === 429) {
      const rejected = walkFind(err, RequestRejected);
      expect(rejected).toBeInstanceOf(RequestRejected);
      expect(rejected?.status).toBe(429);
      expect(rejected?.executed).toBe("no");
    } else {
      const unexpected = walkFind(err, UnexpectedResponse);
      expect(unexpected).toBeInstanceOf(UnexpectedResponse);
      expect(unexpected?.status).toBe(status);
    }
  });

  test.each([
    429, 302, 307, 502,
  ])("the cold attestation answered %i is sent once and nothing is sealed", async (status) => {
    const server = await serve();
    const { client } = build(mode, `${server.url}/eth_vrpc`);
    server.answer((request) => (isGet(request) ? answerFor(server, status) : undefined));

    const err = await rejectionOf(client.getBlockNumber({ cacheTime: 0 }));

    expect(count(server, isGet)).toBe(1);
    expect(count(server, isPost)).toBe(0);
    expect(count(server, isElsewhere)).toBe(0);
    const unavailable = walkFind(err, AttestationUnavailable);
    expect(unavailable).toBeInstanceOf(AttestationUnavailable);
    expect(unavailable?.reason).toBe("status");
  });
});

describe("encoding", () => {
  test("gzipped answers from a gzip-capable gateway are decoded and verified", async () => {
    const server = await serve({ gzipWhenAccepted: true });
    const { client } = build("client", `${server.url}/eth_vrpc`);

    await expect(client.getBlockNumber({ cacheTime: 0 })).resolves.toBe(16n);
    await expect(client.getBlockNumber({ cacheTime: 0 })).resolves.toBe(16n);

    expect(server.requests.some((r) => r.gzipped)).toBe(true);
  });
});

describe("wire invariant", () => {
  test("only attestation GETs and sealed POSTs leave, with no JSON-RPC in clear", async () => {
    const server = await serve(
      {},
      result((call) => {
        if (call.method === "eth_call") return "0x2a";
        if (call.method === "eth_chainId") return "0xa4b1";
        return "0x1";
      }),
    );
    const { client } = build("client", `${server.url}/eth_vrpc`);
    const sentinelAddress = `0x${SENTINEL.repeat(5)}` as const;
    const data = `0x12345678${SENTINEL.repeat(8)}` as const;

    await client.getBlockNumber({ cacheTime: 0 });
    await client.getBalance({ address: sentinelAddress });
    await client.call({ to: sentinelAddress, data });
    await client.getChainId();
    await client.request({ method: "eth_getCode", params: [sentinelAddress, "latest"] });

    expect(count(server, isPost)).toBe(5);
    const hex = (text: string) => Buffer.from(text, "utf8").toString("hex");
    for (const request of server.requests) {
      const query = new URLSearchParams(request.url.split("?")[1] ?? "");
      if (request.method === "GET") {
        expect(request.path.endsWith("/attestation")).toBe(true);
        expect(query.has("nonce")).toBe(true);
      } else {
        expect(request.method).toBe("POST");
        expect(request.path.endsWith("/confidential")).toBe(true);
        expect(query.has("node_id")).toBe(true);
        expect(request.headers["content-type"]).toBe("message/ohttp-req");
      }
      const bodyText = Buffer.from(request.body).toString("utf8");
      const bodyHex = Buffer.from(request.body).toString("hex");
      // The route prefix is the caller's own URL; everything after it is checked.
      const afterRoute = request.url.replace(/^\/eth_vrpc\//, "/");
      for (const needle of ["eth_", "jsonrpc", SENTINEL]) {
        expect(afterRoute).not.toContain(needle);
        expect(bodyText).not.toContain(needle);
        expect(bodyHex).not.toContain(hex(needle));
      }
      expect(bodyHex).not.toContain(SENTINEL);
    }
  });
});

function textForms(err: unknown): string[] {
  if (typeof err !== "object" || err === null) return [String(err)];
  const e = err as Error;
  let json: string;
  try {
    json =
      JSON.stringify(e, (_key, value) => (typeof value === "bigint" ? value.toString() : value)) ??
      "";
  } catch {
    json = "unserialisable";
  }
  return [String(e.message), String(e), String(e.stack ?? ""), json];
}

// The error, every cause below it and every error viem's walk visits.
function chain(err: unknown): unknown[] {
  const out: unknown[] = [];
  let current: unknown = err;
  while (current !== undefined && current !== null && !out.includes(current)) {
    out.push(current);
    current = (current as { cause?: unknown }).cause;
  }
  if (err instanceof BaseError) {
    err.walk((e) => {
      if (!out.includes(e)) out.push(e);
      return false;
    });
  }
  return out;
}

function windows(bytes: Uint8Array): string[] {
  const out: string[] = [];
  for (let offset = 0; offset + 16 <= bytes.byteLength; offset += 16) {
    out.push(Buffer.from(bytes.subarray(offset, offset + 16)).toString("hex"));
  }
  return out;
}

function expectSanitised(err: unknown, bodies: Uint8Array[]): void {
  const secrets = [KEY, "sentinel-param", "sentinel-reply", ...bodies.flatMap(windows)];
  const items = chain(err);
  expect(items.length).toBeGreaterThan(0);
  for (const item of items) {
    for (const form of textForms(item)) {
      for (const secret of secrets) expect(form).not.toContain(secret);
    }
  }
}

const sweepRequest = { method: "eth_blockNumber", params: ["sentinel-param"] } as const;

function keyed(origin: string, timeout?: number) {
  const transport = confidential(
    `${origin}/eth_vrpc/${KEY}`,
    timeout === undefined ? {} : { timeout },
  );
  return createPublicClient({ chain: arbitrum, transport });
}

// Stays bound and drops every connection, so no other process can take the port.
async function droppingEveryConnection(): Promise<string> {
  const server = createServer();
  server.on("connection", (socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => {
    server.closeAllConnections();
    server.close();
  });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

// Records the outer request and response bodies of every sealed POST.
function recordBodies(server: TestNodeServer, sent: Uint8Array[]): void {
  server.answer(async (request, forward) => {
    if (!isPost(request)) return undefined;
    const answer = await forward();
    sent.push(request.body, answer.body);
    return answer;
  });
}

describe("errors carry neither the key, the params, the inner body nor body bytes", () => {
  test("a dropped connection on the cold attestation", async () => {
    const client = keyed(await droppingEveryConnection());

    const err = await rejectionOf(client.request(sweepRequest as never));

    expect(walkFind(err, AttestationUnavailable)?.reason).toBe("transport");
    expectSanitised(err, []);
  });

  test("a sealed answer cut after half its body", async () => {
    const server = await serve();
    const client = keyed(server.url);
    await client.transport.ready();
    const sent: Uint8Array[] = [];
    server.answer(async (request, forward) => {
      if (!isPost(request)) return undefined;
      const answer = await forward();
      sent.push(request.body, answer.body);
      return { ...answer, cutAfter: answer.body.byteLength >> 1 };
    });

    const err = await rejectionOf(client.request(sweepRequest as never));

    expect(walkFind(err, TransportFailed)?.reason).toBe("network");
    expectSanitised(err, sent);
  });

  test("a timeout while the sealed POST hangs", async () => {
    const server = await serve();
    const client = keyed(server.url, 200);
    await client.transport.ready();
    const sent: Uint8Array[] = [];
    server.answer((request) => {
      if (!isPost(request)) return undefined;
      sent.push(request.body);
      return new Promise<undefined>(() => {});
    });

    const err = await rejectionOf(client.request(sweepRequest as never));

    expect(walkFind(err, DOMException)?.name).toBe("TimeoutError");
    expectSanitised(err, sent);
  });

  test.each([413, 500])("an inner %i with a text body", async (status) => {
    const server = await serve({}, () => ({
      status,
      headers: { "content-type": "text/plain" },
      body: "sentinel-reply from the node",
    }));
    const client = keyed(server.url);
    const sent: Uint8Array[] = [];
    recordBodies(server, sent);

    const err = await rejectionOf(client.request(sweepRequest as never));

    expect((walkFind(err, BaseError) as { status?: number } | undefined)?.status).toBe(status);
    expectSanitised(err, sent);
  });

  test("an inner error member", async () => {
    const server = await serve({}, (call) => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: call.id,
        error: { code: -32000, message: "boom" },
      }),
    }));
    const client = keyed(server.url);
    const sent: Uint8Array[] = [];
    recordBodies(server, sent);

    const err = await rejectionOf(client.request(sweepRequest as never));

    expect((err as { code?: number }).code).toBe(-32000);
    expectSanitised(err, sent);
  });

  test.each([429, 502])("a sealed POST answered %i", async (status) => {
    const server = await serve();
    const client = keyed(server.url);
    await client.transport.ready();
    const sent: Uint8Array[] = [];
    server.answer((request) => {
      if (!isPost(request)) return undefined;
      sent.push(request.body);
      return {
        status,
        headers: { "content-type": "text/plain" },
        body: "sentinel-reply from the gateway",
      };
    });

    const err = await rejectionOf(client.request(sweepRequest as never));

    const core = status === 429 ? RequestRejected : UnexpectedResponse;
    expect(walkFind<Error>(err, core)).toBeInstanceOf(core);
    expectSanitised(err, sent);
  });

  test("a custom fetchFn that throws with the keyed URL in its message", async () => {
    const server = await serve();
    const fetchFn: typeof fetch = async (input, init) => {
      if (init?.method !== "POST") return fetch(input, init);
      const url = String(input);
      throw Object.assign(new Error(`request to ${url} failed, reason: socket hang up`), {
        code: "ECONNRESET",
        cause: new Error(`connect to ${url}`),
      });
    };
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(`${server.url}/eth_vrpc/${KEY}`, { fetchFn }),
    });

    const err = await rejectionOf(client.request(sweepRequest as never));

    const failed = walkFind(err, TransportFailed);
    expect(failed?.reason).toBe("network");
    expect((failed?.cause as { code?: string } | undefined)?.code).toBe("ECONNRESET");
    expectSanitised(err, []);
    for (const item of chain(err)) {
      for (const form of textForms(item)) expect(form).not.toContain("/eth_vrpc/");
    }
  });
});

describe("response size cap", () => {
  const CAP = 201_326_592;
  const CHUNK = new Uint8Array(16 * 1024 * 1024);

  // Answers the sealed POST with an endless body, optionally declaring a length.
  function endless(headers: Record<string, string>) {
    const seen = { pulled: 0, cancelled: false };
    const fetchFn: typeof fetch = async (input, init) => {
      if (init?.method !== "POST") return fetch(input, init);
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          seen.pulled += CHUNK.byteLength;
          controller.enqueue(CHUNK);
        },
        cancel() {
          seen.cancelled = true;
        },
      });
      return new Response(body, { status: 200, headers });
    };
    return { fetchFn, seen };
  }

  test.each([
    { name: "a streamed body past the cap", headers: {} },
    {
      name: "a declared identity length past the cap",
      headers: { "content-length": `${CAP + 1}` },
    },
  ])("$name is cut and the call fails without reading on", async ({ headers }) => {
    const server = await serve();
    const { fetchFn, seen } = endless(headers);
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server.url, { fetchFn }),
    });

    const err = await rejectionOf(client.request({ method: "eth_blockNumber" }));

    expect(walkFind(err, TransportFailed)?.reason).toBe("too-large");
    expect(seen.cancelled).toBe(true);
    expect(seen.pulled).toBeLessThanOrEqual(CAP + 2 * CHUNK.byteLength);
  });
});

describe("responses without a web stream body", () => {
  const CAP = 201_326_592;
  type Shape = "a Node Readable" | "an absent";
  const SHAPES: Shape[] = ["a Node Readable", "an absent"];

  // node-fetch answers with a Node Readable body, whatwg-fetch and React Native with none.
  function streamless(
    shape: Shape,
    status: number,
    headers: Headers,
    bytes: Uint8Array,
    seen: { buffered: number },
  ): Response {
    return {
      status,
      statusText: "",
      ok: status >= 200 && status < 300,
      type: "basic",
      headers,
      body: shape === "an absent" ? undefined : Readable.from([bytes]),
      arrayBuffer: async () => {
        seen.buffered += 1;
        return bytes.slice().buffer;
      },
    } as unknown as Response;
  }

  test.each(SHAPES)("%s body is read in full", async (shape) => {
    const server = await serve();
    const seen = { buffered: 0 };
    const fetchFn: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      const bytes = new Uint8Array(await response.arrayBuffer());
      return streamless(shape, response.status, response.headers, bytes, seen);
    };
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server.url, { fetchFn }),
    });

    await expect(client.request({ method: "eth_blockNumber" })).resolves.toBe("0x10");
    expect(seen.buffered).toBe(server.requests.length);
    expect(count(server, isPost)).toBe(1);
  });

  test.each(
    SHAPES.flatMap((shape) => [
      [shape, "declared", { "content-length": `${CAP + 1}` }, 0] as const,
      [shape, "read", {}, CAP + 1] as const,
    ]),
  )("%s body past the cap (%s) fails the call", async (shape, past, headers, size) => {
    const server = await serve();
    const seen = { buffered: 0 };
    const fetchFn: typeof fetch = async (input, init) => {
      if (init?.method !== "POST") return fetch(input, init);
      return streamless(shape, 200, new Headers(headers), new Uint8Array(size), seen);
    };
    const client = createPublicClient({
      chain: arbitrum,
      transport: confidential(server.url, { fetchFn }),
    });

    const err = await rejectionOf(client.request({ method: "eth_blockNumber" }));

    expect(walkFind(err, TransportFailed)?.reason).toBe("too-large");
    expect(seen.buffered).toBe(past === "read" ? 1 : 0);
  });
});

describe("hardware verifier", () => {
  test("without a hardwareVerifier of its own the fetchFn also carries the cloud verify call", async () => {
    const server = await serve();
    const seen: string[] = [];
    const fetchFn: typeof fetch = async (input, init) => {
      seen.push(String(input));
      if (String(input) === DEFAULT_PHALA_VERIFY_ENDPOINT) return new Response("", { status: 503 });
      return fetch(input, init);
    };
    const client = createPublicClient({
      chain: arbitrum,
      transport: vrpcHttp(server.url, {
        headers: { "x-api-key": KEY },
        fetchFn,
        confidential: true,
      }),
    });

    await rejectionOf(client.request({ method: "eth_blockNumber" }));

    expect(seen).toContain(DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(count(server, isPost)).toBe(0);
  });
});
