// Ankr Confidential RPC mode with ethers on the wire: exactly one request per call whatever the
// gateway answers and whatever hooks the caller's FetchRequest carries, no redirect followed,
// identity encoding, no plaintext JSON-RPC, and transport errors without the key or body bytes.

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  AttestationUnavailable,
  RequestRejected,
  TransportFailed,
  UnexpectedResponse,
} from "@w3tech.io/vrpc-core";
import { type VrpcOptions, VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { FetchRequest } from "ethers";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  createTestNode,
  type ServedAnswer,
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
  type TestNodeServerOptions,
  type TestUpstreamResponse,
} from "../../test-support/src/index";
import { CHAIN_ID, TEST_SEED } from "./fixtures";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const NODE_ID = "alpha-vrpc-1";
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const SENTINEL = "5e17e1a1";

type Flavour =
  | "string URL"
  | "FetchRequest with its own getUrlFunc"
  | "FetchRequest with hostile hooks";
const FLAVOURS: Flavour[] = [
  "string URL",
  "FetchRequest with its own getUrlFunc",
  "FetchRequest with hostile hooks",
];

interface Built {
  provider: VrpcProvider;
  fetches: { n: number };
}

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  vi.restoreAllMocks();
});

interface RpcCall {
  id: number;
  method: string;
}

function rpcUpstream(result: (call: RpcCall) => unknown) {
  return async (request: Request): Promise<TestUpstreamResponse> => {
    const parsed = JSON.parse(await request.text()) as RpcCall | RpcCall[];
    const answer = (call: RpcCall) => ({ jsonrpc: "2.0", id: call.id, result: result(call) });
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(Array.isArray(parsed) ? parsed.map(answer) : answer(parsed)),
    };
  };
}

async function serve(
  options: TestNodeServerOptions = {},
  result: (call: RpcCall) => unknown = () => "0x10",
): Promise<TestNodeServer> {
  const node = createTestNode({
    seed: TEST_SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    upstream: rpcUpstream(result),
  });
  const server = await serveTestNode(node, options);
  cleanups.push(() => server.close());
  return server;
}

function build(flavour: Flavour, origin: string, options: VrpcOptions = {}): Built {
  const fetches = { n: 0 };
  let url: string | FetchRequest = `${origin}/eth_vrpc/${KEY}`;
  if (flavour !== "string URL") {
    const req = new FetchRequest(`${origin}/eth_vrpc`);
    req.setHeader("x-api-key", KEY);
    const base = FetchRequest.createGetUrlFunc();
    req.getUrlFunc = async (sent, signal) => {
      fetches.n += 1;
      return base(sent, signal);
    };
    if (flavour === "FetchRequest with hostile hooks") {
      req.retryFunc = async () => true;
      req.processFunc = async (_sent, response) => response.throwThrottleError("slow down", 0);
    }
    url = req;
  }
  const provider = new VrpcProvider(url, 42161, {
    confidential: true,
    hardwareVerifier: mockHardwareVerifier(),
    cacheTimeout: -1,
    ...options,
  });
  cleanups.push(() => provider.destroy());
  return { provider, fetches };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected a rejection");
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

describe.each(FLAVOURS)("one request per call: %s", (flavour) => {
  test.each([
    429, 301, 302, 303, 307, 308, 500, 502, 503, 504,
  ])("the sealed POST answered %i is sent once and no redirect is followed", async (status) => {
    const server = await serve();
    const { provider, fetches } = build(flavour, server.url);
    await provider.confidentialReady();
    server.requests.splice(0);
    fetches.n = 0;
    server.answer((request) => (isPost(request) ? answerFor(server, status) : undefined));

    const err = await rejection(provider.getBlockNumber());

    expect(count(server, isPost)).toBe(1);
    expect(count(server, isElsewhere)).toBe(0);
    expect(server.requests).toHaveLength(1);
    if (flavour !== "string URL") expect(fetches.n).toBe(server.requests.length);
    if (status === 429) {
      expect(err).toBeInstanceOf(RequestRejected);
      expect((err as RequestRejected).status).toBe(429);
      expect((err as RequestRejected).executed).toBe("no");
    } else {
      expect(err).toBeInstanceOf(UnexpectedResponse);
      expect((err as UnexpectedResponse).status).toBe(status);
    }
  });

  test.each([
    429, 302, 307, 502,
  ])("the cold attestation answered %i is sent once and nothing is sealed", async (status) => {
    const server = await serve();
    const { provider, fetches } = build(flavour, server.url);
    server.answer((request) => (isGet(request) ? answerFor(server, status) : undefined));

    const err = await rejection(provider.getBlockNumber());

    expect(count(server, isGet)).toBe(1);
    expect(count(server, isPost)).toBe(0);
    expect(count(server, isElsewhere)).toBe(0);
    if (flavour !== "string URL") expect(fetches.n).toBe(server.requests.length);
    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("status");
    expect((err as AttestationUnavailable).status).toBe(status);
  });
});

describe("base fetcher", () => {
  test("without its own getUrlFunc the request uses a non-following fetch", async () => {
    const server = await serve();
    const created = vi.spyOn(FetchRequest, "createGetUrlFunc");
    const fetched = vi.spyOn(globalThis, "fetch");
    const { provider } = build("string URL", server.url);

    await provider.getBlockNumber();

    expect(created).not.toHaveBeenCalled();
    expect(fetched).toHaveBeenCalledTimes(2);
    for (const [, init] of fetched.mock.calls) expect(init?.redirect).toBe("manual");
  });

  test("the caller's own getUrlFunc is wrapped, not replaced", async () => {
    const server = await serve();
    const { provider, fetches } = build("FetchRequest with its own getUrlFunc", server.url);
    const spy = vi.spyOn(FetchRequest, "createGetUrlFunc");

    await provider.getBlockNumber();

    expect(spy).not.toHaveBeenCalled();
    expect(fetches.n).toBe(2);
  });

  test("a getUrl registered with FetchRequest.registerGetUrl is wrapped, not replaced", async () => {
    const server = await serve();
    const stock = new FetchRequest("http://localhost").getUrlFunc;
    const base = FetchRequest.createGetUrlFunc();
    const registered = { n: 0 };
    FetchRequest.registerGetUrl(async (sent, signal) => {
      registered.n += 1;
      return base(sent, signal);
    });
    cleanups.push(() => FetchRequest.registerGetUrl(stock));
    const { provider } = build("string URL", server.url);

    await provider.getBlockNumber();

    expect(registered.n).toBe(2);
  });
});

describe("encoding", () => {
  test.each([
    "string URL",
    "FetchRequest with its own getUrlFunc",
  ] as const)("%s asks for identity and gets no gzip from a gzip-capable gateway", async (flavour) => {
    const server = await serve({ gzipWhenAccepted: true });
    const { provider } = build(flavour, server.url);

    await expect(provider.getBlockNumber()).resolves.toBe(16);
    await expect(provider.getBlockNumber()).resolves.toBe(16);

    expect(server.requests).toHaveLength(3);
    for (const request of server.requests) {
      expect(request.headers["accept-encoding"]).toBe("identity");
      expect(request.gzipped).toBe(false);
    }
  });
});

describe("wire invariant", () => {
  test("only attestation GETs and sealed POSTs leave, with no JSON-RPC in clear", async () => {
    let block = 0;
    const server = await serve({}, (call) => {
      if (call.method === "eth_blockNumber") {
        block += 1;
        return `0x${block.toString(16)}`;
      }
      if (call.method === "eth_call") return "0x2a";
      return "0x1";
    });
    const { provider } = build("FetchRequest with its own getUrlFunc", server.url, {
      pollingInterval: 50,
    });
    const sentinelAddress = `0x${SENTINEL.repeat(5)}`;
    const data = `0x12345678${SENTINEL.repeat(8)}`;

    await provider.getBlockNumber();
    await provider.getBalance(sentinelAddress);
    await provider.call({ to: sentinelAddress, data });
    await Promise.all([
      provider.getBlockNumber(),
      provider.getBalance(sentinelAddress),
      provider.call({ to: sentinelAddress, data }),
    ]);
    const before = server.requests.length;
    await provider.getNetwork();
    expect(server.requests).toHaveLength(before);
    await new Promise<void>((resolve) => {
      void provider.once("block", () => resolve());
    });
    await provider.removeAllListeners();

    expect(server.requests.length).toBeGreaterThan(before);
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
  const e = err as Error;
  return [
    e.message,
    String(e),
    e.stack ?? "",
    JSON.stringify(e, (_key, value) => (typeof value === "bigint" ? value.toString() : value)),
  ];
}

function causes(err: unknown): unknown[] {
  const out: unknown[] = [];
  let current = (err as { cause?: unknown }).cause;
  while (current !== undefined && current !== null) {
    out.push(current);
    current = (current as { cause?: unknown }).cause;
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

function expectSanitised(
  err: unknown,
  bodies: Uint8Array[],
  code?: string | readonly string[],
): void {
  const chain = causes(err);
  expect(chain.length).toBeGreaterThan(0);
  const secrets = [KEY, ...bodies.flatMap(windows)];
  for (const item of [err, ...chain]) {
    for (const form of textForms(item)) {
      for (const secret of secrets) expect(form).not.toContain(secret);
    }
  }
  for (const cause of chain) {
    expect(Object.getPrototypeOf(cause)).toBe(Error.prototype);
    expect(typeof (cause as Error).message).toBe("string");
    expect(cause).not.toHaveProperty("request");
    expect(cause).not.toHaveProperty("response");
    expect(cause).not.toHaveProperty("info");
    const causeCode = (cause as { code?: unknown }).code;
    expect(causeCode === undefined || typeof causeCode === "string").toBe(true);
  }
  if (code !== undefined) expect([code].flat()).toContain((chain[0] as { code?: unknown }).code);
}

function keyedBoth(origin: string, timeout?: number): VrpcProvider {
  const req = new FetchRequest(`${origin}/eth_vrpc/${KEY}`);
  req.setHeader("x-api-key", KEY);
  if (timeout !== undefined) req.timeout = timeout;
  const provider = new VrpcProvider(req, 42161, {
    confidential: true,
    hardwareVerifier: mockHardwareVerifier(),
    cacheTimeout: -1,
  });
  cleanups.push(() => provider.destroy());
  return provider;
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

describe("transport errors carry neither the key nor body bytes", () => {
  test("a dropped connection on the cold attestation", async () => {
    const provider = keyedBoth(await droppingEveryConnection());

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("transport");
    // undici reports the dropped socket as either code, by timing and Node version.
    expectSanitised(err, [], ["ECONNRESET", "UND_ERR_SOCKET"]);
  });

  test("a sealed answer cut after half its body", async () => {
    const server = await serve();
    const provider = keyedBoth(server.url);
    await provider.confidentialReady();
    const sent: Uint8Array[] = [];
    server.answer(async (request, forward) => {
      if (!isPost(request)) return undefined;
      const answer = await forward();
      sent.push(request.body, answer.body);
      return { ...answer, cutAfter: answer.body.byteLength >> 1 };
    });

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    expectSanitised(err, sent);
  });

  test("a FetchRequest timeout while the sealed POST hangs", async () => {
    const server = await serve();
    const provider = keyedBoth(server.url, 200);
    await provider.confidentialReady();
    const sent: Uint8Array[] = [];
    server.answer((request) => {
      if (!isPost(request)) return undefined;
      sent.push(request.body);
      return new Promise<undefined>(() => {});
    });

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    expectSanitised(err, sent, "TIMEOUT");
  });

  test("a getUrlFunc that throws with the keyed URL in its message", async () => {
    const server = await serve();
    const req = new FetchRequest(`${server.url}/eth_vrpc/${KEY}`);
    const base = FetchRequest.createGetUrlFunc();
    req.getUrlFunc = async (sent, signal) => {
      if (sent.method !== "POST") return base(sent, signal);
      throw Object.assign(new Error(`request to ${sent.url} failed, reason: socket hang up`), {
        code: "ECONNRESET",
        cause: new Error(`connect to ${sent.url}`),
      });
    };
    const provider = new VrpcProvider(req, 42161, {
      confidential: true,
      hardwareVerifier: mockHardwareVerifier(),
      cacheTimeout: -1,
    });
    cleanups.push(() => provider.destroy());

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    expectSanitised(err, [], "ECONNRESET");
    for (const item of [err, ...causes(err)]) {
      for (const form of textForms(item)) expect(form).not.toContain("/eth_vrpc/");
    }
  });

  test("a gzip-labelled answer whose body is not gzip", async () => {
    const server = await serve();
    const provider = keyedBoth(server.url);
    await provider.confidentialReady();
    const sent: Uint8Array[] = [];
    server.answer(async (request, forward) => {
      if (!isPost(request)) return undefined;
      const answer = await forward();
      sent.push(request.body, answer.body);
      return { ...answer, headers: { ...answer.headers, "content-encoding": "gzip" } };
    });

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    expectSanitised(err, sent);
  });
});

describe("response size cap", () => {
  const CAP = 201_326_592;
  const CHUNK = new Uint8Array(16 * 1024 * 1024);

  test.each([
    { name: "a streamed body past the cap", headers: {} },
    {
      name: "a declared identity length past the cap",
      headers: { "content-length": `${CAP + 1}` },
    },
  ])("$name is cut and the call fails without reading on", async ({ headers }) => {
    const server = await serve();
    const seen = { pulled: 0, cancelled: false };
    const original = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      if (init?.method !== "POST") return original(input, init);
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
    });
    const { provider } = build("string URL", server.url);

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
    expect(seen.cancelled).toBe(true);
    expect(seen.pulled).toBeLessThanOrEqual(CAP + 2 * CHUNK.byteLength);
  });
});

describe("responses without a web stream body", () => {
  const CAP = 201_326_592;

  // A fetch polyfill (whatwg-fetch, React Native) answers with no stream body.
  function streamless(
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
      body: undefined,
      arrayBuffer: async () => {
        seen.buffered += 1;
        return bytes.slice().buffer;
      },
    } as unknown as Response;
  }

  test("the body is read in full", async () => {
    const server = await serve();
    const seen = { buffered: 0 };
    const original = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const response = await original(input, init);
      const bytes = new Uint8Array(await response.arrayBuffer());
      return streamless(response.status, response.headers, bytes, seen);
    });
    const { provider } = build("string URL", server.url);

    await expect(provider.getBlockNumber()).resolves.toBe(16);
    expect(seen.buffered).toBe(server.requests.length);
    expect(count(server, isPost)).toBe(1);
  });

  test.each([
    ["declared", { "content-length": `${CAP + 1}` }, 0] as const,
    ["read", {}, CAP + 1] as const,
  ])("a body past the cap (%s) fails the call", async (past, headers, size) => {
    const server = await serve();
    const seen = { buffered: 0 };
    const original = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      if (init?.method !== "POST") return original(input, init);
      return streamless(200, new Headers(headers), new Uint8Array(size), seen);
    });
    const { provider } = build("string URL", server.url);

    const err = await rejection(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
    expect(seen.buffered).toBe(past === "read" ? 1 : 0);
  });
});
