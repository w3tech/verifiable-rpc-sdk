// Ankr Confidential RPC mode with ethers on the wire: exactly one request per call whatever the
// gateway answers and whatever hooks the caller's FetchRequest carries, no redirect followed,
// identity encoding, no plaintext JSON-RPC, and transport errors without the key or body bytes.

import { DEFAULT_PHALA_VERIFY_ENDPOINT, TransportFailed } from "@w3tech.io/vrpc-core";
import { type VrpcOptions, VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { KEY, mockHardwareVerifier, rejectionOf } from "@w3tech.io/vrpc-test-support";
import {
  describeOneRequestPerCall,
  expectNoSecrets,
  expectSealedTrafficOnly,
} from "@w3tech.io/vrpc-test-support/adapter";
import {
  countOf,
  holdPosts,
  isPost,
  serveUpstream,
  type TestNodeServer,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support/server";
import { FetchRequest } from "ethers";
import { afterEach, describe, expect, test, vi } from "vitest";

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
  return async (request: Request) => {
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
  const server = await serveUpstream(rpcUpstream(result), options);
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

for (const flavour of FLAVOURS) {
  describeOneRequestPerCall(
    `one request per call: ${flavour}`,
    async () => {
      const server = await serve();
      const { provider, fetches } = build(flavour, server.url);
      return {
        server,
        call: () => provider.getBlockNumber(),
        ready: () => provider.confidentialReady(),
        fetched: flavour === "string URL" ? undefined : () => fetches.n,
      };
    },
    (err) => err,
  );
}

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
    expectSealedTrafficOnly(server.requests, [SENTINEL]);
  });
});

describe("transport errors carry neither the key nor body bytes", () => {
  test("a FetchRequest timeout while the sealed POST hangs", async () => {
    const server = await serve();
    const req = new FetchRequest(`${server.url}/eth_vrpc/${KEY}`);
    req.setHeader("x-api-key", KEY);
    req.timeout = 200;
    const provider = new VrpcProvider(req, 42161, {
      confidential: true,
      hardwareVerifier: mockHardwareVerifier(),
      cacheTimeout: -1,
    });
    cleanups.push(() => provider.destroy());
    await provider.confidentialReady();
    const sent = holdPosts(server);

    const err = await rejectionOf(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    const cause = (err as TransportFailed).cause as Error;
    expect(Object.getPrototypeOf(cause)).toBe(Error.prototype);
    expect(cause.message).toBe("The request failed.");
    expect({ ...cause }).toEqual({ code: "TIMEOUT" });
    expectNoSecrets([err, cause], [KEY], sent);
  });
});

describe("response size cap", () => {
  const CAP = 201_326_592;
  const CHUNK = new Uint8Array(16 * 1024 * 1024);

  test("a streamed body past the cap is cut and the call fails without reading on", async () => {
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
      return new Response(body, { status: 200 });
    });
    const { provider } = build("string URL", server.url);

    const err = await rejectionOf(provider.getBlockNumber());

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
    expect(seen.cancelled).toBe(true);
    expect(seen.pulled).toBeLessThanOrEqual(CAP + 2 * CHUNK.byteLength);
  });

  test("the attestation GET stops reading at its own 1 MiB cap", async () => {
    const chunk = new Uint8Array(64 * 1024);
    let pulled = 0;
    const pull = (controller: ReadableStreamDefaultController<Uint8Array>) => {
      pulled += chunk.byteLength;
      controller.enqueue(chunk);
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(new ReadableStream({ pull })));
    const { provider } = build("string URL", "http://127.0.0.1:9");

    const err = await rejectionOf(provider.getBlockNumber());

    expect(err).toMatchObject({ kind: "AttestationUnavailable", reason: "too-large" });
    expect(pulled).toBeLessThanOrEqual(1_048_576 + 2 * chunk.byteLength);
  });
});

describe("hardware verifier", () => {
  test("without a hardwareVerifier of its own the fetch option carries the cloud verify call", async () => {
    const server = await serve();
    const seen: string[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      seen.push(String(input));
      return new Response("", { status: 503 });
    };
    const provider = new VrpcProvider(`${server.url}/eth_vrpc/${KEY}`, 42161, {
      confidential: true,
      cacheTimeout: -1,
      fetch,
    });
    cleanups.push(() => provider.destroy());

    await rejectionOf(provider.getBlockNumber());

    expect(seen).toEqual([DEFAULT_PHALA_VERIFY_ENDPOINT]);
    expect(countOf(server, isPost)).toBe(0);
  });
});
