// Ankr Confidential RPC mode with viem on the wire: exactly one request per call whatever the
// gateway answers, also under fallback, no redirect followed, no plaintext JSON-RPC,
// and errors without the key, the params, the inner body or body bytes.

import {
  DEFAULT_PHALA_VERIFY_ENDPOINT,
  RequestRejected,
  UnexpectedResponse,
  VrpcError,
} from "@w3tech.io/vrpc-core";
import {
  countOf,
  isPost,
  jsonResponse,
  KEY,
  type RpcCall,
  rejectionOf,
  rpcUpstream,
  type TestUpstream,
} from "@w3tech.io/vrpc-test-support";
import {
  describeOneRequestPerCall,
  expectNoSecrets,
  expectSealedTrafficOnly,
} from "@w3tech.io/vrpc-test-support/adapter";
import {
  holdPosts,
  serveUpstream,
  type TestNodeServer,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support/server";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { BaseError, createPublicClient, fallback } from "viem";
import { describe, expect, onTestFinished, test } from "vitest";
import { arbitrum, confidential, walkFind } from "./fixtures";

const SENTINEL = "5e17e1a1";

type Mode = "client" | "fallback";

async function serve(
  options: TestNodeServerOptions = {},
  upstream: TestUpstream = rpcUpstream(() => "0x10"),
): Promise<TestNodeServer> {
  const server = await serveUpstream(upstream, options);
  onTestFinished(() => server.close());
  return server;
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

// The client mode is the default transport, covered by the core suite.
describeOneRequestPerCall(
  "one request per call through fallback",
  async () => {
    const server = await serve();
    const { client, ready } = build("fallback", `${server.url}/eth_vrpc`);
    return { server, ready, call: () => client.getBlockNumber({ cacheTime: 0 }) };
  },
  (err) => walkFind(err, VrpcError),
);

describe("wire invariant", () => {
  test("only attestation GETs and sealed POSTs leave, with no JSON-RPC in clear", async () => {
    const server = await serve(
      {},
      rpcUpstream((call) => {
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

    expect(countOf(server, isPost)).toBe(5);
    expectSealedTrafficOnly(server.requests, [SENTINEL]);
  });
});

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

function expectSanitised(err: unknown, bodies: Uint8Array[]): void {
  expectNoSecrets(chain(err), [KEY, "sentinel-param", "sentinel-reply"], bodies);
}

const sweepRequest = { method: "eth_blockNumber", params: ["sentinel-param"] } as const;

function keyed(origin: string, timeout?: number) {
  const transport = confidential(
    `${origin}/eth_vrpc/${KEY}`,
    timeout === undefined ? {} : { timeout },
  );
  return createPublicClient({ chain: arbitrum, transport });
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
  test("a timeout while the sealed POST hangs", async () => {
    const server = await serve();
    const client = keyed(server.url, 200);
    await client.transport.ready();
    const sent = holdPosts(server);

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
    const server = await serve({}, async (request) => {
      const call = (await request.json()) as RpcCall;
      return jsonResponse({
        jsonrpc: "2.0",
        id: call.id,
        error: { code: -32000, message: "boom" },
      });
    });
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
    expect(countOf(server, isPost)).toBe(0);
  });
});
