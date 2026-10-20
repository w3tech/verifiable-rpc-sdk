import { getEventListeners } from "node:events";
import { createServer, type IncomingHttpHeaders, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { gzipSync } from "node:zlib";
import { hexToBytes } from "@noble/hashes/utils.js";
import {
  createTestNode,
  mockHardwareVerifier,
  type TestNode,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import {
  AttestationUnavailable,
  BadSignature,
  TransportFailed,
  UnexpectedResponse,
} from "../src/errors";
import { type ConfidentialTransport, defaultTransport } from "../src/transport";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const NODE_ID = "alpha-vrpc-1";
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const OVER_CAP = 201326593;
const MIB = 1024 * 1024;
const utf8 = new TextEncoder();
const text = new TextDecoder();

type Mode =
  | "plain"
  | "gzip"
  | "redirect"
  | "cut"
  | "short-chunked"
  | "declared-too-large"
  | "streamed-too-large"
  | "attestation-too-large"
  | "hold-body";

interface Seen {
  method: string;
  path: string;
  contentType: string | undefined;
}

interface Harness {
  origin: string;
  node: TestNode;
  log: Seen[];
  setMode(mode: Mode): void;
  partialWritten: Promise<void>;
}

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the promise to reject");
}

function flatten(headers: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined) out[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return out;
}

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
  vi.unstubAllGlobals();
});

function pump(res: ServerResponse): void {
  const chunk = Buffer.alloc(MIB, 0x61);
  while (!res.destroyed) {
    if (!res.write(chunk)) {
      res.once("drain", () => pump(res));
      return;
    }
  }
}

function answerWith(mode: Mode, isPost: boolean, answer: TestOuterResponse, res: ServerResponse) {
  const { status, headers, body } = answer;
  const full = { ...headers, "content-length": String(body.byteLength) };
  if (mode === "gzip") {
    const zipped = gzipSync(body);
    res.writeHead(status, {
      ...headers,
      "content-encoding": "gzip",
      "content-length": String(zipped.byteLength),
    });
    res.end(zipped);
    return undefined;
  }
  if (mode === "attestation-too-large" && !isPost) {
    res.writeHead(status, { ...headers, "content-length": String(OVER_CAP) });
    res.write(body.subarray(0, 1));
    return undefined;
  }
  if (!isPost) {
    res.writeHead(status, full);
    res.end(body);
    return undefined;
  }
  switch (mode) {
    case "redirect":
      res.writeHead(302, { location: "/elsewhere", "content-length": "0" });
      res.end();
      return undefined;
    case "cut":
      res.writeHead(status, full);
      res.write(body.subarray(0, body.byteLength >> 1), () => res.socket?.destroy());
      return undefined;
    case "short-chunked":
      res.writeHead(status, headers);
      res.end(body.subarray(0, body.byteLength - 10));
      return undefined;
    case "declared-too-large":
      res.writeHead(status, { ...headers, "content-length": String(OVER_CAP) });
      res.write(body.subarray(0, 1));
      return undefined;
    case "streamed-too-large":
      res.writeHead(status, headers);
      pump(res);
      return undefined;
    case "hold-body":
      res.writeHead(status, full);
      return "hold";
    default:
      res.writeHead(status, full);
      res.end(body);
      return undefined;
  }
}

async function harness(): Promise<Harness> {
  const node = createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
  const log: Seen[] = [];
  const partial = deferred();
  const sockets = new Set<Socket>();
  let mode: Mode = "plain";
  let origin = "";

  const server = createServer((req, res) => {
    res.on("error", () => {});
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const isPost = req.method === "POST";
      log.push({
        method: req.method ?? "",
        path: req.url ?? "",
        contentType: req.headers["content-type"],
      });
      node
        .transport({
          method: req.method ?? "GET",
          url: `${origin}${req.url ?? "/"}`,
          headers: flatten(req.headers),
          ...(isPost ? { body: new Uint8Array(Buffer.concat(chunks)) } : {}),
        })
        .then((answer) => {
          if (answerWith(mode, isPost, answer, res) === "hold") {
            res.write(answer.body.subarray(0, 16), () => partial.resolve());
          }
        })
        .catch(() => res.destroy());
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return {
    origin,
    node,
    log,
    setMode(next) {
      mode = next;
    },
    partialWritten: partial.promise,
  };
}

function clientAt(h: Harness): ConfidentialClient {
  return new ConfidentialClient({
    url: `${h.origin}/eth_vrpc/${KEY}`,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
  });
}

function posts(h: Harness): Seen[] {
  return h.log.filter((entry) => entry.method === "POST");
}

describe("default transport over HTTP", () => {
  test("attests with a GET, then sends the sealed request as message/ohttp-req", async () => {
    const h = await harness();
    const response = await clientAt(h).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
    expect(h.log.map((entry) => entry.method)).toEqual(["GET", "POST"]);
    expect(h.log[0]?.path).toMatch(
      new RegExp(`^/eth_vrpc/${KEY}/attestation\\?nonce=[0-9a-f]{64}$`),
    );
    expect(h.log[1]?.path).toBe(`/eth_vrpc/${KEY}/confidential?node_id=${NODE_ID}`);
    expect(h.log[1]?.contentType).toBe("message/ohttp-req");
  });

  test("gzip-encoded attestation and confidential answers verify once decoded by the runtime", async () => {
    const h = await harness();
    h.setMode("gzip");
    const response = await clientAt(h).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
  });

  test("a redirect is an unexpected response and its target receives nothing", async () => {
    const h = await harness();
    h.setMode("redirect");
    const err = await rejectionOf(clientAt(h).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect((err as UnexpectedResponse).status).toBe(302);
    expect((err as UnexpectedResponse).executed).toBe("unknown");
    expect(posts(h)).toHaveLength(1);
    expect(h.log.some((entry) => entry.path.startsWith("/elsewhere"))).toBe(false);
  });

  test("a body cut short of its Content-Length is a network failure and drops the pin", async () => {
    const h = await harness();
    const client = clientAt(h);
    h.setMode("cut");
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("network");
    expect((err as TransportFailed).cause).toBeDefined();

    h.setMode("plain");
    expect((await client.request(jsonRpcCall())).status).toBe(200);
    expect(h.node.attestations()).toBe(2);
  });

  test("a chunked body that ends cleanly but short fails the signature", async () => {
    const h = await harness();
    h.setMode("short-chunked");

    expect(await rejectionOf(clientAt(h).request(jsonRpcCall()))).toBeInstanceOf(BadSignature);
  });

  test("a declared Content-Length over the cap is rejected before the body is read", async () => {
    const h = await harness();
    h.setMode("declared-too-large");
    const started = Date.now();
    const err = await rejectionOf(clientAt(h).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
    expect(Date.now() - started).toBeLessThan(5000);
  });

  test("a chunked body streaming past the cap is cut off", { timeout: 60_000 }, async () => {
    const h = await harness();
    h.setMode("streamed-too-large");
    const err = await rejectionOf(clientAt(h).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
  });

  test("an attestation answer over the cap is unavailable and nothing is sent", async () => {
    const h = await harness();
    h.setMode("attestation-too-large");
    const err = await rejectionOf(clientAt(h).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("transport");
    expect(posts(h)).toHaveLength(0);
  });

  test("an abort while the body is arriving rejects with the reason and keeps the pin", async () => {
    const h = await harness();
    const client = clientAt(h);
    h.setMode("hold-body");
    const controller = new AbortController();
    const reason = new Error("caller left");
    const pending = rejectionOf(client.request(jsonRpcCall(), { signal: controller.signal }));

    await h.partialWritten;
    controller.abort(reason);
    expect(await pending).toBe(reason);
    expect(client.getConfidentialInfo()).toBeDefined();

    h.setMode("plain");
    expect((await client.request(jsonRpcCall())).status).toBe(200);
    expect(h.log.filter((entry) => entry.method === "GET")).toHaveLength(1);
  });

  test("50 warm calls sharing one signal hold one abort listener on it", async () => {
    const h = await harness();
    const controller = new AbortController();
    const calls = 50;
    let entered = 0;
    const allEntered = deferred();
    const gate = deferred();
    const transport: ConfidentialTransport = async (request) => {
      if (request.method === "POST") {
        entered += 1;
        if (entered === calls) allEntered.resolve();
        await gate.promise;
      }
      return defaultTransport(request);
    };
    const client = new ConfidentialClient({
      url: `${h.origin}/eth_vrpc/${KEY}`,
      chainId: CHAIN_ID,
      hardwareVerifier: mockHardwareVerifier(),
      transport,
    });
    await client.ready();

    const pending = Promise.all(
      Array.from({ length: calls }, () =>
        client.request(jsonRpcCall(), { signal: controller.signal }),
      ),
    );
    await allEntered.promise;
    await new Promise((resolve) => setTimeout(resolve, 0));
    const inFlight = getEventListeners(controller.signal, "abort").length;
    gate.resolve();
    const responses = await pending;

    expect(inFlight).toBe(1);
    expect(responses.every((response) => response.status === 200)).toBe(true);
    expect(posts(h)).toHaveLength(calls);
  });
});

function opaqueRedirect(): Response {
  const response = new Response("hidden", { status: 200, headers: { "x-hidden": "1" } });
  Object.defineProperty(response, "type", { value: "opaqueredirect" });
  return response;
}

describe("default transport fetch contract", () => {
  test("an opaqueredirect result becomes status 0 with no headers and no body", async () => {
    vi.stubGlobal("fetch", async () => opaqueRedirect());
    const out = await defaultTransport({
      method: "POST",
      url: "http://127.0.0.1:9/x",
      headers: {},
      body: new Uint8Array(3),
    });

    expect(out.status).toBe(0);
    expect([...(out.headers as Headers).keys()]).toEqual([]);
    expect(out.body.byteLength).toBe(0);
  });

  test("an opaque redirect on the confidential request is an unexpected response", async () => {
    const node = createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      if (init.method === "POST") return opaqueRedirect();
      const answer = await node.transport({
        method: "GET",
        url,
        headers: init.headers as Record<string, string>,
      });
      return new Response(answer.body, { status: answer.status, headers: answer.headers });
    });
    const client = new ConfidentialClient({
      url: `https://rpc.example/eth_vrpc/${KEY}`,
      chainId: CHAIN_ID,
      hardwareVerifier: mockHardwareVerifier(),
    });
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect((err as UnexpectedResponse).status).toBe(0);
  });

  test("fetch gets redirect manual and the request as given, with no encoding header added", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      seen.push({ url, init });
      return new Response("ok", { status: 200 });
    });
    const headers = { "x-api-key": "k", "content-type": "message/ohttp-req" };
    const body = new Uint8Array([1, 2, 3]);
    const signal = new AbortController().signal;
    await defaultTransport({ method: "POST", url: "http://127.0.0.1:9/c", headers, body, signal });
    await defaultTransport({ method: "GET", url: "http://127.0.0.1:9/a", headers: {} });

    const [post, get] = seen;
    expect(post?.url).toBe("http://127.0.0.1:9/c");
    expect(post?.init.redirect).toBe("manual");
    expect(post?.init.method).toBe("POST");
    expect(post?.init.headers).toEqual(headers);
    expect(post?.init.body).toBe(body);
    expect(post?.init.signal).toBe(signal);
    expect(
      Object.keys(post?.init.headers as Record<string, string>).map((name) => name.toLowerCase()),
    ).not.toContain("accept-encoding");
    expect(get?.init.redirect).toBe("manual");
    expect(get?.init.method).toBe("GET");
    expect(get?.init).not.toHaveProperty("body");
    expect(get?.init).not.toHaveProperty("signal");
  });
});
