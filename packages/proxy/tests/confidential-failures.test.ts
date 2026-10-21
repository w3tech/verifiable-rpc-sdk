// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: every upstream failure is one typed error after one upstream attempt.

import http from "node:http";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import { getPublicKeyAsync } from "@noble/ed25519";
import { AttestationError, type HardwareVerifier } from "@w3tech.io/dstack-verify";
import { ConfidentialClient } from "@w3tech.io/vrpc-core/confidential";
import type { TestOuterResponse, TestUpstreamResponse } from "@w3tech.io/vrpc-test-support";
import { createTestNode, rejectionOf, TEST_SEED, toHex } from "@w3tech.io/vrpc-test-support";
import {
  closeServer,
  holdPosts,
  isPost,
  listen,
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
} from "@w3tech.io/vrpc-test-support/server";
import { getGlobalDispatcher } from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createConfidentialTransport } from "../src/confidential";
import type { ProxyConfig } from "../src/config";
import {
  type RawResponse,
  type RunningProxy,
  rawRequest,
  startConfidentialProxy,
} from "./support/proxy";
import { TEST_CHAIN_ID, testConfig } from "./support/test-overrides";

const RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RPC_ANSWER = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const OHTTP_KEY_PROBLEM =
  '{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}';
const OTHER_SEED = new Uint8Array(32).fill(0x24);
const TIMEOUT_MS = 300;

interface TogglingVerifier extends HardwareVerifier {
  failing: boolean;
}

interface Harness {
  node: TestNodeServer;
  proxy: RunningProxy;
  verifier: TogglingVerifier;
}

interface Row {
  title: string;
  /** Runs before the proxy listens for attestation rows, after the startup attestation for POST rows. */
  install: (h: Harness) => void | Promise<void>;
  status: number;
  kind: string;
  executed?: "no" | "unknown";
  config?: Partial<ProxyConfig>;
}

const jsonAnswer = (): TestUpstreamResponse => ({
  status: 200,
  headers: { "content-type": "application/json" },
  body: RPC_ANSWER,
});

let answer: () => TestUpstreamResponse = jsonAnswer;
let events: string[] = [];
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  answer = jsonAnswer;
  events = [];
});

function plain(status: number, contentType: string | undefined, body: string): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body: Buffer.from(body),
  };
}

const gets = (wire: ServedRequest[]) => wire.filter((r) => r.method === "GET").length;
const posts = (wire: ServedRequest[]) => wire.filter((r) => r.method === "POST").length;

/** Never answers; only the proxy's own timeout or abort ends the request. */
const stalled = (method: string) => (request: ServedRequest) =>
  request.method === method ? new Promise<undefined>(() => {}) : undefined;

const repeatedNodeId =
  (method: string) => async (request: ServedRequest, forward: () => Promise<TestOuterResponse>) => {
    if (request.method !== method) return undefined;
    const normal = await forward();
    return { ...normal, headers: { ...normal.headers, "vrpc-nodeid": ["n1", "n2"] } };
  };

function post(url: string): Promise<RawResponse> {
  return rawRequest(url, {
    method: "POST",
    path: "/",
    headers: { "content-type": "application/json" },
    body: RPC_BODY,
  });
}

async function startHarness(options: {
  config?: Partial<ProxyConfig>;
  beforeListen?: (h: Omit<Harness, "proxy">) => void | Promise<void>;
  startup: "ok" | "fail";
}): Promise<Harness> {
  const node = await serveTestNode(
    createTestNode({
      seed: TEST_SEED,
      chainId: TEST_CHAIN_ID,
      nodeId: "failure-node-1",
      upstream: () => answer(),
    }),
  );
  cleanups.push(() => node.close());
  const verifier: TogglingVerifier = {
    failing: false,
    async verifyHardware() {
      if (this.failing) throw new AttestationError("CHK-P1", "hardware check failed");
    },
  };
  await options.beforeListen?.({ node, verifier });
  const proxy = await startConfidentialProxy(node, options.config ?? {}, {
    hardwareVerifier: verifier,
    logger: { debug: (event) => void events.push(event) },
  });
  cleanups.push(() => proxy.close());
  const event = options.startup === "ok" ? "confidential.attest.ok" : "confidential.attest.fail";
  // The failing startup attestation takes the upstream timeout; leave headroom under full load.
  await vi.waitFor(() => expect(events).toContain(event), { timeout: 3000 });
  return { node, proxy, verifier };
}

function restore(h: Harness): void {
  h.node.node.setConfidential();
  h.node.node.setAttestation();
  h.node.answer();
  h.verifier.failing = false;
  answer = jsonAnswer;
}

async function expectTypedError(
  res: RawResponse,
  status: number,
  kind: string,
  executed: "no" | "unknown" | undefined,
): Promise<void> {
  expect(res.status).toBe(status);
  expect(res.headers["content-type"]).toBe("application/json");
  const body = JSON.parse(res.body.toString()) as {
    error: { kind: string; message: string; executed?: string; traceId?: string };
  };
  expect(body.error.kind).toBe(kind);
  expect(typeof body.error.message).toBe("string");
  expect(body.error.executed).toBe(executed);
  expect(body.error).not.toHaveProperty("traceId");
}

/** One failed request with its upstream count, then a recovered request that attests again. */
async function failThenRecover(
  h: Harness,
  expected: { status: number; kind: string; executed?: "no" | "unknown" },
  attempt: { gets: number; posts: number },
): Promise<void> {
  const wire = h.node.requests;
  const before = { gets: gets(wire), posts: posts(wire) };
  const res = await post(h.proxy.url);
  await expectTypedError(res, expected.status, expected.kind, expected.executed);
  await vi.waitFor(() => {
    expect(gets(wire) - before.gets).toBe(attempt.gets);
    expect(posts(wire) - before.posts).toBe(attempt.posts);
  });

  restore(h);
  const after = posts(wire);
  const ok = await post(h.proxy.url);
  expect(ok.status).toBe(200);
  expect(ok.body.toString()).toBe(RPC_ANSWER);
  expect(posts(wire) - after).toBe(1);
}

const attestationRows: Row[] = [
  {
    title: "gateway rate limit on attestation",
    install: ({ node }) => node.node.setAttestation(() => plain(429, "text/plain", "slow down")),
    status: 429,
    kind: "AttestationUnavailable",
    executed: "no",
  },
  {
    title: "attestation server error",
    install: ({ node }) => node.node.setAttestation(() => plain(500, "text/plain", "down")),
    status: 503,
    kind: "AttestationUnavailable",
    executed: "no",
  },
  {
    title: "attestation key refused",
    install: ({ node }) =>
      node.node.setAttestation(() => plain(401, "application/json", '{"error":"unauthorized"}')),
    status: 503,
    kind: "AttestationUnavailable",
    executed: "no",
  },
  {
    title: "attestation without a node id",
    install: ({ node }) =>
      node.node.setAttestation(async (context) => {
        const normal = await context.normal();
        const { "vRPC-NodeId": _, ...headers } = normal.headers;
        return { ...normal, headers };
      }),
    status: 503,
    kind: "AttestationUnavailable",
    executed: "no",
  },
  {
    title: "attestation with a repeated node id",
    install: ({ node }) => node.answer(repeatedNodeId("GET")),
    status: 502,
    kind: "AttestationFailed",
    executed: "no",
  },
  {
    title: "attestation slower than the timeout",
    install: ({ node }) => node.answer(stalled("GET")),
    status: 504,
    kind: "AttestationUnavailable",
    executed: "no",
  },
  {
    title: "hardware verification failure",
    install: (h) => {
      h.verifier.failing = true;
    },
    status: 502,
    kind: "AttestationFailed",
    executed: "no",
  },
];

const postRows: Row[] = [
  {
    title: "gateway key refused",
    install: ({ node }) =>
      node.node.setConfidential(() => plain(401, "application/json", '{"error":"unauthorized"}')),
    status: 502,
    kind: "RequestRejected",
    executed: "no",
  },
  {
    title: "unknown node 404",
    install: ({ node }) => node.node.setConfidential(() => plain(404, "text/plain", "not found")),
    status: 502,
    kind: "RequestRejected",
    executed: "no",
  },
  {
    title: "key configuration problem 400",
    install: ({ node }) =>
      node.node.setConfidential(() => plain(400, "application/problem+json", OHTTP_KEY_PROBLEM)),
    status: 502,
    kind: "RequestRejected",
    executed: "no",
  },
  {
    title: "edge proxy 413",
    install: ({ node }) => node.node.setConfidential(() => plain(413, undefined, "")),
    status: 413,
    kind: "RequestRejected",
    executed: "no",
  },
  {
    title: "gateway rate limit",
    install: ({ node }) => node.node.setConfidential(() => plain(429, "text/plain", "slow down")),
    status: 429,
    kind: "RequestRejected",
    executed: "no",
  },
  {
    title: "gateway 502",
    install: ({ node }) => node.node.setConfidential(() => plain(502, "text/plain", "bad gateway")),
    status: 502,
    kind: "UnexpectedResponse",
    executed: "unknown",
  },
  {
    title: "node answer slower than the timeout",
    install: ({ node }) => node.answer(stalled("POST")),
    status: 504,
    kind: "UpstreamTimeout",
    executed: "unknown",
  },
  {
    title: "connection closed before the status line",
    install: ({ node }) =>
      node.answer((request) => {
        if (isPost(request)) request.socket.destroy();
        return undefined;
      }),
    status: 502,
    kind: "UpstreamConnect",
    executed: "unknown",
  },
  {
    title: "node answer cut short",
    install: async ({ node, proxy }) => {
      let outerLength = 0;
      node.node.setConfidential(async (context) => {
        const normal = await context.normal();
        outerLength = normal.body.byteLength;
        return normal;
      });
      expect((await post(proxy.url)).status).toBe(200);
      node.node.setConfidential();
      node.answer(async (request, forward) =>
        isPost(request)
          ? { ...(await forward()), cutAfter: Math.floor(outerLength / 2) }
          : undefined,
      );
    },
    status: 502,
    kind: "UpstreamConnect",
    executed: "unknown",
  },
  {
    title: "decoded answer over the body limit",
    config: { maxBodyBytes: 4096 },
    install: () => {
      answer = () => ({
        status: 200,
        headers: { "content-type": "application/octet-stream" },
        body: Buffer.alloc(8192, 0x61),
      });
    },
    status: 502,
    kind: "UpstreamBodyTooLarge",
    executed: "unknown",
  },
  {
    title: "corrupt gzip answer",
    install: ({ node }) =>
      node.answer(async (request, forward) => {
        if (!isPost(request)) return undefined;
        const normal = await forward();
        return {
          ...normal,
          headers: { ...normal.headers, "content-encoding": "gzip" },
          body: Buffer.concat([Buffer.from("not gzip:"), normal.body]),
        };
      }),
    status: 502,
    kind: "DecodeFailed",
    executed: "unknown",
  },
  {
    title: "answer signed by another node key",
    install: async ({ node }) => {
      const pubkeyHex = `0x${toHex(await getPublicKeyAsync(OTHER_SEED))}`;
      node.node.setConfidential(async (context) => {
        const normal = await context.normal();
        return {
          ...normal,
          headers: {
            ...normal.headers,
            ...context.sign(normal.body, { seed: OTHER_SEED, pubkeyHex }),
          },
        };
      });
    },
    status: 502,
    kind: "ConfidentialSignerMismatch",
    executed: "unknown",
  },
  {
    title: "one ciphertext byte flipped",
    install: ({ node }) =>
      node.node.setConfidential(async (context) => {
        const normal = await context.normal();
        const body = Buffer.from(normal.body);
        body[body.length - 1] = (body[body.length - 1] ?? 0) ^ 0x01;
        return { ...normal, body };
      }),
    status: 502,
    kind: "BadSignature",
    executed: "unknown",
  },
  {
    title: "vRPC-Timestamp above u64",
    install: ({ node }) =>
      node.node.setConfidential(async (context) => {
        const normal = await context.normal();
        return {
          ...normal,
          headers: { ...normal.headers, "vRPC-Timestamp": "18446744073709551616" },
        };
      }),
    status: 502,
    kind: "MalformedHeader",
    executed: "unknown",
  },
  {
    title: "repeated vRPC-NodeId on the answer",
    install: ({ node }) => node.answer(repeatedNodeId("POST")),
    status: 502,
    kind: "MalformedHeader",
    executed: "unknown",
  },
];

describe("attestation failures", () => {
  test.each(attestationRows)("$title → $status $kind", async (row) => {
    const h = await startHarness({
      startup: "fail",
      config: { upstreamTimeoutMs: TIMEOUT_MS, ...row.config },
      beforeListen: (partial) => row.install(partial as Harness),
    });
    await failThenRecover(h, row, { gets: 1, posts: 0 });
  });
});

describe("sealed request failures", () => {
  test.each(postRows)("$title → $status $kind", async (row) => {
    const h = await startHarness({
      startup: "ok",
      config: { upstreamTimeoutMs: TIMEOUT_MS, ...row.config },
    });
    await row.install(h);
    await failThenRecover(h, row, { gets: 0, posts: 1 });
  });

  test("a redirect is not followed and its location receives nothing", async () => {
    let redirected = 0;
    const target = http.createServer((_req, res) => {
      redirected += 1;
      res.end();
    });
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
    cleanups.push(
      () =>
        new Promise<void>((resolve) => {
          target.closeAllConnections();
          target.close(() => resolve());
        }),
    );
    const location = `http://127.0.0.1:${(target.address() as AddressInfo).port}/elsewhere`;
    const h = await startHarness({ startup: "ok", config: { upstreamTimeoutMs: TIMEOUT_MS } });
    h.node.node.setConfidential(() => ({
      status: 302,
      headers: { location },
      body: new Uint8Array(0),
    }));
    await failThenRecover(
      h,
      { status: 502, kind: "UnexpectedResponse", executed: "unknown" },
      { gets: 0, posts: 1 },
    );
    expect(redirected).toBe(0);
  });
});

describe("outer read cap", () => {
  test.each([
    ["identity", Buffer.alloc(128), "UPSTREAM_BODY_TOO_LARGE"],
    ["gzip", gzipSync(Buffer.alloc(4096)), "DECODE_FAILED"],
  ])("an answer past the request's own maxBytes is cut at it (%s)", async (encoding, body, code) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-encoding": encoding }).end(body);
    });
    const url = await listen(server);
    cleanups.push(() => closeServer(server));
    const transport = createConfidentialTransport(testConfig(url), getGlobalDispatcher());

    const err = await rejectionOf(transport({ method: "GET", url, headers: {}, maxBytes: 64 }));

    expect(err).toMatchObject({ code });
  });
});

describe("concurrent and interrupted requests", () => {
  test("twenty requests share one pending attestation and all fail with it", async () => {
    const { promise: gate, resolve: answerAttestation } =
      Promise.withResolvers<TestOuterResponse>();
    const node = await serveTestNode(
      createTestNode({
        seed: TEST_SEED,
        chainId: TEST_CHAIN_ID,
        nodeId: "failure-node-1",
        upstream: () => answer(),
      }),
    );
    cleanups.push(() => node.close());
    node.node.setAttestation(() => gate);
    const proxy = await startConfidentialProxy(node);
    cleanups.push(() => proxy.close());
    const requested = vi.spyOn(ConfidentialClient.prototype, "request");
    cleanups.push(async () => requested.mockRestore());

    const pending = Array.from({ length: 20 }, () => post(proxy.url));
    await vi.waitFor(() => expect(requested).toHaveBeenCalledTimes(20));
    answerAttestation(plain(503, "text/plain", "unavailable"));
    const responses = await Promise.all(pending);
    for (const res of responses) {
      await expectTypedError(res, 503, "AttestationUnavailable", "no");
    }
    expect(gets(node.requests)).toBe(1);
    expect(posts(node.requests)).toBe(0);

    node.node.setAttestation();
    const ok = await post(proxy.url);
    expect(ok.status).toBe(200);
    expect(gets(node.requests)).toBe(2);
    expect(posts(node.requests)).toBe(1);
  });

  test("a client that disconnects mid-request leaves the proxy serving with its pin", async () => {
    const stderr: string[] = [];
    const write = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    cleanups.push(async () => write.mockRestore());
    const h = await startHarness({ startup: "ok", config: { logLevel: "debug" } });
    h.node.answer(stalled("POST"));
    const target = new URL(h.proxy.url);
    const req = http.request({
      host: target.hostname,
      port: target.port,
      method: "POST",
      path: "/",
      headers: { "content-type": "application/json" },
    });
    req.on("error", () => {});
    req.end(RPC_BODY);
    await vi.waitFor(() => expect(posts(h.node.requests)).toBe(1));
    req.destroy();
    await vi.waitFor(() =>
      expect(stderr.some((l) => / proxy\.(relay|clientAborted|error)\b/.test(l))).toBe(true),
    );
    expect(gets(h.node.requests)).toBe(1);

    h.node.answer();
    const ok = await post(h.proxy.url);
    expect(ok.status).toBe(200);
    expect(gets(h.node.requests)).toBe(1);
    expect(posts(h.node.requests)).toBe(2);
  });

  test("a client disconnect aborts the upstream request", async () => {
    const h = await startHarness({ startup: "ok" });
    holdPosts(h.node);
    const target = new URL(h.proxy.url);
    const req = http.request({
      host: target.hostname,
      port: target.port,
      method: "POST",
      path: "/",
      headers: { "content-type": "application/json" },
    });
    req.on("error", () => {});
    req.end(RPC_BODY);
    await vi.waitFor(() => expect(posts(h.node.requests)).toBe(1));
    const upstream = h.node.requests.find((r) => r.method === "POST");
    req.destroy();

    await vi.waitFor(() => expect(upstream?.socket.destroyed).toBe(true));
  });
});
