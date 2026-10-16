// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: every upstream failure is one typed error after one upstream attempt.

import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { getPublicKeyAsync } from "@noble/ed25519";
import { AttestationError, type HardwareVerifier } from "@w3tech.io/dstack-verify";
import { afterEach, describe, expect, test, vi } from "vitest";

import type { TestOuterResponse, TestUpstreamResponse } from "../../test-support/src/index";
import type { ProxyConfig } from "../src/config";

import {
  type RawResponse,
  type RunningProxy,
  rawRequest,
  startConfidentialProxy,
  startTestNodeServer,
  type TestNodeServer,
  type WireRequest,
} from "./support/test-node-server";
import { TEST_CHAIN_ID, TEST_SEED, toHex } from "./support/test-overrides";

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

const gets = (wire: WireRequest[]) => wire.filter((r) => r.method === "GET").length;
const posts = (wire: WireRequest[]) => wire.filter((r) => r.method === "POST").length;

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
  const node = await startTestNodeServer({
    seed: TEST_SEED,
    chainId: TEST_CHAIN_ID,
    nodeId: "failure-node-1",
    upstream: () => answer(),
  });
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
  await vi.waitFor(() => expect(events).toContain(event));
  return { node, proxy, verifier };
}

function restore(h: Harness): void {
  h.node.node.setConfidential();
  h.node.node.setAttestation();
  h.node.setWire();
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
  const wire = h.node.wire;
  const before = { gets: gets(wire), posts: posts(wire) };
  const res = await post(h.proxy.url);
  await expectTypedError(res, expected.status, expected.kind, expected.executed);
  await vi.waitFor(() => {
    expect(gets(wire) - before.gets).toBe(attempt.gets);
    expect(posts(wire) - before.posts).toBe(attempt.posts);
  });

  restore(h);
  const after = { gets: gets(wire), posts: posts(wire) };
  const ok = await post(h.proxy.url);
  expect(ok.status).toBe(200);
  expect(ok.body.toString()).toBe(RPC_ANSWER);
  expect(gets(wire) - after.gets).toBe(1);
  expect(posts(wire) - after.posts).toBe(1);
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
    title: "attestation slower than the timeout",
    install: ({ node }) => node.setWire({ delayMs: 1000, only: "GET" }),
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
    kind: "Attestation",
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
    install: ({ node }) => node.setWire({ delayMs: 1000, only: "POST" }),
    status: 504,
    kind: "UpstreamTimeout",
    executed: "unknown",
  },
  {
    title: "connection closed before the status line",
    install: ({ node }) => node.setWire({ destroyBeforeHeaders: true, only: "POST" }),
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
      node.setWire({ cutAfterBytes: Math.floor(outerLength / 2), only: "POST" });
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
    install: ({ node }) => node.setWire({ corruptGzip: true, only: "POST" }),
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

describe("concurrent and interrupted requests", () => {
  test("twenty requests share one pending attestation and all fail with it", async () => {
    let answerAttestation: (response: TestOuterResponse) => void = () => {};
    const gate = new Promise<TestOuterResponse>((resolve) => {
      answerAttestation = resolve;
    });
    const node = await startTestNodeServer({
      seed: TEST_SEED,
      chainId: TEST_CHAIN_ID,
      nodeId: "failure-node-1",
      upstream: () => answer(),
    });
    cleanups.push(() => node.close());
    node.node.setAttestation(() => gate);
    const proxy = await startConfidentialProxy(node);
    cleanups.push(() => proxy.close());
    let arrived = 0;
    proxy.server.on("request", () => {
      arrived += 1;
    });

    const pending = Array.from({ length: 20 }, () => post(proxy.url));
    await vi.waitFor(() => expect(arrived).toBe(20));
    await delay(50);
    answerAttestation(plain(503, "text/plain", "unavailable"));
    const responses = await Promise.all(pending);
    for (const res of responses) {
      await expectTypedError(res, 503, "AttestationUnavailable", "no");
    }
    expect(gets(node.wire)).toBe(1);
    expect(posts(node.wire)).toBe(0);

    node.node.setAttestation();
    const ok = await post(proxy.url);
    expect(ok.status).toBe(200);
    expect(gets(node.wire)).toBe(2);
    expect(posts(node.wire)).toBe(1);
  });

  test("a client that disconnects mid-request leaves the proxy serving with its pin", async () => {
    const h = await startHarness({ startup: "ok" });
    h.node.setWire({ delayMs: 200, only: "POST" });
    const target = new URL(h.proxy.url);
    const aborted = new Promise<void>((resolve) => {
      const req = http.request({
        host: target.hostname,
        port: target.port,
        method: "POST",
        path: "/",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(50),
      });
      req.on("error", () => resolve());
      req.on("response", () => resolve());
      req.end(RPC_BODY);
    });
    await aborted;
    await delay(300);
    expect(posts(h.node.wire)).toBe(1);
    expect(gets(h.node.wire)).toBe(1);

    h.node.setWire();
    const ok = await post(h.proxy.url);
    expect(ok.status).toBe(200);
    expect(gets(h.node.wire)).toBe(1);
    expect(posts(h.node.wire)).toBe(2);
  });
});
