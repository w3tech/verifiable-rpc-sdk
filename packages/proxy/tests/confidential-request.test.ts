// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: what the node receives, what is refused locally, and the outer wire headers.

import { countOf, createTestNode, isGet, isPost, NODE_ID } from "@w3tech.io/vrpc-test-support";
import {
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
} from "@w3tech.io/vrpc-test-support/server";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  type RawRequestOptions,
  type RunningProxy,
  rawRequest,
  startConfidentialProxy,
  wireHeaderNames,
} from "./support/proxy";
import { TEST_CHAIN_ID } from "./support/test-overrides";

const API_KEY = "configured-key-1";
const PATH_KEY = "ab".repeat(32);
const JSON_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const ANSWER = '{"ok":true}';
// Node's client frames a GET or HEAD body only with an explicit length.
const BODY_LENGTH = String(Buffer.byteLength(JSON_BODY));

interface SeenInner {
  method: string;
  target: string;
  contentType: string | null;
  accept: string | null;
  body: Buffer;
}

let nodeServer: TestNodeServer | undefined;
let proxy: RunningProxy | undefined;
let seen: SeenInner[] = [];

afterEach(async () => {
  await proxy?.close();
  await nodeServer?.close();
  proxy = undefined;
  nodeServer = undefined;
  seen = [];
});

async function startNode(): Promise<TestNodeServer> {
  nodeServer = await serveTestNode(
    createTestNode({
      chainId: TEST_CHAIN_ID,
      upstream: async (inner) => {
        const url = new URL(inner.url);
        seen.push({
          method: inner.method,
          target: url.pathname + url.search,
          contentType: inner.headers.get("content-type"),
          accept: inner.headers.get("accept"),
          body: Buffer.from(await inner.arrayBuffer()),
        });
        return { status: 200, headers: { "content-type": "application/json" }, body: ANSWER };
      },
    }),
  );
  return nodeServer;
}

async function setup(maxBodyBytes?: number): Promise<{ node: TestNodeServer; url: string }> {
  const node = await startNode();
  proxy = await startConfidentialProxy(node, {
    apiKey: API_KEY,
    attestationHeaders: { "x-api-key": API_KEY },
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes }),
  });
  await vi.waitFor(() => expect(node.node.attestations()).toBe(1));
  return { node, url: proxy.url };
}

function errorOf(body: Buffer): { kind: string; message: string } {
  return (JSON.parse(body.toString()) as { error: { kind: string; message: string } }).error;
}

async function expectNextRequestRelayed(node: TestNodeServer, url: string): Promise<void> {
  const res = await rawRequest(url, {
    method: "POST",
    path: "/",
    headers: { "content-type": "application/json" },
    body: JSON_BODY,
  });
  expect(res.status).toBe(200);
  expect(res.body.toString()).toBe(ANSWER);
  expect(countOf(node, isGet)).toBe(1);
  expect(node.node.attestations()).toBe(1);
}

describe("inner request mapping", () => {
  test("carries method, path and query, media types and body", async () => {
    const { url } = await setup();
    const res = await rawRequest(url, {
      method: "POST",
      path: "/rpc?x=1",
      headers: { "content-type": "application/json; charset=utf-8", accept: ["a/b", "c/d"] },
      body: JSON_BODY,
    });
    expect(res.status).toBe(200);
    expect(seen).toEqual([
      {
        method: "POST",
        target: "/rpc?x=1",
        contentType: "application/json; charset=utf-8",
        accept: "a/b, c/d",
        body: Buffer.from(JSON_BODY),
      },
    ]);
  });

  test("a GET without a body reaches the node with no body and no content-type", async () => {
    const { url } = await setup();
    const res = await rawRequest(url, { method: "GET", path: "/v1/blocks?full=true" });
    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("GET");
    expect(seen[0]?.target).toBe("/v1/blocks?full=true");
    expect(seen[0]?.contentType).toBeNull();
    expect(seen[0]?.body.length).toBe(0);
  });

  test("a repeated content-type sends the first value", async () => {
    const { url } = await setup();
    const res = await rawRequest(url, {
      method: "POST",
      path: "/",
      headers: { "content-type": ["application/json", "text/plain"] },
      body: JSON_BODY,
    });
    expect(res.status).toBe(200);
    expect(seen[0]?.contentType).toBe("application/json");
  });

  test("an empty query is sent normalized", async () => {
    const { url } = await setup();
    const res = await rawRequest(url, { method: "GET", path: "/x?" });
    expect(res.status).toBe(200);
    expect(seen[0]?.target).toBe("/x");
  });
});

describe("refused locally", () => {
  test.each<[string, RawRequestOptions]>([
    [
      "content-encoding gzip",
      {
        method: "POST",
        path: "/",
        headers: { "content-type": "application/json", "content-encoding": "gzip" },
        body: JSON_BODY,
      },
    ],
    [
      "content-encoding identity",
      {
        method: "POST",
        path: "/",
        headers: { "content-type": "application/json", "content-encoding": "identity" },
        body: JSON_BODY,
      },
    ],
    ["a body without content-type", { method: "POST", path: "/", body: JSON_BODY }],
    [
      "a body with an empty content-type",
      { method: "POST", path: "/", headers: { "content-type": "" }, body: JSON_BODY },
    ],
  ])("%s is 415 with nothing upstream", async (_name, options) => {
    const { node, url } = await setup();
    const res = await rawRequest(url, options);
    expect(res.status).toBe(415);
    expect(errorOf(res.body).kind).toBe("UnsupportedMediaType");
    expect(node.requests).toHaveLength(1);
    expect(seen).toHaveLength(0);
    await expectNextRequestRelayed(node, url);
  });

  test.each<[string, RawRequestOptions]>([
    ["double slash", { method: "GET", path: "//x" }],
    ["dot segment", { method: "GET", path: "/a/../b" }],
    ["absolute form", { method: "GET", path: "http://upstream.example/a?b=1" }],
    ["asterisk form", { method: "OPTIONS", path: "*" }],
    ["TRACE", { method: "TRACE", path: "/" }],
    [
      "GET with a body",
      {
        method: "GET",
        path: "/",
        headers: { "content-type": "application/json", "content-length": BODY_LENGTH },
        body: JSON_BODY,
      },
    ],
  ])("%s is 400 InvalidInnerRequest with nothing upstream", async (_name, options) => {
    const { node, url } = await setup();
    const res = await rawRequest(url, options);
    expect(res.status).toBe(400);
    const error = errorOf(res.body);
    expect(error.kind).toBe("InvalidInnerRequest");
    expect(error.message.startsWith("Inner request rejected:")).toBe(true);
    for (const leak of ["upstream.example", "/a/../b", "//x"]) {
      expect(error.message).not.toContain(leak);
    }
    expect(node.requests).toHaveLength(1);
    expect(seen).toHaveLength(0);
    await expectNextRequestRelayed(node, url);
  });

  test("HEAD with a body is 400 with nothing upstream", async () => {
    const { node, url } = await setup();
    const res = await rawRequest(url, {
      method: "HEAD",
      path: "/",
      headers: { "content-type": "application/json", "content-length": BODY_LENGTH },
      body: JSON_BODY,
    });
    expect(res.status).toBe(400);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(node.requests).toHaveLength(1);
    expect(seen).toHaveLength(0);
    await expectNextRequestRelayed(node, url);
  });

  test("a body over the limit is 413 BodyTooLarge with nothing upstream", async () => {
    const { node, url } = await setup(1024);
    const res = await rawRequest(url, {
      method: "POST",
      path: "/",
      headers: { "content-type": "application/octet-stream" },
      body: Buffer.alloc(2048, 0x61),
    });
    expect(res.status).toBe(413);
    expect(errorOf(res.body).kind).toBe("BodyTooLarge");
    expect(node.requests).toHaveLength(1);
    expect(seen).toHaveLength(0);
  });
});

describe("outer wire", () => {
  test("carries only the configured key and no client header", async () => {
    const { node, url } = await setup();
    const res = await rawRequest(url, {
      method: "POST",
      path: "/",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer sentinel-auth",
        cookie: "sentinel-cookie=1",
        "user-agent": "sentinel-agent",
        "x-forwarded-for": "sentinel-forwarded",
        traceparent: "00-sentinel-trace-01",
        "x-api-key": "sentinel-client-key",
      },
      body: JSON_BODY,
    });
    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);

    expect(node.requests).toHaveLength(2);
    const get = node.requests.find(isGet) as ServedRequest;
    const post = node.requests.find(isPost) as ServedRequest;
    expect(new Set(wireHeaderNames(get))).toEqual(
      new Set(["host", "connection", "accept-encoding", "x-api-key"]),
    );
    expect(new Set(wireHeaderNames(post))).toEqual(
      new Set([
        "host",
        "connection",
        "accept-encoding",
        "x-api-key",
        "content-type",
        "content-length",
      ]),
    );
    expect(get.url).toMatch(/^[^?]*\?nonce=[0-9a-f]{64}$/);
    expect(post.url).toBe(`${post.path}?node_id=${NODE_ID}`);
    expect(post.headers["content-type"]).toBe("message/ohttp-req");
    for (const record of node.requests) {
      expect(record.headers["accept-encoding"]).toBe("identity");
      expect(record.headers["x-api-key"]).toBe(API_KEY);
      expect(record.url).not.toContain("sentinel");
      for (const field of record.rawHeaders) expect(field).not.toContain("sentinel");
    }
  });

  test("a key in the upstream path is used as configured, with no key header", async () => {
    const node = await startNode();
    proxy = await startConfidentialProxy(node, {
      upstreamUrl: `${node.url}/test_vrpc/${PATH_KEY}`,
      attestationHeaders: {},
    });
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    const res = await rawRequest(proxy.url, {
      method: "POST",
      path: "/",
      headers: { "content-type": "application/json" },
      body: JSON_BODY,
    });
    expect(res.status).toBe(200);
    const get = node.requests.find(isGet);
    const post = node.requests.find(isPost);
    expect(get?.path).toBe(`/test_vrpc/${PATH_KEY}/attestation`);
    expect(post?.path).toBe(`/test_vrpc/${PATH_KEY}/confidential`);
    for (const record of node.requests) expect(wireHeaderNames(record)).not.toContain("x-api-key");
  });
});
