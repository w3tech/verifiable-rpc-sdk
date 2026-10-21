// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: what the client receives from a verified, decrypted node answer.

import { gzipSync } from "node:zlib";
import {
  bhttpField,
  bhttpOkResponse,
  createTestNode,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import {
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
} from "@w3tech.io/vrpc-test-support/server";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  type RawResponse,
  type RunningProxy,
  rawRequest,
  startConfidentialProxy,
} from "./support/proxy";
import { TEST_CHAIN_ID } from "./support/test-overrides";

const RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RPC_ANSWER = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const BATCH_BODY =
  '[{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]},' +
  '{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]},' +
  '{"jsonrpc":"2.0","id":3,"method":"net_version","params":[]}]';
const BATCH_ANSWER =
  '[{"jsonrpc":"2.0","id":1,"result":"0x10"},' +
  '{"jsonrpc":"2.0","id":2,"result":"0x1"},' +
  '{"jsonrpc":"2.0","id":3,"result":"1"}]';
const PROBLEM = '{"type":"urn:vrpc:error:batch-too-large","title":"Batch too large"}';
const RELAY_HEADERS = new Set([
  "content-type",
  "content-length",
  "date",
  "connection",
  "keep-alive",
]);

interface SeenInner {
  method: string;
  target: string;
  accept: string | null;
  body: Buffer;
}

type Answer = (inner: Request) => TestUpstreamResponse | Promise<TestUpstreamResponse>;

const jsonAnswer: Answer = () => ({
  status: 200,
  headers: { "content-type": "application/json" },
  body: RPC_ANSWER,
});

let nodeServer: TestNodeServer | undefined;
let proxy: RunningProxy | undefined;
let seen: SeenInner[] = [];
let answer: Answer = jsonAnswer;

afterEach(async () => {
  await proxy?.close();
  await nodeServer?.close();
  proxy = undefined;
  nodeServer = undefined;
  seen = [];
  answer = jsonAnswer;
});

async function setup(): Promise<{ node: TestNodeServer; url: string }> {
  const node = await serveTestNode(
    createTestNode({
      chainId: TEST_CHAIN_ID,
      upstream: async (inner) => {
        const url = new URL(inner.url);
        seen.push({
          method: inner.method,
          target: url.pathname + url.search,
          accept: inner.headers.get("accept"),
          body: Buffer.from(await inner.arrayBuffer()),
        });
        return answer(inner);
      },
    }),
  );
  nodeServer = node;
  proxy = await startConfidentialProxy(node);
  await vi.waitFor(() => expect(node.node.attestations()).toBe(1));
  return { node, url: proxy.url };
}

function post(url: string, body = RPC_BODY): Promise<RawResponse> {
  return rawRequest(url, {
    method: "POST",
    path: "/",
    headers: { "content-type": "application/json" },
    body,
  });
}

function headerCount(res: RawResponse, name: string): number {
  return res.rawHeaders.filter((_, i) => i % 2 === 0 && _.toLowerCase() === name).length;
}

const gets = (wire: ServedRequest[]) => wire.filter((r) => r.method === "GET").length;

describe("relayed answers", () => {
  test("a JSON-RPC batch reaches the node unchanged and its array answer is relayed byte for byte", async () => {
    answer = () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: BATCH_ANSWER,
    });
    const { url } = await setup();
    const res = await post(url, BATCH_BODY);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.body.equals(Buffer.from(BATCH_BODY))).toBe(true);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.body.equals(Buffer.from(BATCH_ANSWER))).toBe(true);
  });

  test("a REST GET keeps its path, query and accept, and the answer is relayed", async () => {
    answer = () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"x":1}',
    });
    const { url } = await setup();
    const res = await rawRequest(url, {
      method: "GET",
      path: "/v1/x?y=1",
      headers: { accept: "application/json" },
    });
    expect(seen).toEqual([
      { method: "GET", target: "/v1/x?y=1", accept: "application/json", body: Buffer.alloc(0) },
    ]);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.body.toString()).toBe('{"x":1}');
  });

  test("an inner 500 is delivered as the node's answer and keeps the pin", async () => {
    answer = () => ({ status: 500, headers: { "content-type": "text/plain" }, body: "boom" });
    const { node, url } = await setup();
    const res = await post(url);
    expect(res.status).toBe(500);
    expect(res.headers["content-type"]).toBe("text/plain");
    expect(res.body.toString()).toBe("boom");
    answer = jsonAnswer;
    expect((await post(url)).status).toBe(200);
    expect(gets(node.requests)).toBe(1);
  });

  test("an inner 413 problem answer is delivered as the node's answer and keeps the pin", async () => {
    answer = () => ({
      status: 413,
      headers: { "content-type": "application/problem+json" },
      body: PROBLEM,
    });
    const { node, url } = await setup();
    const res = await post(url);
    expect(res.status).toBe(413);
    expect(res.headers["content-type"]).toBe("application/problem+json");
    expect(res.body.toString()).toBe(PROBLEM);
    answer = jsonAnswer;
    expect((await post(url)).status).toBe(200);
    expect(gets(node.requests)).toBe(1);
  });
});

describe("relay framing", () => {
  test.each([
    204, 304,
  ])("an inner %i carries neither content-length nor transfer-encoding", async (status) => {
    answer = () => ({ status });
    const { url } = await setup();
    const res = await post(url);
    expect(res.status).toBe(status);
    expect(res.headers["content-length"]).toBeUndefined();
    expect(res.headers["transfer-encoding"]).toBeUndefined();
    expect(res.body).toHaveLength(0);
  });

  test("an inner 205 carries content-length 0 and no transfer-encoding", async () => {
    answer = () => ({ status: 205 });
    const { url } = await setup();
    const res = await post(url);
    expect(res.status).toBe(205);
    expect(res.headers["content-length"]).toBe("0");
    expect(res.headers["transfer-encoding"]).toBeUndefined();
    expect(res.body).toHaveLength(0);
  });

  test("a HEAD answer carries the inner content-type and no length or chunking", async () => {
    const { url } = await setup();
    const res = await rawRequest(url, { method: "HEAD", path: "/" });
    expect(seen[0]?.method).toBe("HEAD");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.headers["content-length"]).toBeUndefined();
    expect(res.headers["transfer-encoding"]).toBeUndefined();
    expect(res.body).toHaveLength(0);
  });

  test("a 1 MiB answer carries its exact length and bytes", async () => {
    const big = Buffer.alloc(1024 * 1024, 0x61);
    answer = () => ({
      status: 200,
      headers: { "content-type": "application/octet-stream" },
      body: big,
    });
    const { url } = await setup();
    const res = await post(url);
    expect(res.status).toBe(200);
    expect(res.headers["content-length"]).toBe("1048576");
    expect(res.body.equals(big)).toBe(true);
  });

  test("two inner content-type values reach the client as one joined header", async () => {
    const { node, url } = await setup();
    node.node.setConfidential(async (context) => {
      const inner = Buffer.from(
        bhttpOkResponse(
          [
            bhttpField("content-type", "application/json"),
            bhttpField("content-type", "text/plain"),
          ],
          "{}",
        ),
        "hex",
      );
      const sealed = await context.seal(inner);
      return {
        status: 200,
        headers: { "content-type": "message/ohttp-res", ...context.sign(sealed) },
        body: sealed,
      };
    });
    const res = await post(url);
    expect(res.status).toBe(200);
    expect(headerCount(res, "content-type")).toBe(1);
    expect(res.headers["content-type"]).toBe("application/json, text/plain");
    expect(res.body.toString()).toBe("{}");
  });
});

describe("outer answer never relayed", () => {
  test("outer headers stay behind and only the relay set reaches the client", async () => {
    const { node, url } = await setup();
    node.answer(async (_request, forward) => {
      const normal = await forward();
      return { ...normal, headers: { ...normal.headers, "x-upstream-extra": "sentinel-extra" } };
    });
    const res = await post(url);
    expect(res.status).toBe(200);
    const names = res.rawHeaders.filter((_, i) => i % 2 === 0).map((n) => n.toLowerCase());
    expect(names).not.toContain("x-upstream-extra");
    expect(names.filter((n) => n.startsWith("vrpc-"))).toEqual([]);
    expect(names).not.toContain("content-encoding");
    expect(res.headers["content-type"]).not.toBe("message/ohttp-res");
    for (const name of names) expect(RELAY_HEADERS.has(name)).toBe(true);
    expect(res.body.toString()).toBe(RPC_ANSWER);
  });

  test("a gzip outer answer is decoded before verification and relayed as plaintext", async () => {
    const { node, url } = await setup();
    node.answer(async (_request, forward) => {
      const normal = await forward();
      if (normal.status >= 400) return normal;
      return {
        ...normal,
        headers: { ...normal.headers, "content-encoding": "gzip" },
        body: gzipSync(normal.body),
      };
    });
    const res = await post(url);
    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.body.toString()).toBe(RPC_ANSWER);
  });
});
