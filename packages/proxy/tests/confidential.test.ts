// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode end to end against the in-test node behind a loopback server.

import { request } from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";

import {
  type RunningProxy,
  startConfidentialProxy,
  startTestNodeServer,
  type TestNodeServer,
  type WireRequest,
} from "./support/test-node-server";
import { TEST_CHAIN_ID, TEST_SEED } from "./support/test-overrides";

const API_KEY = "test-api-key-1";
const RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RPC_ANSWER = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';

interface SeenInner {
  method: string;
  pathname: string;
  contentType: string | null;
  body: Buffer;
}

let nodeServer: TestNodeServer | undefined;
let proxy: RunningProxy | undefined;

afterEach(async () => {
  await proxy?.close();
  await nodeServer?.close();
  proxy = undefined;
  nodeServer = undefined;
});

async function startNode(seen: SeenInner[] = []): Promise<TestNodeServer> {
  nodeServer = await startTestNodeServer({
    seed: TEST_SEED,
    chainId: TEST_CHAIN_ID,
    nodeId: "proxy-node-1",
    upstream: async (inner) => {
      seen.push({
        method: inner.method,
        pathname: new URL(inner.url).pathname,
        contentType: inner.headers.get("content-type"),
        body: Buffer.from(await inner.arrayBuffer()),
      });
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: RPC_ANSWER,
      };
    },
  });
  return nodeServer;
}

async function startProxy(node: TestNodeServer): Promise<RunningProxy> {
  proxy = await startConfidentialProxy(node, {
    apiKey: API_KEY,
    attestationHeaders: { "x-api-key": API_KEY },
  });
  return proxy;
}

async function postRpc(url: string): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}> {
  const res = await request(`${url}/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: RPC_BODY,
  });
  const chunks: Buffer[] = [];
  for await (const chunk of res.body) chunks.push(chunk as Buffer);
  return { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) };
}

const posts = (wire: WireRequest[]) => wire.filter((r) => r.method === "POST");
const gets = (wire: WireRequest[]) => wire.filter((r) => r.method === "GET");

describe("confidential mode", () => {
  test("attestsOnceAtStartupBeforeAnyClientRequest", async () => {
    const node = await startNode();
    await startProxy(node);
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    expect(node.wire).toHaveLength(1);
    const [get] = node.wire;
    expect(get?.method).toBe("GET");
    expect(get?.path).toBe("/test_vrpc/attestation");
    expect(get?.query).toMatch(/^nonce=[0-9a-f]{64}$/);
    expect(posts(node.wire)).toHaveLength(0);
  });

  test("relaysTheInnerAnswerOfAJsonRpcCall", async () => {
    const seen: SeenInner[] = [];
    const node = await startNode(seen);
    const { url } = await startProxy(node);
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    const res = await postRpc(url);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.body.toString()).toBe(RPC_ANSWER);
    expect(res.headers["content-length"]).toBe(String(res.body.length));
    expect(Object.keys(res.headers).filter((name) => name.startsWith("vrpc-"))).toEqual([]);

    expect(node.wire).toHaveLength(2);
    const [post] = posts(node.wire);
    expect(post?.path).toBe("/test_vrpc/confidential");
    expect(post?.query).toBe("node_id=proxy-node-1");
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
    expect(post?.headers["accept-encoding"]).toBe("identity");
    expect(post?.headers["x-api-key"]).toBe(API_KEY);
    expect(post?.body.toString("hex").startsWith("00002000010002")).toBe(true);
    expect(post?.body.includes(Buffer.from("eth_blockNumber"))).toBe(false);

    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.pathname).toBe("/");
    expect(seen[0]?.contentType).toBe("application/json");
    expect(seen[0]?.body.equals(Buffer.from(RPC_BODY))).toBe(true);
  });

  test("keepsOneNodePinnedAcrossRequests", async () => {
    const node = await startNode();
    const { url } = await startProxy(node);
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    expect((await postRpc(url)).status).toBe(200);
    for (let i = 0; i < 10; i += 1) {
      expect((await postRpc(url)).status).toBe(200);
    }

    const sealed = posts(node.wire);
    expect(sealed).toHaveLength(11);
    expect(sealed.every((r) => r.query === "node_id=proxy-node-1")).toBe(true);
    expect(gets(node.wire)).toHaveLength(1);
    expect(node.node.attestations()).toBe(1);
  });
});
