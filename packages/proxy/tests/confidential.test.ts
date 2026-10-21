// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode end to end against the in-test node behind a loopback server.

import { ConfidentialClient, InvalidOption } from "@w3tech.io/vrpc-core/confidential";
import { createTestNode, TEST_SEED } from "@w3tech.io/vrpc-test-support";
import {
  type ServedRequest,
  serveTestNode,
  type TestNodeServer,
} from "@w3tech.io/vrpc-test-support/server";
import { Agent, request } from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createProxyServer, type ProxyTestOverrides } from "../src/server";
import { type RunningProxy, startConfidentialProxy } from "./support/proxy";
import { TEST_CHAIN_ID, testConfig } from "./support/test-overrides";

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
  vi.restoreAllMocks();
  await proxy?.close();
  await nodeServer?.close();
  proxy = undefined;
  nodeServer = undefined;
});

async function startNode(seen: SeenInner[] = []): Promise<TestNodeServer> {
  nodeServer = await serveTestNode(
    createTestNode({
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
    }),
  );
  return nodeServer;
}

async function startProxy(
  node: TestNodeServer,
  overrides: ProxyTestOverrides = {},
): Promise<RunningProxy> {
  proxy = await startConfidentialProxy(
    node,
    { apiKey: API_KEY, attestationHeaders: { "x-api-key": API_KEY } },
    overrides,
  );
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

const posts = (wire: ServedRequest[]) => wire.filter((r) => r.method === "POST");
const gets = (wire: ServedRequest[]) => wire.filter((r) => r.method === "GET");

describe("confidential mode", () => {
  test("attestsOnceAtStartupBeforeAnyClientRequest", async () => {
    const node = await startNode();
    await startProxy(node);
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    expect(node.requests).toHaveLength(1);
    const [get] = node.requests;
    expect(get?.method).toBe("GET");
    expect(get?.path).toBe("/test_vrpc/attestation");
    expect(get?.url).toMatch(/^[^?]*\?nonce=[0-9a-f]{64}$/);
    expect(posts(node.requests)).toHaveLength(0);
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

    expect(node.requests).toHaveLength(2);
    const [post] = posts(node.requests);
    expect(post?.path).toBe("/test_vrpc/confidential");
    expect(post?.url).toBe(`${post?.path}?node_id=proxy-node-1`);
    expect(post?.headers["content-type"]).toBe("message/ohttp-req");
    expect(post?.headers["accept-encoding"]).toBe("identity");
    expect(post?.headers["x-api-key"]).toBe(API_KEY);
    const body = Buffer.from(post?.body ?? []);
    expect(body.toString("hex").startsWith("00002000010002")).toBe(true);
    expect(body.includes(Buffer.from("eth_blockNumber"))).toBe(false);

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

    const sealed = posts(node.requests);
    expect(sealed).toHaveLength(11);
    expect(sealed.every((r) => r.url === `${r.path}?node_id=proxy-node-1`)).toBe(true);
    expect(gets(node.requests)).toHaveLength(1);
    expect(node.node.attestations()).toBe(1);
  });
});

describe("confidential mode startup", () => {
  test("failedStartupAttestationKeepsServingAndTheNextRequestAttestsAgain", async () => {
    const node = await startNode();
    node.node.setAttestation(() => ({
      status: 503,
      headers: { "content-type": "text/plain" },
      body: new Uint8Array(0),
    }));
    const events: string[] = [];
    const running = await startProxy(node, {
      logger: { debug: (event) => void events.push(event) },
    });
    await vi.waitFor(() => expect(events).toContain("confidential.attest.fail"));
    expect(node.node.attestations()).toBe(1);
    expect(running.server.listening).toBe(true);

    const failed = await postRpc(running.url);
    expect(failed.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(failed.body.toString()).error.kind).toBe("AttestationUnavailable");
    expect(node.node.attestations()).toBe(2);
    expect(posts(node.requests)).toHaveLength(0);

    node.node.setAttestation();
    const ok = await postRpc(running.url);
    expect(ok.status).toBe(200);
    expect(ok.body.toString()).toBe(RPC_ANSWER);
    expect(node.node.attestations()).toBe(3);
    expect(posts(node.requests)).toHaveLength(1);
  });

  test("requestDuringStartupAttestationJoinsIt", async () => {
    const node = await startNode();
    const { promise: gate, resolve: release } = Promise.withResolvers<void>();
    node.node.setAttestation(async (context) => {
      await gate;
      return context.normal();
    });
    const running = await startProxy(node);
    await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

    const requested = vi.spyOn(ConfidentialClient.prototype, "request");
    const pending = postRpc(running.url);
    await vi.waitFor(() => expect(requested).toHaveBeenCalledTimes(1));
    release();

    const res = await pending;
    expect(res.status).toBe(200);
    expect(gets(node.requests)).toHaveLength(1);
    expect(posts(node.requests)).toHaveLength(1);
  });

  test.each([
    true,
    false,
  ])("confidential %s: invalid options throw InvalidOption before listen and close the Agent", (confidential) => {
    const close = vi.spyOn(Agent.prototype, "close");
    const upstream = "http://127.0.0.1:1/test_vrpc";
    const badKey = "bad\nkey";
    const build = (overrides: Parameters<typeof testConfig>[1]) => () =>
      createProxyServer(testConfig(upstream, { confidential, ...overrides }));

    const badHeader = build({ attestationHeaders: { "x-api-key": badKey } });
    expect(badHeader).toThrow(InvalidOption);
    let message = "";
    try {
      badHeader();
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).not.toContain("bad");
    expect(build({ replayWindowMs: 1.5 })).toThrow(InvalidOption);
    expect(build({ pubkeyCacheTtlMs: Number.POSITIVE_INFINITY })).toThrow(InvalidOption);
    expect(new Set(close.mock.contexts).size).toBe(4);
  });
});
