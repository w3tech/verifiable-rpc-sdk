// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client against the real sidecar and the dstack simulator.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import {
  BadSignature,
  ConfidentialClient,
  type InnerRequest,
  RequestRejected,
  UnavailableError,
  VerificationError,
} from "../../src/confidential";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const CHAIN_ID = "42161";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function parse(body: Uint8Array): unknown {
  return JSON.parse(decoder.decode(body));
}

function jsonRequest(payload: unknown): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: encoder.encode(JSON.stringify(payload)),
  };
}

function batch(size: number): { jsonrpc: string; id: number; method: string; params: [] }[] {
  return Array.from({ length: size }, (_, i) => ({
    jsonrpc: "2.0",
    id: i + 1,
    method: "eth_blockNumber",
    params: [],
  }));
}

let nextId = 1;

function blockNumber(): InnerRequest {
  return jsonRequest({ jsonrpc: "2.0", id: nextId++, method: "eth_blockNumber", params: [] });
}

d("integration: Ankr Confidential RPC against the sidecar", () => {
  let env: Interop | undefined;

  beforeAll(async () => {
    env = await spawnInterop({ chainId: CHAIN_ID });
  }, 60_000);

  afterAll(async () => {
    await env?.kill();
  });

  function stack(): Interop {
    if (!env) throw new Error("interop stack not started");
    return env;
  }

  function client(): ConfidentialClient {
    return new ConfidentialClient({
      url: stack().relay.url,
      chainId: CHAIN_ID,
      hardwareVerifier: mockHardwareVerifier(),
    });
  }

  it("answers a sealed JSON-RPC call exactly as the clear call", async () => {
    const { relay, upstream, nodeId } = stack();
    const relayBefore = relay.requests().length;
    const upstreamBefore = upstream.requests().length;
    const body = encoder.encode(
      JSON.stringify({ jsonrpc: "2.0", id: 7, method: "eth_blockNumber", params: [] }),
    );

    const res = await client().request({
      method: "POST",
      path: "/",
      contentType: "application/json",
      accept: "application/json",
      body,
    });

    expect(res.status).toBe(200);
    expect(res.contentType).toBe("application/json");
    expect(parse(res.body)).toEqual({ jsonrpc: "2.0", id: 7, result: "0x1234" });

    const seen = relay.requests().slice(relayBefore);
    expect(seen.map((r) => r.method)).toEqual(["GET", "POST"]);
    expect(seen[0]?.url).toMatch(/^\/attestation\?nonce=[0-9a-f]{64}$/);
    expect(seen[1]?.url).toBe(`/confidential?node_id=${nodeId}`);
    expect(seen[1]?.headers["content-type"]).toBe("message/ohttp-req");
    expect(upstream.requests().slice(upstreamBefore)).toEqual([
      expect.objectContaining({ method: "POST", url: "/" }),
    ]);

    const clear = await fetch(relay.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(await clear.json()).toEqual(parse(res.body));
    expect(upstream.requests().length).toBe(upstreamBefore + 2);
  });

  it("answers a batch in order with one upstream call", async () => {
    const { upstream } = stack();
    const before = upstream.requests().length;

    const res = await client().request(
      jsonRequest([
        { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] },
        { jsonrpc: "2.0", id: 2, method: "eth_chainId", params: [] },
        {
          jsonrpc: "2.0",
          id: 3,
          method: "eth_getBalance",
          params: ["0x0000000000000000000000000000000000000000", "latest"],
        },
      ]),
    );

    expect(res.status).toBe(200);
    expect(parse(res.body)).toEqual([
      { jsonrpc: "2.0", id: 1, result: "0x1234" },
      { jsonrpc: "2.0", id: 2, result: "0xa4b1" },
      { jsonrpc: "2.0", id: 3, result: "0x5" },
    ]);
    const calls = upstream.requests().slice(before);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: "POST", jsonArrayLength: 3 });
  });

  it("serves a batch at the size limit and refuses one call more before the node", async () => {
    const { upstream } = stack();
    const c = client();

    const full = await c.request(jsonRequest(batch(1000)));
    expect(full.status).toBe(200);
    const results = parse(full.body) as { id: number }[];
    expect(results.map((r) => r.id)).toEqual(batch(1000).map((call) => call.id));

    const before = upstream.requests().length;
    const over = await c.request(jsonRequest(batch(1001)));
    expect(over.status).toBe(413);
    expect(over.contentType).toBe("application/problem+json");
    expect(parse(over.body)).toMatchObject({ type: "urn:vrpc:error:batch-too-large" });
    expect(upstream.requests().length).toBe(before);
  }, 30_000);

  it("carries a REST request with its path and query", async () => {
    const res = await client().request({
      method: "GET",
      path: "/v1/status?x=1&y=two",
      accept: "application/json",
    });

    expect(res.status).toBe(200);
    expect(parse(res.body)).toEqual({ method: "GET", url: "/v1/status?x=1&y=two" });
    expect(stack().upstream.requests().at(-1)).toMatchObject({
      method: "GET",
      url: "/v1/status?x=1&y=two",
      accept: "application/json",
    });
  });

  it("returns inner error and empty statuses as answers", async () => {
    const { relay } = stack();
    const c = client();

    const notFound = await c.request({ method: "GET", path: "/status/404" });
    expect(notFound.status).toBe(404);
    expect(notFound.contentType).toMatch(/^text\/plain/);
    expect(decoder.decode(notFound.body)).toBe("status 404");

    const noContent = await c.request({ method: "GET", path: "/status/204" });
    expect(noContent.status).toBe(204);
    expect(noContent.body).toHaveLength(0);
    expect(relay.requests().at(-1)).toMatchObject({ method: "POST", status: 200 });
  });

  it("sends nothing of the inner request in clear", async () => {
    const { relay, upstream } = stack();
    const relayBefore = relay.requests().length;

    const res = await client().request({
      method: "POST",
      path: "/sentinel-path?q=sentinel-query",
      accept: "application/sentinel-accept",
      contentType: "application/sentinel-type",
      body: encoder.encode("sentinel-plaintext"),
    });

    expect(res.status).toBe(400);
    const seen = relay.requests().slice(relayBefore);
    expect(seen.length).toBeGreaterThan(0);
    for (const record of seen) {
      const exposed = [
        record.url,
        ...Object.entries(record.headers).flat(),
        decoder.decode(record.body),
        Buffer.from(record.body).toString("hex"),
      ]
        .join("\n")
        .toLowerCase();
      expect(exposed).not.toContain("sentinel");
      expect(exposed).not.toContain("73656e74696e656c");
    }
    expect(upstream.requests().at(-1)?.url).toBe("/sentinel-path?q=sentinel-query");
  });

  it("rejects a flipped answer byte and re-attests on the next call", async () => {
    const { relay } = stack();
    const c = client();
    await c.request(blockNumber());

    try {
      relay.set({ mode: "flip" });
      const err = await c.request(blockNumber()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      expect(err).toMatchObject({ kind: "BadSignature" });

      const attestations = relay.attestations();
      relay.set({ mode: "pass" });
      const res = await c.request(blockNumber());
      expect(res.status).toBe(200);
      expect(relay.attestations()).toBe(attestations + 1);
    } finally {
      relay.set({ mode: "pass", confidentialTarget: null });
    }
  });

  it("rejects a replayed answer to another request without reaching the node", async () => {
    const { relay, upstream } = stack();
    const c = client();
    await c.request(blockNumber());

    try {
      relay.set({ mode: "replay" });
      const before = upstream.requests().length;
      const err = await c
        .request(jsonRequest({ jsonrpc: "2.0", id: nextId++, method: "eth_chainId", params: [] }))
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BadSignature);
      expect(err).toMatchObject({ kind: "BadSignature" });
      expect(upstream.requests().length).toBe(before);
    } finally {
      relay.set({ mode: "pass", confidentialTarget: null });
    }
  });

  it("rejects a request sealed to another node key before the node runs it", async () => {
    const env = stack();
    const extra = await env.spawnExtraSidecar(["--key-path", "rpc-sign/other"]);
    const c = client();
    const before = env.upstream.requests().length;

    try {
      env.relay.set({ confidentialTarget: extra.url });
      const err = await c.request(blockNumber()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RequestRejected);
      expect(err).toBeInstanceOf(UnavailableError);
      expect(err).toMatchObject({ status: 400, executed: "no" });
      expect(env.upstream.requests().length).toBe(before);

      const attestations = env.relay.attestations();
      env.relay.set({ confidentialTarget: null });
      const res = await c.request(blockNumber());
      expect(res.status).toBe(200);
      expect(env.relay.attestations()).toBe(attestations + 1);
    } finally {
      env.relay.set({ mode: "pass", confidentialTarget: null });
    }
  }, 30_000);
});
