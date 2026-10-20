// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpc-proxy in Ankr Confidential RPC mode against the real sidecar.

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { createProxyServer } from "../../src/index";
import { testConfig } from "../support/test-overrides";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const CHAIN_ID = "42161";
const BLOCK_NUMBER = { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] };

function batch(size: number): (typeof BLOCK_NUMBER)[] {
  return Array.from({ length: size }, (_, i) => ({ ...BLOCK_NUMBER, id: i + 1 }));
}

function relayedHeaderNames(res: Response): string[] {
  return [...res.headers.keys()].filter((n) => n.startsWith("vrpc-") || n === "content-encoding");
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

async function waitFor(check: () => boolean, maxMs: number): Promise<void> {
  const deadline = Date.now() + maxMs;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error("timeout waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

d("integration: vrpc-proxy in Ankr Confidential RPC mode against the sidecar", () => {
  let env: Interop | undefined;
  const servers: Server[] = [];
  let sealedUrl = "";
  let openUrl = "";

  async function startProxy(relayUrl: string, confidential: boolean): Promise<string> {
    const config = testConfig(relayUrl, {
      chainId: CHAIN_ID,
      attestationUrl: `${relayUrl}/attestation`,
      ...(confidential ? { confidential: true } : {}),
    });
    const server = createProxyServer(config, { hardwareVerifier: mockHardwareVerifier() });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  beforeAll(async () => {
    env = await spawnInterop({ chainId: CHAIN_ID });
    const relay = env.relay;
    sealedUrl = await startProxy(relay.url, true);
    await waitFor(() => relay.attestations() >= 1, 15_000);
    openUrl = await startProxy(relay.url, false);
  }, 60_000);

  afterAll(async () => {
    for (const server of servers) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    }
    await env?.kill();
  });

  function stack(): Interop {
    if (!env) throw new Error("interop stack not started");
    return env;
  }

  function post(base: string, payload: unknown): Promise<Response> {
    return fetch(`${base}/`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      redirect: "manual",
    });
  }

  it("a sealed JSON-RPC call answers what the open-mode proxy answers", async () => {
    const sealed = await post(sealedUrl, BLOCK_NUMBER);
    expect(sealed.status).toBe(200);
    expect(sealed.headers.get("content-type")).toBe("application/json");
    const body = await sealed.text();
    expect(body).toBe('{"jsonrpc":"2.0","id":1,"result":"0x1234"}');

    const open = await post(openUrl, BLOCK_NUMBER);
    expect(open.status).toBe(200);
    expect(await open.json()).toEqual(JSON.parse(body));
  });

  it("a 3-element batch is relayed in one sealed call", async () => {
    const { upstream } = stack();
    const before = upstream.requests().length;
    const res = await post(sealedUrl, batch(3));
    const seen = upstream.requests().slice(before);

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(relayedHeaderNames(res)).toEqual([]);
    const body = (await res.json()) as { id: number }[];
    expect(body.map((r) => r.id)).toEqual([1, 2, 3]);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.jsonArrayLength).toBe(3);
  });

  it("a 1001-element batch answers the sidecar's 413 and the node is not called", async () => {
    const { upstream } = stack();
    const before = upstream.requests().length;
    const res = await post(sealedUrl, batch(1001));

    expect(res.status).toBe(413);
    expect(res.headers.get("content-type")).toBe("application/problem+json");
    expect(relayedHeaderNames(res)).toEqual([]);
    expect(((await res.json()) as { type?: string }).type).toBe("urn:vrpc:error:batch-too-large");
    expect(upstream.requests()).toHaveLength(before);
  });

  it("a REST GET keeps its path and query", async () => {
    const { upstream } = stack();
    const res = await fetch(`${sealedUrl}/v1/status?x=1&y=two`, {
      headers: { accept: "application/json" },
      redirect: "manual",
    });

    expect(res.status).toBe(200);
    expect(relayedHeaderNames(res)).toEqual([]);
    expect(await res.json()).toEqual({ method: "GET", url: "/v1/status?x=1&y=two" });
    expect(upstream.requests().at(-1)?.url).toBe("/v1/status?x=1&y=two");
  });

  it("an inner 404 keeps its status and content-type", async () => {
    const res = await fetch(`${sealedUrl}/status/404`, { redirect: "manual" });

    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")?.startsWith("text/plain")).toBe(true);
    expect(relayedHeaderNames(res)).toEqual([]);
    expect(await res.text()).toBe("status 404");
  });

  it("the client's path and query never reach the relay in the clear", async () => {
    const { relay, upstream } = stack();
    const before = relay.requests().length;
    const res = await fetch(`${sealedUrl}/sentinel-path?q=sentinel-query`, { redirect: "manual" });
    await res.arrayBuffer();
    const seen = relay.requests().slice(before);

    expect(seen.length).toBeGreaterThan(0);
    for (const record of seen) {
      expect(record.url).not.toContain("sentinel");
      for (const value of Object.values(record.headers)) expect(value).not.toContain("sentinel");
      expect(new TextDecoder().decode(record.body)).not.toContain("sentinel");
      expect(toHex(record.body)).not.toContain("73656e74696e656c");
    }
    expect(upstream.requests().at(-1)?.url).toBe("/sentinel-path?q=sentinel-query");
  });

  it("a flipped answer is a 502 BadSignature and the next request re-attests", async () => {
    const { relay } = stack();
    relay.set({ mode: "flip" });
    let attestations: number;
    try {
      const res = await post(sealedUrl, BLOCK_NUMBER);
      expect(res.status).toBe(502);
      const body = (await res.json()) as { error?: { kind?: string } };
      expect(body.error?.kind).toBe("BadSignature");
      attestations = relay.attestations();
    } finally {
      relay.set({ mode: "pass" });
    }

    const res = await post(sealedUrl, BLOCK_NUMBER);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jsonrpc: "2.0", id: 1, result: "0x1234" });
    expect(relay.attestations()).toBe(attestations + 1);
  });
});
