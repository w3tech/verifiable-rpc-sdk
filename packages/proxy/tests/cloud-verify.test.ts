// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Without test overrides the proxy verifies attestations over the network:
// these tests pin that the attestation GET and the Phala cloud verify POST go
// through undici fetch on the proxy's Agent, never through global fetch.

import http from "node:http";
import { DEFAULT_PHALA_VERIFY_ENDPOINT } from "@w3tech.io/vrpc-core";
import { attestationBody, TEST_SEED } from "@w3tech.io/vrpc-test-support";
import * as undici from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";

import { createProxyServer } from "../src/index";
import { startMockSidecar } from "./support/mock-sidecar";
import { closeServer, listen, rawRequest, startTestNodeServer } from "./support/test-node-server";
import { TEST_CHAIN_ID, testConfig } from "./support/test-overrides";

vi.mock("undici", async (importOriginal) => {
  const actual = await importOriginal<typeof import("undici")>();
  return { ...actual, fetch: vi.fn(actual.fetch) };
});

const RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';

const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/** Mock the network: global fetch fails, undici fetch answers attestation and refuses Phala. */
function mockNetwork() {
  const globalFetch = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("global fetch"));
  cleanups.push(async () => globalFetch.mockRestore());
  const calls: { url: string; dispatcher: unknown }[] = [];
  vi.mocked(undici.fetch).mockImplementation(async (input, init) => {
    const url = String(input);
    calls.push({ url, dispatcher: init?.dispatcher });
    if (!url.includes("/attestation")) return new undici.Response("unavailable", { status: 503 });
    const nonce = new URL(url).searchParams.get("nonce") ?? "";
    return new undici.Response(attestationBody(nonce), {
      headers: { "content-type": "application/json" },
    });
  });
  return { globalFetch, calls };
}

async function serve(server: http.Server): Promise<string> {
  const url = await listen(server);
  cleanups.push(() => closeServer(server));
  return url;
}

async function postRpc(url: string): Promise<{ status: number; kind: string }> {
  const res = await rawRequest(url, {
    method: "POST",
    path: "/",
    headers: { "content-type": "application/json" },
    body: RPC_BODY,
  });
  const { kind } = (JSON.parse(res.body.toString()) as { error: { kind: string } }).error;
  return { status: res.status, kind };
}

describe("cloud verify egress", () => {
  test("open mode verifies the attestation through the proxy Agent", async () => {
    const { globalFetch, calls } = mockNetwork();
    const mock = await startMockSidecar();
    cleanups.push(() => mock.close());
    const url = await serve(createProxyServer(testConfig(mock.url)));

    const { kind } = await postRpc(url);
    expect(globalFetch).not.toHaveBeenCalled();
    expect(kind).toBe("Attestation");
    const attestation = calls.find((c) => c.url.includes("/attestation"));
    expect(attestation?.dispatcher).toBeInstanceOf(undici.Agent);
    const phala = calls.find((c) => c.url === DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(phala?.dispatcher).toBeInstanceOf(undici.Agent);
  });

  test("open-mode attestation is bounded by --timeout", async () => {
    const actual = await vi.importActual<typeof import("undici")>("undici");
    vi.mocked(undici.fetch).mockImplementation(actual.fetch);
    const globalFetch = vi.spyOn(globalThis, "fetch");
    cleanups.push(async () => globalFetch.mockRestore());
    const slow = http.createServer((_req, res) => {
      const timer = setTimeout(() => res.end("{}"), 1000);
      res.on("close", () => clearTimeout(timer));
    });
    const slowUrl = await serve(slow);
    const mock = await startMockSidecar();
    cleanups.push(() => mock.close());
    const config = testConfig(mock.url, {
      attestationUrl: `${slowUrl}/attestation`,
      upstreamTimeoutMs: 200,
    });
    const url = await serve(createProxyServer(config));

    const started = Date.now();
    expect(await postRpc(url)).toEqual({ status: 504, kind: "AttestationUnavailable" });
    expect(Date.now() - started).toBeLessThan(1000);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test("Ankr Confidential RPC verifies the attestation through the proxy Agent", async () => {
    const { globalFetch, calls } = mockNetwork();
    const node = await startTestNodeServer({ seed: TEST_SEED, chainId: TEST_CHAIN_ID });
    cleanups.push(() => node.close());
    const config = testConfig(`${node.url}/test_vrpc`, { confidential: true });
    const url = await serve(createProxyServer(config));

    await postRpc(url);
    expect(globalFetch).not.toHaveBeenCalled();
    const phala = calls.find((c) => c.url === DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(phala?.dispatcher).toBeInstanceOf(undici.Agent);
  });
});
