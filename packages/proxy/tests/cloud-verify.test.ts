// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Without test overrides the proxy verifies attestations over the network:
// these tests pin that the attestation GET and the Phala cloud verify POST go
// through undici fetch on the proxy's Agent, never through global fetch.

import http from "node:http";
import { DEFAULT_PHALA_VERIFY_ENDPOINT } from "@w3tech.io/vrpc-core";
import { attestationBody, createTestNode } from "@w3tech.io/vrpc-test-support";
import { closeServer, listen, serveTestNode } from "@w3tech.io/vrpc-test-support/server";
import * as undici from "undici";
import { describe, expect, onTestFinished, test, vi } from "vitest";
import { createProxyServer } from "../src/index";
import { startMockSidecar } from "./support/mock-sidecar";
import { errorOf, postRpc } from "./support/proxy";
import { TEST_CHAIN_ID, testConfig } from "./support/test-overrides";

vi.mock("undici", async (importOriginal) => {
  const actual = await importOriginal<typeof import("undici")>();
  return { ...actual, fetch: vi.fn(actual.fetch) };
});

/** Mock the network: global fetch fails, undici fetch answers attestation and refuses Phala. */
function mockNetwork() {
  const globalFetch = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("global fetch"));
  onTestFinished(async () => globalFetch.mockRestore());
  const calls: { url: string; dispatcher: unknown }[] = [];
  vi.mocked(undici.fetch).mockImplementation(async (input, init) => {
    const url = String(input);
    calls.push({ url, dispatcher: init?.dispatcher });
    if (url === DEFAULT_PHALA_VERIFY_ENDPOINT || !url.includes("/attestation")) {
      return new undici.Response("unavailable", { status: 503 });
    }
    const nonce = new URL(url).searchParams.get("nonce") ?? "";
    return new undici.Response(attestationBody(nonce), {
      headers: { "content-type": "application/json" },
    });
  });
  return { globalFetch, calls };
}

async function serve(server: http.Server): Promise<string> {
  const url = await listen(server);
  onTestFinished(() => closeServer(server));
  return url;
}

describe("cloud verify egress", () => {
  test("open mode verifies the attestation through the proxy Agent", async () => {
    const { globalFetch, calls } = mockNetwork();
    const mock = await startMockSidecar();
    onTestFinished(() => mock.close());
    const url = await serve(createProxyServer(testConfig(mock.url)));

    const res = await postRpc(url);
    expect(globalFetch).not.toHaveBeenCalled();
    expect(errorOf(res)).toMatchObject({ status: 503, kind: "AttestationUnavailable" });
    const attestation = calls.find((c) => c.url.includes("/attestation"));
    expect(attestation?.dispatcher).toBeInstanceOf(undici.Agent);
    const phala = calls.find((c) => c.url === DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(phala?.dispatcher).toBeInstanceOf(undici.Agent);
  });

  test("open-mode attestation is bounded by --timeout", async () => {
    const actual = await vi.importActual<typeof import("undici")>("undici");
    vi.mocked(undici.fetch).mockImplementation(actual.fetch);
    const globalFetch = vi.spyOn(globalThis, "fetch");
    onTestFinished(async () => globalFetch.mockRestore());
    const silent = http.createServer(() => {});
    const silentUrl = await serve(silent);
    const mock = await startMockSidecar();
    onTestFinished(() => mock.close());
    const config = testConfig(mock.url, {
      attestationUrl: `${silentUrl}/attestation`,
      upstreamTimeoutMs: 200,
    });
    const url = await serve(createProxyServer(config));

    expect(errorOf(await postRpc(url))).toMatchObject({
      status: 504,
      kind: "AttestationUnavailable",
    });
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test("Ankr Confidential RPC verifies the attestation through the proxy Agent", async () => {
    const { globalFetch, calls } = mockNetwork();
    const node = await serveTestNode(createTestNode({ chainId: TEST_CHAIN_ID }));
    onTestFinished(() => node.close());
    const config = testConfig(`${node.url}/test_vrpc`, { confidential: true });
    const url = await serve(createProxyServer(config));

    expect(errorOf(await postRpc(url))).toMatchObject({
      status: 503,
      kind: "AttestationUnavailable",
    });
    expect(globalFetch).not.toHaveBeenCalled();
    const phala = calls.find((c) => c.url === DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(phala?.dispatcher).toBeInstanceOf(undici.Agent);
  });
});
