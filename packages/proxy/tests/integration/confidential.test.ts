// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpc-proxy in Ankr Confidential RPC mode against the real sidecar.

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { createProxyServer } from "../../src/index";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";
import { testConfig } from "../support/test-overrides";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const CHAIN_ID = "42161";
const BLOCK_NUMBER = { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] };

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
});
