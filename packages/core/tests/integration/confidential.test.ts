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
import { ConfidentialClient } from "../../src/confidential";
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
});
