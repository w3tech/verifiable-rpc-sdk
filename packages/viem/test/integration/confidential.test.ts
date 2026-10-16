// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// viem transport in Ankr Confidential RPC mode against the real sidecar.

import { BaseError, createPublicClient } from "viem";
import { arbitrum } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { BadSignature, vrpcHttp } from "../../src/index";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const ADDR = "0x000000000000000000000000000000000000dEaD";

d("integration: viem in Ankr Confidential RPC mode against the sidecar", () => {
  let env: Interop | undefined;

  beforeAll(async () => {
    env = await spawnInterop({ chainId: String(arbitrum.id) });
  }, 60_000);

  afterAll(async () => {
    await env?.kill();
  });

  function stack(): Interop {
    if (!env) throw new Error("interop stack not started");
    return env;
  }

  function sealedClient() {
    return createPublicClient({
      chain: arbitrum,
      cacheTime: 0,
      transport: vrpcHttp(stack().relay.url, {
        confidential: true,
        hardwareVerifier: mockHardwareVerifier(),
      }),
    });
  }

  function openClient() {
    return createPublicClient({
      chain: arbitrum,
      cacheTime: 0,
      transport: vrpcHttp(stack().relay.url, { hardwareVerifier: mockHardwareVerifier() }),
    });
  }

  it("a sealed call answers what the open-mode call answers", async () => {
    const sealed = await sealedClient().getBlockNumber();
    expect(sealed).toBe(4660n);
    expect(await openClient().getBlockNumber()).toBe(sealed);
  });

  it("eth_chainId and getBalance answer the same in both modes", async () => {
    const sealed = sealedClient();
    const open = openClient();
    expect(await sealed.request({ method: "eth_chainId" })).toBe("0xa4b1");
    expect(await open.request({ method: "eth_chainId" })).toBe("0xa4b1");
    expect(await sealed.getBalance({ address: ADDR })).toBe(5n);
    expect(await open.getBalance({ address: ADDR })).toBe(5n);
  });

  it("transport.ready attests up front and getConfidentialInfo reports the node", async () => {
    const client = sealedClient();
    await client.transport.ready();
    expect(client.transport.getConfidentialInfo()?.nodeId).toBe("interop-node-1");
  });

  it("a flipped answer rejects with BadSignature, is not resent and the next call recovers", async () => {
    const { relay } = stack();
    const client = sealedClient();
    const sealedPosts = () =>
      relay.requests().filter((r) => r.method === "POST" && r.url.startsWith("/confidential"))
        .length;
    await client.request({ method: "eth_chainId" });
    relay.set({ mode: "flip" });
    try {
      const before = sealedPosts();
      const err = await client.getBlockNumber().then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(sealedPosts()).toBe(before + 1);
      expect(err).toBeInstanceOf(BaseError);
      const found = (err as BaseError).walk(
        (e) => (e as { kind?: unknown } | undefined)?.kind === "BadSignature",
      );
      expect(found).toBeInstanceOf(BadSignature);
    } finally {
      relay.set({ mode: "pass" });
    }
    expect(await client.getBlockNumber()).toBe(4660n);
  });
});
