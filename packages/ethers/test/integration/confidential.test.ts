// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// ethers provider in Ankr Confidential RPC mode against the real sidecar.

import { isError, toUtf8String } from "ethers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { BadSignature, type VrpcOptions, VrpcProvider } from "../../src/index";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const CHAIN_ID = 42161;
const ADDR = "0x000000000000000000000000000000000000dEaD";

function threeCalls(p: VrpcProvider): Promise<[number, bigint, number]> {
  return Promise.all([p.getBlockNumber(), p.getBalance(ADDR), p.getTransactionCount(ADDR)]);
}

d("integration: ethers in Ankr Confidential RPC mode against the sidecar", () => {
  let env: Interop | undefined;
  const providers: VrpcProvider[] = [];

  beforeAll(async () => {
    env = await spawnInterop({ chainId: String(CHAIN_ID) });
  }, 60_000);

  afterAll(async () => {
    for (const p of providers) p.destroy();
    await env?.kill();
  });

  function stack(): Interop {
    if (!env) throw new Error("interop stack not started");
    return env;
  }

  function provider(options: VrpcOptions = {}): VrpcProvider {
    const p = new VrpcProvider(stack().relay.url, CHAIN_ID, {
      hardwareVerifier: mockHardwareVerifier(),
      // ethers would otherwise answer identical calls within 250 ms from one request.
      cacheTimeout: -1,
      ...options,
    });
    providers.push(p);
    return p;
  }

  it("a sealed call answers what the open-mode call answers", async () => {
    const { relay, nodeId } = stack();
    const before = relay.requests().length;
    const sealed = await provider({ confidential: true }).getBlockNumber();
    const seen = relay.requests().slice(before);

    expect(sealed).toBe(4660);
    expect(await provider().getBlockNumber()).toBe(sealed);
    expect(seen.some((r) => r.method === "GET" && r.url.startsWith("/attestation"))).toBe(true);
    expect(
      seen.some((r) => r.method === "POST" && r.url === `/confidential?node_id=${nodeId}`),
    ).toBe(true);
  });

  it("confidentialReady attests up front and reports the sidecar's key", async () => {
    const { sidecar, nodeId } = stack();
    const p = provider({ confidential: true });
    await p.confidentialReady();
    const info = p.getConfidentialInfo();
    expect(info?.nodeId).toBe(nodeId);
    expect(info?.pubkey.toLowerCase()).toBe(sidecar.pubkeyHex.toLowerCase());
  });

  it("three calls issued together travel as one sealed batch", async () => {
    const { upstream } = stack();
    const sealed = provider({ confidential: true });
    await sealed.send("eth_chainId", []);
    const before = upstream.requests().length;
    const answers = await threeCalls(sealed);
    const seen = upstream.requests().slice(before);

    expect(answers).toEqual([4660, 5n, 3]);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.jsonArrayLength).toBe(3);
    expect(await threeCalls(provider())).toEqual(answers);
  });

  it("1001 calls issued together all fail with the sidecar's 413 and the node is not called", async () => {
    const { upstream } = stack();
    const p = provider({ confidential: true, batchMaxCount: 1001 });
    await p.confidentialReady();
    const before = upstream.requests().length;
    const results = await Promise.allSettled(
      Array.from({ length: 1001 }, () => p.getBalance(ADDR)),
    );

    expect(results).toHaveLength(1001);
    for (const result of results) {
      expect(result.status).toBe("rejected");
      const err = (result as PromiseRejectedResult).reason;
      expect(isError(err, "SERVER_ERROR")).toBe(true);
      if (!isError(err, "SERVER_ERROR")) continue;
      expect(String(err.info?.responseStatus).startsWith("413")).toBe(true);
      const body = err.response?.body;
      expect(body).toBeTruthy();
      if (body) expect(toUtf8String(body)).toContain("urn:vrpc:error:batch-too-large");
    }
    expect(upstream.requests()).toHaveLength(before);
  }, 30_000);

  it("a flipped answer rejects with BadSignature and the next call recovers", async () => {
    const { relay } = stack();
    const p = provider({ confidential: true });
    await p.send("eth_chainId", []);
    relay.set({ mode: "flip" });
    try {
      const err = await p.getBlockNumber().then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(BadSignature);
      expect((err as BadSignature).kind).toBe("BadSignature");
    } finally {
      relay.set({ mode: "pass" });
    }
    expect(await p.getBlockNumber()).toBe(4660);
  });
});
