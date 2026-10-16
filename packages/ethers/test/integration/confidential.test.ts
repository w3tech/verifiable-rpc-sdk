// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// ethers provider in Ankr Confidential RPC mode against the real sidecar.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { type VrpcOptions, VrpcProvider } from "../../src/index";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

const CHAIN_ID = 42161;

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
});
