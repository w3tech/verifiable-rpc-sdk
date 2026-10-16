// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// viem transport in Ankr Confidential RPC mode against the real sidecar.

import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INTEROP_SKIP_MESSAGE,
  type Interop,
  integrationEnabled,
  spawnInterop,
} from "../../../test-support/src/interop";
import { vrpcHttp } from "../../src/index";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";

if (!integrationEnabled) {
  console.log(INTEROP_SKIP_MESSAGE);
}

const d = integrationEnabled ? describe : describe.skip;

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
      transport: vrpcHttp(stack().relay.url, {
        confidential: true,
        hardwareVerifier: mockHardwareVerifier(),
      }),
    });
  }

  function openClient() {
    return createPublicClient({
      chain: arbitrum,
      transport: vrpcHttp(stack().relay.url, { hardwareVerifier: mockHardwareVerifier() }),
    });
  }

  it("a sealed call answers what the open-mode call answers", async () => {
    const sealed = await sealedClient().getBlockNumber();
    expect(sealed).toBe(4660n);
    expect(await openClient().getBlockNumber()).toBe(sealed);
  });
});
