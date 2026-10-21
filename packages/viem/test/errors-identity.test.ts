// Every error class Ankr Confidential RPC mode can throw is exported by the adapter as the very
// class core exports from each of its entries, so instanceof holds whichever one a caller imports.

import * as core from "@w3tech.io/vrpc-core";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import * as errors from "@w3tech.io/vrpc-core/errors";
import { isPost, KEY, mockHardwareVerifier, rejectionOf } from "@w3tech.io/vrpc-test-support";
import { describeAdapterErrors, serveRpcNode } from "@w3tech.io/vrpc-test-support/adapter";
import * as adapter from "@w3tech.io/vrpc-viem";
import { BaseError, createPublicClient, defineChain } from "viem";
import { describe, expect, test } from "vitest";

const arbitrum = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

describeAdapterErrors("viem", { adapter, core, errors, confidential: conf });

describe("an error from a live call", () => {
  test("a rejected sealed call is an instance of the classes from every entry", async () => {
    const { server } = await serveRpcNode();
    server.answer((request) =>
      isPost(request)
        ? { status: 429, headers: { "content-type": "text/plain", "retry-after": "1" } }
        : undefined,
    );
    const client = createPublicClient({
      chain: arbitrum,
      transport: adapter.vrpcHttp(`${server.url}/eth_vrpc`, {
        headers: { "x-api-key": KEY },
        hardwareVerifier: mockHardwareVerifier(),
        confidential: true,
      }),
    });

    const thrown = await rejectionOf(client.getBlockNumber({ cacheTime: 0 }));
    expect(thrown).toBeInstanceOf(BaseError);
    const err = (thrown as BaseError).walk((e) => e instanceof core.UnavailableError);

    for (const entry of [adapter, core, errors, conf]) {
      expect(err).toBeInstanceOf(entry.RequestRejected);
      expect(err).toBeInstanceOf(entry.UnavailableError);
    }
    expect((err as core.RequestRejected).status).toBe(429);
  });
});
