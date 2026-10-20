// Every error class Ankr Confidential RPC mode can throw is exported by the adapter as the very
// class core exports from each of its entries, so instanceof holds whichever one a caller imports.

import * as core from "@w3tech.io/vrpc-core";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import * as errors from "@w3tech.io/vrpc-core/errors";
import {
  createTestNode,
  mockHardwareVerifier,
  rejectionOf,
  TEST_SEED,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import { describeAdapterErrors } from "@w3tech.io/vrpc-test-support/adapter";
import { serveTestNode } from "@w3tech.io/vrpc-test-support/server";
import * as adapter from "@w3tech.io/vrpc-viem";
import { BaseError, createPublicClient, defineChain } from "viem";
import { afterEach, describe, expect, test } from "vitest";
import { CHAIN_ID } from "./fixtures";

const KEY = "0123456789abcdefghijABCDEFGHIJkl";

const arbitrum = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describeAdapterErrors("viem", { adapter, core, errors, confidential: conf });

describe("an error from a live call", () => {
  test("a rejected sealed call is an instance of the classes from every entry", async () => {
    const node = createTestNode({
      seed: TEST_SEED,
      chainId: CHAIN_ID,
      nodeId: "alpha-vrpc-1",
      upstream: async (request): Promise<TestUpstreamResponse> => {
        const call = JSON.parse(await request.text()) as { id: number };
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: call.id, result: "0x10" }),
        };
      },
    });
    const server = await serveTestNode(node);
    cleanups.push(() => server.close());
    server.answer((request) =>
      request.method === "POST"
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
