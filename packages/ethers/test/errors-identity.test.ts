// Every error class Ankr Confidential RPC mode can throw is exported by the adapter as the very
// class core exports from each of its entries, so instanceof holds whichever one a caller imports.

import * as core from "@w3tech.io/vrpc-core";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import * as errors from "@w3tech.io/vrpc-core/errors";
import * as adapter from "@w3tech.io/vrpc-ethers";
import {
  CHAIN_ID,
  createTestNode,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  TEST_SEED,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import { describeAdapterErrors } from "@w3tech.io/vrpc-test-support/adapter";
import { serveTestNode } from "@w3tech.io/vrpc-test-support/server";
import { afterEach, describe, expect, test } from "vitest";

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describeAdapterErrors("ethers", { adapter, core, errors, confidential: conf });

describe("an error from a live call", () => {
  test("a rejected sealed call is an instance of the classes from every entry", async () => {
    const node = createTestNode({
      seed: TEST_SEED,
      chainId: CHAIN_ID,
      nodeId: NODE_ID,
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
    const provider = new adapter.VrpcProvider(`${server.url}/eth_vrpc/${KEY}`, 42161, {
      confidential: true,
      hardwareVerifier: mockHardwareVerifier(),
      cacheTimeout: -1,
    });
    cleanups.push(() => provider.destroy());

    const err = await rejectionOf(provider.getBlockNumber());

    for (const entry of [adapter, core, errors, conf]) {
      expect(err).toBeInstanceOf(entry.RequestRejected);
      expect(err).toBeInstanceOf(entry.UnavailableError);
    }
    expect((err as core.RequestRejected).status).toBe(429);
  });
});
