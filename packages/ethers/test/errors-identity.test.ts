// Every error class Ankr Confidential RPC mode can throw is exported by the adapter as the very
// class core exports from each of its entries, so instanceof holds whichever one a caller imports.

import * as core from "@w3tech.io/vrpc-core";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import * as errors from "@w3tech.io/vrpc-core/errors";
import * as adapter from "@w3tech.io/vrpc-ethers";
import { isPost, KEY, mockHardwareVerifier, rejectionOf } from "@w3tech.io/vrpc-test-support";
import { describeAdapterErrors, serveRpcNode } from "@w3tech.io/vrpc-test-support/adapter";
import { afterEach, describe, expect, test } from "vitest";

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describeAdapterErrors("ethers", { adapter, core, errors, confidential: conf });

describe("an error from a live call", () => {
  test("a rejected sealed call is an instance of the classes from every entry", async () => {
    const { server } = await serveRpcNode();
    server.answer((request) =>
      isPost(request)
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
