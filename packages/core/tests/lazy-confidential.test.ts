import {
  CHAIN_ID,
  createTestNode,
  jsonRpcCall,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { ConfidentialClientOptions } from "../src/confidential-client";
import { InvalidOption } from "../src/errors";
import { LazyConfidentialClient } from "../src/lazy-confidential";

function optionsFor(node: ReturnType<typeof createTestNode>): ConfidentialClientOptions {
  return {
    url: `https://rpc.example/eth_vrpc/${KEY}`,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport: node.transport,
  };
}

function testNode() {
  return createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
}

describe("LazyConfidentialClient", () => {
  afterEach(() => {
    vi.doUnmock("../src/confidential-client");
    vi.resetModules();
  });

  test.each([
    { replayWindowMs: 0 },
    { chainId: undefined as unknown as string },
  ])("a bad option %o throws InvalidOption at construction", (bad) => {
    expect(() => new LazyConfidentialClient({ ...optionsFor(testNode()), ...bad })).toThrow(
      InvalidOption,
    );
  });

  test("request and ready load one client and report the same pin", async () => {
    const node = testNode();
    const client = new LazyConfidentialClient(optionsFor(node));
    expect(client.getConfidentialInfo()).toBeUndefined();

    const responses = await Promise.all(
      Array.from({ length: 20 }, () => client.request(jsonRpcCall())),
    );
    const info = await client.ready();

    expect(responses.every((response) => response.status === 200)).toBe(true);
    expect(node.attestations()).toBe(1);
    expect(info.pubkey).toBe(node.pubkeyHex);
    expect(client.getConfidentialInfo()).toEqual(info);
  });

  test("a failed load is InternalError with executed no and is retried", async () => {
    let failures = 1;
    vi.doMock("../src/confidential-client", async (importOriginal) => {
      if (failures-- > 0) throw new Error("chunk load failed");
      return importOriginal();
    });
    vi.resetModules();
    const { LazyConfidentialClient: Lazy } = await import("../src/lazy-confidential");
    const { InternalError } = await import("../src/errors");
    const node = testNode();
    const client = new Lazy(optionsFor(node));

    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(InternalError);
    expect(err).toMatchObject({ executed: "no" });
    const cause = (err as Error).cause as Error;
    expect(cause).toBeInstanceOf(Error);
    expect(cause.cause).toMatchObject({ message: "chunk load failed" });
    expect(node.requests).toHaveLength(0);
    expect((await client.request(jsonRpcCall())).status).toBe(200);
  });
});
