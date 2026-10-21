import {
  CHAIN_ID,
  createTestNode,
  jsonRpcCall,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  type TestNodeOptions,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import { AttestationUnavailable, RequestRejected } from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";

const KEYED_URL = "https://rpc.example/eth_vrpc/0123456789abcdefghijABCDEFGHIJkl";

const T0 = 1_800_000_000_000;

function testNode(overrides: Partial<TestNodeOptions> = {}) {
  return createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID, ...overrides });
}

function clientFor(
  transport: ConfidentialTransport,
  overrides: Partial<ConfidentialClientOptions> = {},
): ConfidentialClient {
  return new ConfidentialClient({
    url: KEYED_URL,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport,
    ...overrides,
  });
}

function posts(node: ReturnType<typeof testNode>): number {
  return node.requests.filter((request) => request.method === "POST").length;
}

function plain(status: number, contentType?: string): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body: new Uint8Array(0),
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ready and getConfidentialInfo", () => {
  test("a cold client has no info; ready attests once and returns the pinned node", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    expect(client.getConfidentialInfo()).toBeUndefined();

    const before = Date.now();
    const info = await client.ready();
    const after = Date.now();

    expect(info).toEqual({
      nodeId: NODE_ID,
      pubkey: node.pubkeyHex,
      composeHash: "deadbeef",
      attestedAt: info.attestedAt,
    });
    expect(Object.keys(info).sort()).toEqual(["attestedAt", "composeHash", "nodeId", "pubkey"]);
    expect(info.pubkey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(typeof info.attestedAt).toBe("number");
    expect(info.attestedAt).toBeGreaterThanOrEqual(before);
    expect(info.attestedAt).toBeLessThanOrEqual(after);
    expect(node.attestations()).toBe(1);
  });

  test("a second ready and a following request reuse the pin", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    const first = await client.ready();
    const second = await client.ready();

    expect(second).toEqual(first);
    expect(client.getConfidentialInfo()).toEqual(first);
    expect(node.attestations()).toBe(1);

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(1);
    expect(node.requests.filter((request) => request.method === "GET")).toHaveLength(1);
  });
});

describe("single flight", () => {
  test("50 concurrent cold calls share one attestation", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    const responses = await Promise.all(
      Array.from({ length: 50 }, () => client.request(jsonRpcCall())),
    );

    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(50);
    expect(responses.every((response) => response.status === 200)).toBe(true);
  });

  test("a failed shared attestation rejects every caller with one error and is not kept", async () => {
    const node = testNode();
    node.setAttestation(() => plain(503, "text/plain"));
    const client = clientFor(node.transport);
    const results = await Promise.allSettled(
      Array.from({ length: 50 }, () => client.request(jsonRpcCall())),
    );

    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(0);
    const reasons = results.map((result) => {
      expect(result.status).toBe("rejected");
      return (result as PromiseRejectedResult).reason as unknown;
    });
    const first = reasons[0];
    expect(first).toBeInstanceOf(AttestationUnavailable);
    expect((first as AttestationUnavailable).status).toBe(503);
    for (const reason of reasons) expect(reason).toBe(first);
    expect(client.getConfidentialInfo()).toBeUndefined();

    node.setAttestation();
    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(node.attestations()).toBe(2);
  });
});

describe("pin lifetime", () => {
  test("a pin lives pubkeyCacheTtlMs from its attestation", async () => {
    vi.useFakeTimers({ now: T0 });
    const node = testNode();
    const client = clientFor(node.transport, { pubkeyCacheTtlMs: 1000 });
    const { attestedAt } = await client.ready();

    vi.setSystemTime(attestedAt + 999);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);

    vi.setSystemTime(attestedAt + 1000);
    expect(client.getConfidentialInfo()).toBeUndefined();
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
    expect(client.getConfidentialInfo()?.attestedAt).toBe(attestedAt + 1000);
  });

  test("without the option a pin lives one hour", async () => {
    vi.useFakeTimers({ now: T0 });
    const node = testNode();
    const client = clientFor(node.transport);
    const { attestedAt } = await client.ready();

    vi.setSystemTime(attestedAt + 3_599_999);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);

    vi.setSystemTime(attestedAt + 3_600_000);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });
});

describe("eviction", () => {
  test("a late failure on an older pin keeps the fresh pin", async () => {
    vi.useFakeTimers({ now: T0 });
    const node = testNode();
    const client = clientFor(node.transport);
    await client.ready();

    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let calls = 0;
    node.setConfidential(async (context) => {
      calls += 1;
      if (calls === 1) {
        entered.resolve();
        await release.promise;
        return plain(404, "text/plain");
      }
      if (calls === 2) return plain(404, "text/plain");
      return context.normal();
    });

    const a = client.request(jsonRpcCall());
    a.catch(() => {});
    await entered.promise;

    await expect(client.request(jsonRpcCall())).rejects.toBeInstanceOf(RequestRejected);
    expect(client.getConfidentialInfo()).toBeUndefined();

    vi.setSystemTime(T0 + 5000);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);

    release.resolve();
    await expect(a).rejects.toBeInstanceOf(RequestRejected);
    expect(client.getConfidentialInfo()?.attestedAt).toBe(T0 + 5000);

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });

  test("re-attesting the same node id yields a new pin", async () => {
    vi.useFakeTimers({ now: T0 });
    const node = testNode();
    const client = clientFor(node.transport);
    const first = await client.ready();

    node.setConfidential(() => plain(404, "text/plain"));
    await expect(client.request(jsonRpcCall())).rejects.toBeInstanceOf(RequestRejected);
    node.setConfidential();

    vi.setSystemTime(T0 + 5000);
    await client.request(jsonRpcCall());
    const second = client.getConfidentialInfo();
    expect(node.attestations()).toBe(2);
    expect(second?.nodeId).toBe(first.nodeId);
    expect(second?.attestedAt).toBe(T0 + 5000);
  });

  test("an inner 500 keeps the pin", async () => {
    const node = testNode({ upstream: () => ({ status: 500, body: "boom" }) });
    const client = clientFor(node.transport);
    await client.ready();

    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(500);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);
    expect(client.getConfidentialInfo()).toBeDefined();
  });
});
