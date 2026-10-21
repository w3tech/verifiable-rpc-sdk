import { getEventListeners } from "node:events";
import {
  CHAIN_ID,
  createTestNode,
  jsonRpcCall,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
  type TestOuterRequest,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import { AttestationUnavailable } from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";

const KEYED_URL = "https://rpc.example/eth_vrpc/0123456789abcdefghijABCDEFGHIJkl";

function testNode() {
  return createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
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

function plain(status: number): TestOuterResponse {
  return { status, headers: { "content-type": "text/plain" }, body: new Uint8Array(0) };
}

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  vi.useRealTimers();
});

function recordProcessEvent(event: "warning" | "unhandledRejection"): unknown[] {
  const seen: unknown[] = [];
  const listener = (value: unknown) => {
    seen.push(value);
  };
  process.on(event, listener);
  cleanups.push(() => {
    process.off(event, listener);
  });
  return seen;
}

describe("cancellation", () => {
  test("a signal aborted before the call rejects with its reason and sends nothing", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    const reason = new Error("stop");
    const controller = new AbortController();
    controller.abort(reason);

    expect(await rejectionOf(client.request(jsonRpcCall(), { signal: controller.signal }))).toBe(
      reason,
    );
    expect(await rejectionOf(client.ready({ signal: controller.signal }))).toBe(reason);
    expect(node.requests).toHaveLength(0);
  });

  test("an abort while waiting for a shared attestation leaves the other waiters and the attestation alone", async () => {
    const node = testNode();
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    node.setAttestation(async (context) => {
      entered.resolve();
      await release.promise;
      return context.normal();
    });
    const client = clientFor(node.transport);
    const controller = new AbortController();
    const reason = new Error("caller A left");

    const a = rejectionOf(client.request(jsonRpcCall(), { signal: controller.signal }));
    const b = client.request(jsonRpcCall());
    const c = client.ready();
    await entered.promise;
    controller.abort(reason);
    expect(await a).toBe(reason);

    release.resolve();
    expect((await b).status).toBe(200);
    expect((await c).nodeId).toBe(NODE_ID);
    expect(node.attestations()).toBe(1);
  });

  test("ready rejects with the reason when aborted during the attestation", async () => {
    const node = testNode();
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    node.setAttestation(async (context) => {
      entered.resolve();
      await release.promise;
      return context.normal();
    });
    const client = clientFor(node.transport);
    const controller = new AbortController();
    const reason = new Error("not now");

    const pending = rejectionOf(client.ready({ signal: controller.signal }));
    await entered.promise;
    controller.abort(reason);
    expect(await pending).toBe(reason);

    release.resolve();
    await client.ready();
    expect(node.attestations()).toBe(1);
  });

  test("AbortSignal.timeout rejects with a TimeoutError", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    await client.ready();
    node.setConfidential(async (context) => {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      return context.normal();
    });

    const err = await rejectionOf(
      client.request(jsonRpcCall(), { signal: AbortSignal.timeout(50) }),
    );
    expect((err as Error).name).toBe("TimeoutError");
  });

  test("a stuck attestation ends after 60 s even when the transport ignores its signal", async () => {
    vi.useFakeTimers({ now: 1_800_000_000_000 });
    const node = testNode();
    let stall = true;
    const stalled: TestOuterRequest[] = [];
    const transport: ConfidentialTransport = (request) => {
      if (stall && request.method === "GET") {
        stalled.push(request);
        return new Promise(() => {});
      }
      return node.transport(request);
    };
    const client = clientFor(transport);
    const controller = new AbortController();

    const pending = rejectionOf(client.request(jsonRpcCall(), { signal: controller.signal }));
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(59_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);

    const err = await pending;
    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect((err as AttestationUnavailable).reason).toBe("timeout");
    expect(stalled).toHaveLength(1);
    expect(stalled[0]?.signal).toBeDefined();
    expect(stalled[0]?.signal).not.toBe(controller.signal);

    stall = false;
    expect((await client.request(jsonRpcCall())).status).toBe(200);
    expect(node.attestations()).toBe(1);
  });

  test("a shared attestation failing after every waiter left is handled and not kept", async () => {
    const unhandled = recordProcessEvent("unhandledRejection");
    const node = testNode();
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    node.setAttestation(async () => {
      entered.resolve();
      await release.promise;
      return plain(503);
    });
    const client = clientFor(node.transport);
    const first = new AbortController();
    const second = new AbortController();

    const a = rejectionOf(client.request(jsonRpcCall(), { signal: first.signal }));
    const b = rejectionOf(client.request(jsonRpcCall(), { signal: second.signal }));
    await entered.promise;
    first.abort(new Error("a"));
    second.abort(new Error("b"));
    await a;
    await b;

    release.resolve();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(unhandled).toEqual([]);

    node.setAttestation();
    expect((await client.request(jsonRpcCall())).status).toBe(200);
    expect(node.attestations()).toBe(2);
  });

  test("50 cold calls sharing one signal print no warning and leave no abort listener", async () => {
    const warnings = recordProcessEvent("warning");
    const node = testNode();
    // The client's own listeners are under test, not the in-test transport's.
    const transport: ConfidentialTransport = ({ signal: _signal, ...request }) =>
      node.transport(request);
    const client = clientFor(transport);
    const controller = new AbortController();

    const responses = await Promise.all(
      Array.from({ length: 50 }, () =>
        client.request(jsonRpcCall(), { signal: controller.signal }),
      ),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(responses).toHaveLength(50);
    expect(node.attestations()).toBe(1);
    expect(warnings).toEqual([]);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
});
