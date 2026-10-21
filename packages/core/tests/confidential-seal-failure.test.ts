import {
  CHAIN_ID,
  createTestNode,
  jsonRpcCall,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test, vi } from "vitest";
import { ConfidentialClient } from "../src/confidential-client";
import { InternalError, UnavailableError } from "../src/errors";
import { InvalidNodeKey } from "../src/node-key";
import { OhttpError, sealRequest } from "../src/ohttp";

vi.mock("../src/ohttp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/ohttp")>();
  return { ...actual, sealRequest: vi.fn(actual.sealRequest) };
});

function setup() {
  const node = createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
  const client = new ConfidentialClient({
    url: "https://rpc.example/eth_vrpc",
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport: node.transport,
  });
  return { node, client };
}

describe("sealing failures", () => {
  test.each([
    ["OhttpError seal-failed", new OhttpError("seal-failed")],
    ["InvalidNodeKey malformed", new InvalidNodeKey("malformed")],
    ["InvalidNodeKey encap-failed", new InvalidNodeKey("encap-failed")],
    ["a platform TypeError", new TypeError("crypto.subtle unavailable")],
  ])("%s while sealing is InternalError with that cause, nothing is sent and the pin is dropped", async (_label, failure) => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    vi.mocked(sealRequest).mockRejectedValueOnce(failure);

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBeInstanceOf(InternalError);
    expect(err).toBeInstanceOf(UnavailableError);
    const sealFailed = err as InternalError;
    expect(sealFailed.kind).toBe("InternalError");
    expect(sealFailed.executed).toBe("no");
    expect(sealFailed.cause).toBe(failure);
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(1);
    expect(client.getConfidentialInfo()).toBeUndefined();

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });

  test("an abort while sealing rejects with the reason, sends nothing and keeps the pin", async () => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    const controller = new AbortController();
    const reason = new Error("caller gave up");
    vi.mocked(sealRequest).mockImplementationOnce(async (key, bhttp) => {
      controller.abort(reason);
      return (await vi.importActual<typeof import("../src/ohttp")>("../src/ohttp")).sealRequest(
        key,
        bhttp,
      );
    });

    const err = await rejectionOf(client.request(jsonRpcCall(), { signal: controller.signal }));
    expect(err).toBe(reason);
    expect("executed" in reason).toBe(false);
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(1);
    expect(client.getConfidentialInfo()).toBeDefined();
  });
});
