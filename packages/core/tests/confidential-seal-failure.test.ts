import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test, vi } from "vitest";
import { createTestNode } from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import { ConfidentialSealFailed, UnavailableError } from "../src/errors";
import { InvalidNodeKey } from "../src/node-key";
import { OhttpError, sealRequest } from "../src/ohttp";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

vi.mock("../src/ohttp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/ohttp")>();
  return { ...actual, sealRequest: vi.fn(actual.sealRequest) };
});

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: new TextEncoder().encode(
      '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}',
    ),
  };
}

function setup() {
  const node = createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: "alpha-vrpc-1" });
  const client = new ConfidentialClient({
    url: "https://rpc.example/eth_vrpc",
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport: node.transport,
  });
  return { node, client };
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the promise to reject");
}

describe("sealing failures", () => {
  test.each([
    ["OhttpError seal-failed", new OhttpError("seal-failed")],
    ["InvalidNodeKey malformed", new InvalidNodeKey("malformed")],
    ["InvalidNodeKey encap-failed", new InvalidNodeKey("encap-failed")],
    ["a platform TypeError", new TypeError("crypto.subtle unavailable")],
  ])("%s while sealing is ConfidentialSealFailed with that cause, nothing is sent and the pin is dropped", async (_label, failure) => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    vi.mocked(sealRequest).mockRejectedValueOnce(failure);

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBeInstanceOf(ConfidentialSealFailed);
    expect(err).toBeInstanceOf(UnavailableError);
    const sealFailed = err as ConfidentialSealFailed;
    expect(sealFailed.kind).toBe("ConfidentialSealFailed");
    expect(sealFailed.executed).toBe("no");
    expect(sealFailed.cause).toBe(failure);
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(1);
    expect(client.getConfidentialInfo()).toBeUndefined();

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });
});
