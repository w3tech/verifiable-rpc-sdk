import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test, vi } from "vitest";
import { createTestNode } from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import { MalformedAttestationResponse } from "../src/errors";
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
  test("a failure inside the crypto layer is rethrown unchanged and drops the pin", async () => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    const failure = new OhttpError("seal-failed");
    vi.mocked(sealRequest).mockRejectedValueOnce(failure);

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBe(failure);

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });

  test.each([
    "malformed",
    "small-order",
    "not-torsion-free",
  ] as const)("a node key rejected while sealing (%s) is MalformedAttestationResponse and drops the pin", async (reason) => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    vi.mocked(sealRequest).mockRejectedValueOnce(new InvalidNodeKey(reason));

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    expect((err as MalformedAttestationResponse).reason).toBe(
      "attested pubkey is not a usable encryption key",
    );

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });

  test("an encapsulation failure is rethrown unchanged with its cause and drops the pin", async () => {
    const { node, client } = setup();
    await client.request(jsonRpcCall());
    const cause = new Error("platform crypto failure");
    const failure = new InvalidNodeKey("encap-failed", { cause });
    vi.mocked(sealRequest).mockRejectedValueOnce(failure);

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBe(failure);
    expect((err as InvalidNodeKey).cause).toBe(cause);

    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });
});
