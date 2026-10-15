import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vitest";
import { createTestNode } from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import {
  RequestRejected,
  UnavailableError,
  UnexpectedResponse,
  VerificationError,
} from "../src/errors";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const NODE_ID = "alpha-vrpc-1";
const utf8 = new TextEncoder();

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

function setup(upstream?: Parameters<typeof createTestNode>[0]["upstream"]) {
  const node = createTestNode({
    seed: SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    ...(upstream === undefined ? {} : { upstream }),
  });
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

describe("confidential answer classification", () => {
  test("gateway rate limit 429 text/plain is RequestRejected and the next call attests again", async () => {
    const { node, client } = setup();
    node.setConfidential(() => ({
      status: 429,
      headers: { "content-type": "text/plain" },
      body: utf8.encode("message: rate limited"),
    }));

    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(RequestRejected);
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err).not.toBeInstanceOf(VerificationError);
    const rejected = err as RequestRejected;
    expect(rejected.kind).toBe("RequestRejected");
    expect(rejected.status).toBe(429);
    expect(rejected.executed).toBe("no");
    expect(rejected.contentType).toBe("text/plain");
    expect(rejected.nodeId).toBe(NODE_ID);

    node.setConfidential();
    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(node.attestations()).toBe(2);
    expect(node.requests.map((request) => request.method)).toEqual(["GET", "POST", "GET", "POST"]);
  });

  test("an inner 500 is returned and keeps the pin", async () => {
    const { node, client } = setup(() => ({ status: 500, body: "boom" }));

    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(500);
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(1);
  });

  test("gateway 502 text/plain is UnexpectedResponse and the next call attests again", async () => {
    const { node, client } = setup();
    node.setConfidential(() => ({
      status: 502,
      headers: { "content-type": "text/plain" },
      body: utf8.encode("upstream down"),
    }));

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect((err as UnexpectedResponse).executed).toBe("unknown");

    node.setConfidential();
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });
});
