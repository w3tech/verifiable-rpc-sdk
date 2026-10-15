import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vitest";
import { createTestNode, type TestNodeOptions } from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import {
  AttestationUnavailable,
  ConfidentialSignerMismatch,
  UnavailableError,
  UnexpectedResponse,
  VerificationError,
} from "../src/errors";
import { buildPreImage } from "../src/preimage";
import type { ConfidentialTransport } from "../src/transport";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const OTHER_SEED = new Uint8Array(32).fill(0x42);
const CHAIN_ID = "42161";
const BASE_URL = "https://rpc.example/eth_vrpc";
// Fake key literal, never a real key.
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const KEYED_URL = `${BASE_URL}/${KEY}`;
const NODE_ID = "alpha-vrpc-1";
const utf8 = new TextEncoder();
const JSON_RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const DEFAULT_UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode(JSON_RPC_BODY),
  };
}

function testNode(overrides: Partial<TestNodeOptions> = {}) {
  return createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID, ...overrides });
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

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the promise to reject");
}

describe("ConfidentialClient", () => {
  test("a JSON-RPC call returns the upstream's status, content-type and body", async () => {
    const node = testNode();
    const response = await clientFor(node.transport).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(response.contentType).toBe("application/json");
    expect(new TextDecoder().decode(response.body)).toBe(DEFAULT_UPSTREAM_BODY);
  });

  test("the first call attests then posts ciphertext; the second call only posts", async () => {
    const node = testNode();
    const client = clientFor(node.transport);
    await client.request(jsonRpcCall());

    expect(node.requests).toHaveLength(2);
    const [attestation, call] = node.requests;
    expect(attestation?.method).toBe("GET");
    expect(attestation?.url.startsWith(`${KEYED_URL}/attestation?nonce=`)).toBe(true);
    expect(attestation?.url.slice(`${KEYED_URL}/attestation?nonce=`.length)).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(attestation?.url).not.toContain("node_id");
    expect(attestation?.body).toBeUndefined();

    expect(call?.method).toBe("POST");
    expect(call?.url).toBe(`${KEYED_URL}/confidential?node_id=${NODE_ID}`);
    expect(call?.headers).toEqual({ "content-type": "message/ohttp-req" });
    expect(bytesToHex(call?.body ?? new Uint8Array(0)).startsWith("00002000010002")).toBe(true);

    await client.request(jsonRpcCall());
    expect(node.requests).toHaveLength(3);
    expect(node.requests[2]?.method).toBe("POST");
    expect(node.attestations()).toBe(1);
  });

  test.each([
    ["absent", null],
    ["empty", ""],
  ])("a %s vRPC-NodeId on the attestation answer is AttestationUnavailable and nothing is posted", async (_label, nodeId) => {
    const node = testNode({ nodeId });
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err).not.toBeInstanceOf(VerificationError);
    const unavailable = err as AttestationUnavailable;
    expect(unavailable.kind).toBe("AttestationUnavailable");
    expect(unavailable.reason).toBe("node-id-missing");
    expect(unavailable.executed).toBe("no");
    expect(node.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  test("a plain-text gateway answer is UnexpectedResponse and is never opened", async () => {
    const node = testNode();
    const transport: ConfidentialTransport = async (request) =>
      request.method === "POST"
        ? {
            status: 502,
            headers: { "content-type": "text/plain" },
            body: utf8.encode("upstream down"),
          }
        : node.transport(request);
    const err = await rejectionOf(clientFor(transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect(err).toBeInstanceOf(UnavailableError);
    const unexpected = err as UnexpectedResponse;
    expect(unexpected.kind).toBe("UnexpectedResponse");
    expect(unexpected.status).toBe(502);
    expect(unexpected.contentType).toBe("text/plain");
    expect(unexpected.executed).toBe("unknown");
    expect(unexpected.nodeId).toBe(NODE_ID);
  });

  test("a sealed answer signed by another key is ConfidentialSignerMismatch", async () => {
    const node = testNode();
    const otherPubkey = `0x${bytesToHex(await getPublicKeyAsync(OTHER_SEED))}`;
    const transport: ConfidentialTransport = async (request) => {
      const response = await node.transport(request);
      if (request.method !== "POST" || request.body === undefined) return response;
      const timestamp = BigInt(Date.now());
      const signature = await signAsync(
        buildPreImage(CHAIN_ID, request.body, response.body, timestamp),
        OTHER_SEED,
      );
      return {
        status: response.status,
        headers: {
          "content-type": "message/ohttp-res",
          "vRPC-Signature": `0x${bytesToHex(signature)}`,
          "vRPC-Timestamp": timestamp.toString(),
          "vRPC-Pubkey": otherPubkey,
          "vRPC-NodeId": NODE_ID,
        },
        body: response.body,
      };
    };
    const err = await rejectionOf(clientFor(transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(ConfidentialSignerMismatch);
    expect(err).toBeInstanceOf(VerificationError);
    const mismatch = err as ConfidentialSignerMismatch;
    expect(mismatch.kind).toBe("ConfidentialSignerMismatch");
    expect(mismatch.expectedPubkey).toBe(node.pubkeyHex);
    expect(mismatch.actualPubkey).toBe(otherPubkey);
  });
});
