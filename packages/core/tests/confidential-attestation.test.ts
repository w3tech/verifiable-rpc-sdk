import { readFileSync } from "node:fs";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AttestationError, type HardwareVerifier } from "@w3tech.io/dstack-verify";
import { describe, expect, test } from "vitest";
import {
  type AttestationContext,
  createTestNode,
  type TestNode,
  type TestOuterResponse,
} from "../../test-support/src/index";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import {
  AttestationFailed,
  AttestationUnavailable,
  MalformedAttestationResponse,
  VerificationError,
} from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const BASE_URL = "https://rpc.example/eth_vrpc";
const NODE_ID = "alpha-vrpc-1";
// Fake key literal, never a real key.
const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const utf8 = new TextEncoder();

interface RejectRow {
  name: string;
  ed25519PublicKey: string;
  reason: string;
}

const keyVectors = JSON.parse(
  readFileSync(
    new URL("../../test-support/vectors/ed25519-to-x25519.json", import.meta.url),
    "utf8",
  ),
) as { reject: RejectRow[] };

const unusableKeys = keyVectors.reject.filter(
  (row) => row.reason === "small-order" || row.reason === "not-torsion-free",
);

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

function testNode(): TestNode {
  return createTestNode({ seed: SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
}

function clientFor(
  transport: ConfidentialTransport,
  overrides: Partial<ConfidentialClientOptions> = {},
): ConfidentialClient {
  return new ConfidentialClient({
    url: BASE_URL,
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

function posts(node: TestNode): number {
  return node.requests.filter((request) => request.method === "POST").length;
}

type Fields = Record<string, unknown>;

/** The standard answer with its JSON body edited. */
async function edited(
  context: AttestationContext,
  edit: (body: Fields & { quote: Fields }) => void,
): Promise<TestOuterResponse> {
  const answer = await context.normal();
  const body = JSON.parse(new TextDecoder().decode(answer.body)) as Fields & { quote: Fields };
  edit(body);
  return { ...answer, body: utf8.encode(JSON.stringify(body)) };
}

function answer(
  status: number,
  body: Uint8Array | string,
  headers: Record<string, string> = {},
): TestOuterResponse {
  return {
    status,
    headers: { "vRPC-NodeId": NODE_ID, ...headers },
    body: typeof body === "string" ? utf8.encode(body) : body,
  };
}

async function withStatus(context: AttestationContext, status: number): Promise<TestOuterResponse> {
  return { ...(await context.normal()), status };
}

function expectUnavailable(err: unknown, reason: string): AttestationUnavailable {
  expect(err).toBeInstanceOf(AttestationUnavailable);
  const unavailable = err as AttestationUnavailable;
  expect(unavailable.reason).toBe(reason);
  expect(unavailable.executed).toBe("no");
  return unavailable;
}

async function expectRecovers(node: TestNode, client: ConfidentialClient): Promise<void> {
  const before = node.attestations();
  node.setAttestation();
  const response = await client.request(jsonRpcCall());
  expect(response.status).toBe(200);
  expect(node.attestations()).toBe(before + 1);
}

function countingVerifier(): HardwareVerifier & { calls: number } {
  const verifier = {
    calls: 0,
    async verifyHardware(): Promise<void> {
      verifier.calls += 1;
    },
  };
  return verifier;
}

describe("ConfidentialClient attestation: attested key", () => {
  test.each([
    ["63 hex characters", (pubkey: string) => pubkey.slice(0, -1)],
    ["no 0x prefix", (pubkey: string) => pubkey.slice(2)],
    ["non-hex characters", () => `0x${"zz".repeat(32)}`],
  ])("a pubkey with %s is MalformedAttestationResponse and nothing is posted", async (_label, shape) => {
    const node = testNode();
    node.setAttestation((context) =>
      edited(context, (body) => {
        body.pubkey = shape(node.pubkeyHex);
      }),
    );
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    expect((err as MalformedAttestationResponse).reason).toBe("pubkey must be 0x + 64 hex chars");
    expect(posts(node)).toBe(0);
  });

  test("an uppercase-hex pubkey is pinned in lowercase and the signed answer is accepted", async () => {
    const node = testNode();
    node.setAttestation((context) =>
      edited(context, (body) => {
        body.pubkey = `0x${node.pubkeyHex.slice(2).toUpperCase()}`;
      }),
    );
    const response = await clientFor(node.transport).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(posts(node)).toBe(1);
  });

  test.each(
    unusableKeys,
  )("an attested $reason key ($name) is rejected before the hardware verifier runs", async ({
    ed25519PublicKey,
  }) => {
    const node = testNode();
    node.setAttestation((context) =>
      edited(context, (body) => {
        body.pubkey = `0x${ed25519PublicKey}`;
        body.quote.report_data = `${ed25519PublicKey}${context.nonceHex}`;
      }),
    );
    const verifier = countingVerifier();
    const err = await rejectionOf(
      clientFor(node.transport, { hardwareVerifier: verifier }).request(jsonRpcCall()),
    );

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    expect((err as MalformedAttestationResponse).reason).toBe(
      "attested pubkey is not a usable encryption key",
    );
    expect((err as Error).cause).toBeUndefined();
    expect(verifier.calls).toBe(0);
    expect(posts(node)).toBe(0);
  });
});

describe("ConfidentialClient attestation: quote verification", () => {
  test("a hardware verifier failure is AttestationFailed, and the next call attests again", async () => {
    const node = testNode();
    const failure = new AttestationError("CHK-P1", "cloud verify request failed (transport error)");
    let failing = true;
    const verifier: HardwareVerifier = {
      async verifyHardware(): Promise<void> {
        if (failing) throw failure;
      },
    };
    const client = clientFor(node.transport, { hardwareVerifier: verifier });
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationFailed);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as AttestationFailed).chkId).toBe("CHK-P1");
    expect((err as Error).cause).toBe(failure);
    expect(posts(node)).toBe(0);

    failing = false;
    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(node.attestations()).toBe(2);
    expect(posts(node)).toBe(1);
  });
});

describe("ConfidentialClient attestation: gateway answers", () => {
  test("a transport failure is AttestationUnavailable carrying the thrown value", async () => {
    const node = testNode();
    const failure = new TypeError("fetch failed");
    let failing = true;
    const transport: ConfidentialTransport = (request) =>
      failing && request.method === "GET" ? Promise.reject(failure) : node.transport(request);
    const client = clientFor(transport);
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(expectUnavailable(err, "transport").cause).toBe(failure);
    expect(posts(node)).toBe(0);

    failing = false;
    await expectRecovers(node, client);
  });

  test("an attestation body over the size cap is AttestationUnavailable", async () => {
    const node = testNode();
    node.setAttestation(() => answer(200, new Uint8Array(201326593)));
    const client = clientFor(node.transport);
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expectUnavailable(err, "transport");
    expect(posts(node)).toBe(0);
    await expectRecovers(node, client);
  });

  test.each([
    [401, { "content-type": "application/json" }, '{"error":"unauthorized"}'],
    [403, { "content-type": "text/plain" }, "forbidden"],
    [404, { "content-type": "text/plain" }, "not found"],
    [429, { "content-type": "text/plain" }, "too many requests"],
    [502, { "content-type": "text/plain" }, "bad gateway"],
    [503, { "content-type": "text/html" }, "<html>unavailable</html>"],
    [302, {}, ""],
    [0, {}, ""],
    [199, {}, ""],
    [300, {}, ""],
  ])("status %i is AttestationUnavailable with that status", async (status, headers, body) => {
    const node = testNode();
    node.setAttestation(() => answer(status, body, headers));
    const client = clientFor(node.transport);
    const err = await rejectionOf(client.request(jsonRpcCall()));

    expect(expectUnavailable(err, "status").status).toBe(status);
    expect(posts(node)).toBe(0);
    await expectRecovers(node, client);
  });

  test("status 299 with a valid body attests", async () => {
    const node = testNode();
    node.setAttestation((context) => withStatus(context, 299));
    const response = await clientFor(node.transport).request(jsonRpcCall());

    expect(response.status).toBe(200);
    expect(posts(node)).toBe(1);
  });

  test("a non-JSON body is MalformedAttestationResponse that never echoes the body", async () => {
    const node = testNode();
    node.setAttestation(() =>
      answer(200, "<html>sentinel-body</html>", { "content-type": "text/html" }),
    );
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    const malformed = err as MalformedAttestationResponse;
    expect(malformed.reason).toBe("response is not valid JSON");
    expect(malformed.cause).toBeUndefined();
    expect(malformed.message).not.toContain("sentinel-body");
    expect(String(malformed)).not.toContain("sentinel-body");
    expect(malformed.stack ?? "").not.toContain("sentinel-body");
    expect(JSON.stringify(malformed)).not.toContain("sentinel-body");
    expect(posts(node)).toBe(0);
  });

  test("an empty 200 body is MalformedAttestationResponse", async () => {
    const node = testNode();
    node.setAttestation(() => answer(200, ""));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    expect((err as MalformedAttestationResponse).reason).toBe("response is not valid JSON");
  });

  test("a JSON body of the wrong shape names the missing field", async () => {
    const node = testNode();
    node.setAttestation(() => answer(200, '{"quote":{}}'));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
    expect((err as MalformedAttestationResponse).reason).toBe("missing field: pubkey");
  });

  test("an empty 500 body is a status error", async () => {
    const node = testNode();
    node.setAttestation(() => answer(500, ""));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(expectUnavailable(err, "status").status).toBe(500);
  });
});

describe("ConfidentialClient attestation: check order", () => {
  test("a 500 carrying a valid attestation is a status error", async () => {
    const node = testNode();
    node.setAttestation((context) => withStatus(context, 500));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(expectUnavailable(err, "status").status).toBe(500);
  });

  test("a 200 without vRPC-NodeId and with a non-JSON body is node-id-missing", async () => {
    const node = testNode();
    node.setAttestation(() => ({ status: 200, headers: {}, body: utf8.encode("not json") }));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expectUnavailable(err, "node-id-missing");
  });

  test("a 200 with vRPC-NodeId and a non-JSON body is MalformedAttestationResponse", async () => {
    const node = testNode();
    node.setAttestation(() => answer(200, "not json"));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(MalformedAttestationResponse);
  });
});

describe("ConfidentialClient attestation: quote binding and compose", () => {
  test("report_data bound to another nonce is AttestationFailed CHK-A1", async () => {
    const node = testNode();
    node.setAttestation((context) =>
      edited(context, (body) => {
        body.quote.report_data = `${node.pubkeyHex.slice(2)}${"0".repeat(64)}`;
      }),
    );
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationFailed);
    expect((err as AttestationFailed).chkId).toBe("CHK-A1");
    expect(posts(node)).toBe(0);
  });

  test("an app_compose that does not hash to composeHash is AttestationFailed CHK-A2", async () => {
    const node = testNode();
    node.setAttestation((context) =>
      edited(context, (body) => {
        body.app_compose = "{}";
        body.composeHash = "deadbeef";
      }),
    );
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationFailed);
    expect((err as AttestationFailed).chkId).toBe("CHK-A2");
    expect(posts(node)).toBe(0);
  });
});

describe("ConfidentialClient attestation: request", () => {
  test("the attestation GET carries the nonce and the caller's headers without content-type", async () => {
    const node = testNode();
    await clientFor(node.transport, {
      headers: { "x-api-key": KEY, "Content-Type": "application/json" },
    }).request(jsonRpcCall());

    const get = node.requests[0];
    expect(get?.method).toBe("GET");
    const url = new URL(get?.url ?? "");
    expect(`${url.origin}${url.pathname}`).toBe(`${BASE_URL}/attestation`);
    expect(url.searchParams.get("nonce")).toMatch(/^[0-9a-f]{64}$/);
    expect(url.search).toBe(`?nonce=${url.searchParams.get("nonce")}`);
    expect(url.searchParams.has("node_id")).toBe(false);
    expect(get?.body).toBeUndefined();
    expect(get?.headers).toEqual({ "x-api-key": KEY });
  });

  test("ten concurrent cold calls share one failed attestation", async () => {
    const node = testNode();
    const client = clientFor(node.transport, {
      hardwareVerifier: mockHardwareVerifier({
        fail: new AttestationError("CHK-P1", "cloud verify request failed (transport error)"),
      }),
    });
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => client.request(jsonRpcCall())),
    );

    for (const result of results) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") expect(result.reason).toBeInstanceOf(AttestationFailed);
    }
    expect(node.attestations()).toBe(1);
    expect(posts(node)).toBe(0);
  });
});
