import { AttestationError, type HardwareVerifier } from "@w3tech.io/dstack-verify";
import {
  type AttestationContext,
  CHAIN_ID,
  createTestNode,
  jsonRpcCall,
  KEY,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
  type TestNode,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import ed25519ToX25519 from "@w3tech.io/vrpc-test-support/vectors/ed25519-to-x25519.json";
import { describe, expect, test } from "vitest";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import { AttestationFailed, AttestationUnavailable } from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";

const BASE_URL = "https://rpc.example/eth_vrpc";
const utf8 = new TextEncoder();

interface RejectRow {
  name: string;
  ed25519PublicKey: string;
  reason: string;
}

const keyVectors = ed25519ToX25519 as { reject: RejectRow[] };

const unusableKeys = keyVectors.reject.filter(
  (row) => row.reason === "small-order" || row.reason === "not-torsion-free",
);

function testNode(): TestNode {
  return createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
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
  )("an attested $reason key ($name) is rejected after the quote verifies", async ({
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

    expect(err).toBeInstanceOf(AttestationFailed);
    expect((err as AttestationFailed).detail).toBe(
      "attested pubkey is not a usable encryption key",
    );
    expect((err as Error).cause).toBeUndefined();
    expect(verifier.calls).toBe(1);
    expect(posts(node)).toBe(0);
  });
});

describe("ConfidentialClient attestation: gateway answers", () => {
  test.each([0, 199])("status %i is AttestationUnavailable with that status", async (status) => {
    const node = testNode();
    node.setAttestation(() => answer(status, ""));
    const err = await rejectionOf(clientFor(node.transport).request(jsonRpcCall()));

    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toMatchObject({ reason: "status", status, executed: "no" });
    expect(posts(node)).toBe(0);
  });
});

describe("ConfidentialClient attestation: quote binding and compose", () => {
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

  test("ready and request waiting on one failed attestation reject with the same error, not executed", async () => {
    const node = testNode();
    const client = clientFor(node.transport, {
      hardwareVerifier: mockHardwareVerifier({ fail: new AttestationError("CHK-P1", "down") }),
    });
    const [ready, call] = await Promise.all([
      rejectionOf(client.ready()),
      rejectionOf(client.request(jsonRpcCall())),
    ]);

    expect(call).toBeInstanceOf(AttestationFailed);
    expect(ready).toBe(call);
    expect((call as AttestationFailed).executed).toBe("no");
    expect(node.attestations()).toBe(1);
  });
});
