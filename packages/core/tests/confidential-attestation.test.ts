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
import { AttestationFailed, MalformedAttestationResponse, VerificationError } from "../src/errors";
import type { ConfidentialTransport } from "../src/transport";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const CHAIN_ID = "42161";
const BASE_URL = "https://rpc.example/eth_vrpc";
const NODE_ID = "alpha-vrpc-1";
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
