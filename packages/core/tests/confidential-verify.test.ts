import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  type ConfidentialContext,
  createTestNode,
  mockHardwareVerifier,
  type TestOuterResponse,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import vectors from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { describe, expect, expectTypeOf, test } from "vitest";
import { type InnerRequest, MalformedInnerResponse } from "../src/bhttp";
import { ConfidentialClient, type ConfidentialClientOptions } from "../src/confidential-client";
import {
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "../src/errors";
import { InvalidNodeKey } from "../src/node-key";
import { OhttpError } from "../src/ohttp";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const OTHER_SEED = new Uint8Array(32).fill(0x42);
const CHAIN_ID = "42161";
const NODE_ID = "alpha-vrpc-1";
const OHTTP_RES = { "content-type": "message/ohttp-res" };
const utf8 = new TextEncoder();
const text = new TextDecoder();

function jsonRpcCall(): InnerRequest {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}

function setup(upstream?: () => TestUpstreamResponse) {
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

function expectPublicFamily(err: unknown): void {
  expect(err).toBeInstanceOf(VerificationError);
  expect(err).not.toBeInstanceOf(OhttpError);
  expect(err).not.toBeInstanceOf(MalformedInnerResponse);
  expect(err).not.toBeInstanceOf(InvalidNodeKey);
  expect(["OhttpError", "MalformedInnerResponse", "InvalidNodeKey"]).not.toContain(
    (err as VerificationError).kind,
  );
}

type Answer = (context: ConfidentialContext) => TestOuterResponse | Promise<TestOuterResponse>;

async function failedCallAfterWarmup(answer: Answer): Promise<unknown> {
  const { node, client } = setup();
  await client.request(jsonRpcCall());
  node.setConfidential(answer);
  const err = await rejectionOf(client.request(jsonRpcCall()));
  node.setConfidential();
  await client.request(jsonRpcCall());
  expect(node.attestations()).toBe(2);
  expectPublicFamily(err);
  return err;
}

function signed(context: ConfidentialContext, body: Uint8Array): TestOuterResponse {
  return { status: 200, headers: { ...OHTTP_RES, ...context.sign(body) }, body };
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function vli(length: number): string {
  return length < 64 ? length.toString(16).padStart(2, "0") : (0x4000 | length).toString(16);
}

function field(name: string, value: string): string {
  return (
    vli(name.length) +
    bytesToHex(utf8.encode(name)) +
    vli(value.length) +
    bytesToHex(utf8.encode(value))
  );
}

function okResponse(fields: string[], body: string): string {
  const section = fields.join("");
  const content = bytesToHex(utf8.encode(body));
  return `0140c8${vli(section.length / 2)}${section}${vli(content.length / 2)}${content}00`;
}

describe("signed confidential answers that fail verification", () => {
  test("an answer signed by another node key is ConfidentialSignerMismatch", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      return {
        ...normal,
        headers: { ...normal.headers, ...context.sign(normal.body, { seed: OTHER_SEED }) },
      };
    });
    expect(err).toBeInstanceOf(ConfidentialSignerMismatch);
  });

  test("the key that verified the signature is compared with the pin", async () => {
    const { node } = setup();
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      const { "vRPC-Pubkey": otherPubkey, ...otherHeaders } = context.sign(normal.body, {
        seed: OTHER_SEED,
      });
      const stored = new Headers({ ...OHTTP_RES, ...otherHeaders });
      // The pinned key is shown until verification reads the signature.
      let signatureRead = false;
      const headers = {
        get(name: string): string | null {
          const lower = name.toLowerCase();
          if (lower === "vrpc-signature") signatureRead = true;
          if (lower !== "vrpc-pubkey") return stored.get(name);
          return signatureRead ? (otherPubkey ?? null) : node.pubkeyHex;
        },
      } as unknown as Record<string, string>;
      return { ...normal, headers };
    });
    expect(err).toBeInstanceOf(ConfidentialSignerMismatch);
    expect((err as ConfidentialSignerMismatch).actualPubkey).not.toBe(node.pubkeyHex);
  });

  test("another key's signature under the pinned vRPC-Pubkey is BadSignature", async () => {
    const { node } = setup();
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      const headers = context.sign(normal.body, { seed: OTHER_SEED, pubkeyHex: node.pubkeyHex });
      return { ...normal, headers: { ...normal.headers, ...headers } };
    });
    expect(err).toBeInstanceOf(BadSignature);
  });

  test("a ciphertext byte flipped after signing is BadSignature", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      const body = normal.body.slice();
      body[40] = (body[40] ?? 0) ^ 0x01;
      return { ...normal, body };
    });
    expect(err).toBeInstanceOf(BadSignature);
  });

  test("a body cut short after signing is BadSignature", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      return { ...normal, body: normal.body.slice(0, normal.body.length - 16) };
    });
    expect(err).toBeInstanceOf(BadSignature);
  });

  test("an answer recorded for another request is BadSignature", async () => {
    const { node, client } = setup();
    let recorded: TestOuterResponse | undefined;
    node.setConfidential(async (context) => {
      recorded = await context.normal();
      return recorded;
    });
    await client.request(jsonRpcCall());
    node.setConfidential(() => {
      if (recorded === undefined) throw new Error("nothing recorded");
      return recorded;
    });

    const err = await rejectionOf(client.request(jsonRpcCall()));
    expect(err).toBeInstanceOf(BadSignature);
    expectPublicFamily(err);

    node.setConfidential();
    await client.request(jsonRpcCall());
    expect(node.attestations()).toBe(2);
  });

  test("a signature timestamp outside the replay window is StaleTimestamp", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      const headers = context.sign(normal.body, { timestampMs: Date.now() - 61_000 });
      return { ...normal, headers: { ...normal.headers, ...headers } };
    });
    expect(err).toBeInstanceOf(StaleTimestamp);
  });

  test("an answer without vRPC headers is MissingHeader", async () => {
    const err = await failedCallAfterWarmup(async (context) => ({
      ...(await context.normal()),
      headers: { ...OHTTP_RES },
    }));
    expect(err).toBeInstanceOf(MissingHeader);
  });

  test("a non-decimal vRPC-Timestamp is MalformedHeader", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      return { ...normal, headers: { ...normal.headers, "vRPC-Timestamp": "12a" } };
    });
    expect(err).toBeInstanceOf(MalformedHeader);
  });

  test("a signed body of 47 bytes is MalformedConfidentialResponse too-short", async () => {
    const err = await failedCallAfterWarmup((context) => signed(context, random(47)));
    expect(err).toBeInstanceOf(MalformedConfidentialResponse);
    expect((err as MalformedConfidentialResponse).reason).toBe("too-short");
  });

  test("a signed body that does not open is ConfidentialDecryptFailed", async () => {
    const err = await failedCallAfterWarmup((context) => signed(context, random(32 + 64)));
    expect(err).toBeInstanceOf(ConfidentialDecryptFailed);
    expect((err as ConfidentialDecryptFailed).kind).toBe("ConfidentialDecryptFailed");
  });

  test.each([
    ["0040c800", "framing"],
    ["0140660040c80002686900", "informational"],
    ["0140c8", "decode-failed"],
  ])("sealed inner bytes %s are MalformedConfidentialResponse %s", async (hex, reason) => {
    const err = await failedCallAfterWarmup(async (context) =>
      signed(context, await context.seal(hexToBytes(hex))),
    );
    expect(err).toBeInstanceOf(MalformedConfidentialResponse);
    expect((err as MalformedConfidentialResponse).reason).toBe(reason);
  });
});

describe("delivered inner responses", () => {
  test("any inner status is returned and keeps the pin", async () => {
    const envelope = vectors.envelopes[1]?.response;
    if (envelope === undefined) throw new Error("missing envelope vector");
    const envelopeContentType = envelope.fields.find((entry) => entry.name === "content-type");
    let next: TestUpstreamResponse = { status: 200 };
    const { node, client } = setup(() => next);
    const outerStatuses: number[] = [];
    node.setConfidential(async (context) => {
      const normal = await context.normal();
      outerStatuses.push(normal.status);
      return normal;
    });

    next = {
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"jsonrpc":"2.0","id":1,"result":"0x10"}',
    };
    const ok = await client.request(jsonRpcCall());
    expect(ok.status).toBe(200);
    expect(ok.contentType).toBe("application/json");

    next = {
      status: envelope.status,
      headers: { "content-type": envelopeContentType?.value ?? "" },
      body: envelope.body,
    };
    const badRequest = await client.request(jsonRpcCall());
    expect(badRequest.status).toBe(400);
    expect(badRequest.contentType).toBe("application/problem+json");
    expect(text.decode(badRequest.body)).toBe(envelope.body);

    next = { status: 404, headers: { "content-type": "text/plain" }, body: "not found" };
    const notFound = await client.request(jsonRpcCall());
    expect(notFound.status).toBe(404);
    expect(notFound.contentType).toBe("text/plain");

    next = { status: 500, headers: { "content-type": "application/json" }, body: "{}" };
    expect((await client.request(jsonRpcCall())).status).toBe(500);

    next = { status: 204 };
    const noContent = await client.request(jsonRpcCall());
    expect(noContent.status).toBe(204);
    expect(noContent.body.length).toBe(0);
    expect("contentType" in noContent).toBe(false);

    expect(outerStatuses).toEqual([200, 400, 404, 500, 200]);

    node.setConfidential(async (context) =>
      signed(
        context,
        await context.seal(
          hexToBytes(
            okResponse(
              [field("content-type", "application/json"), field("content-type", "text/plain")],
              "{}",
            ),
          ),
        ),
      ),
    );
    const twoLines = await client.request(jsonRpcCall());
    expect(twoLines.status).toBe(200);
    expect(twoLines.contentType).toBe("application/json, text/plain");

    expect(node.attestations()).toBe(1);
  });
});

describe("client options", () => {
  test("no option can relax the signature, pin or replay-window check", () => {
    expectTypeOf<keyof ConfidentialClientOptions>().toEqualTypeOf<
      | "url"
      | "chainId"
      | "headers"
      | "replayWindowMs"
      | "pubkeyCacheTtlMs"
      | "logger"
      | "hardwareVerifier"
      | "transport"
    >();
  });
});
