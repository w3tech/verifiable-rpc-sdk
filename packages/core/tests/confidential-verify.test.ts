import { hexToBytes } from "@noble/hashes/utils.js";
import {
  bhttpField,
  bhttpOkResponse,
  type ConfidentialContext,
  createTestNode,
  jsonRpcCall,
  rejectionOf,
  TEST_SEED,
  type TestOuterResponse,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import vectors from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { describe, expect, expectTypeOf, test } from "vitest";
import type { ConfidentialClientOptions } from "../src/confidential-client";
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
import { clientFor, signed } from "./support/confidential";

const OHTTP_RES = { "content-type": "message/ohttp-res" };
const text = new TextDecoder();

function setup(upstream?: () => TestUpstreamResponse) {
  const node = createTestNode({ upstream });
  return { node, client: clientFor(node.transport) };
}

type Answer = (context: ConfidentialContext) => TestOuterResponse | Promise<TestOuterResponse>;

async function failedCallAfterWarmup(answer: Answer): Promise<unknown> {
  const { node, client } = setup();
  await client.request(jsonRpcCall());
  node.setConfidential(answer);
  const err = await rejectionOf(client.request(jsonRpcCall()));
  expect(err).toBeInstanceOf(VerificationError);
  return err;
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

describe("signed confidential answers that fail verification", () => {
  test("an answer signed by another node key is ConfidentialSignerMismatch", async () => {
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      return {
        ...normal,
        headers: { ...normal.headers, ...context.sign(normal.body, { seed: TEST_SEED }) },
      };
    });
    expect(err).toBeInstanceOf(ConfidentialSignerMismatch);
  });

  test("the key that verified the signature is compared with the pin", async () => {
    const { node } = setup();
    const err = await failedCallAfterWarmup(async (context) => {
      const normal = await context.normal();
      const { "vRPC-Pubkey": otherPubkey, ...otherHeaders } = context.sign(normal.body, {
        seed: TEST_SEED,
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
      const headers = context.sign(normal.body, { seed: TEST_SEED, pubkeyHex: node.pubkeyHex });
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
            bhttpOkResponse(
              [
                bhttpField("content-type", "application/json"),
                bhttpField("content-type", "text/plain"),
              ],
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
      | "fetch"
      | "transport"
    >();
  });
});
