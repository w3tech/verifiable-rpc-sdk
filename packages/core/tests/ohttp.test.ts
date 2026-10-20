import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { createRecipient } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import appendixA from "../../test-support/vectors/rfc9458-appendix-a.json";
import { decodeInnerResponse, encodeInnerRequest } from "../src/bhttp";
import { InvalidNodeKey, nodeKeyFromEd25519 } from "../src/node-key";
import {
  createSuite,
  type KemChoice,
  OhttpError,
  openResponse,
  type SealedRequest,
  seal,
  sealRequest,
} from "../src/ohttp";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const REQUEST_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RESPONSE_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const KEMS: readonly KemChoice[] = ["js", "native"];

const recipient = createRecipient(SEED);
const nodeKey = nodeKeyFromEd25519(recipient.ed25519PublicKey);

function jsonRpcRequest(): Promise<Uint8Array> {
  return encodeInnerRequest({
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: new TextEncoder().encode(REQUEST_BODY),
  });
}

function encOf(sealed: SealedRequest): string {
  return bytesToHex(sealed.body.subarray(7, 39));
}

async function replyTo(sealed: SealedRequest, body = RESPONSE_BODY): Promise<Uint8Array> {
  const opened = await recipient.openRequest(sealed.body);
  return opened.respond({ status: 200, headers: { "content-type": "application/json" }, body });
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  const [result] = await Promise.allSettled([promise]);
  if (result?.status !== "rejected") throw new Error("expected a rejection");
  return result.reason;
}

function expectTypedError(
  error: unknown,
  type: typeof InvalidNodeKey | typeof OhttpError,
  reason: string,
  secrets: readonly Uint8Array[],
): void {
  expect(error).toBeInstanceOf(type);
  const typed = error as InvalidNodeKey | OhttpError;
  expect(typed.reason).toBe(reason);
  for (const secret of secrets) {
    if (secret.length > 0) expect(typed.message).not.toContain(bytesToHex(secret));
  }
}

describe.each(KEMS)("RFC 9458 Appendix A with the %s KEM", (kem) => {
  test("seals byte-exact and opens the encapsulated response", async () => {
    const suite = createSuite(kem, 0x0001);
    const ekm = {
      privateKey: await suite.kem.importKey("raw", hexToBytes(appendixA.skE).slice().buffer, false),
      publicKey: await suite.kem.importKey("raw", hexToBytes(appendixA.pkE).slice().buffer, true),
    };
    const gatewayKey = hexToBytes(appendixA.keyConfig).subarray(3, 35);

    const sealed = await seal(suite, 1, gatewayKey, hexToBytes(appendixA.request), ekm);

    expect(bytesToHex(sealed.body.subarray(0, 7))).toBe("01002000010001");
    expect(bytesToHex(sealed.body)).toBe(appendixA.encapsulatedRequest);
    const secret = await sealed.opener.context.export(
      new TextEncoder().encode("message/bhttp response"),
      16,
    );
    expect(bytesToHex(new Uint8Array(secret))).toBe(appendixA.secret);
    const response = await openResponse(sealed.opener, hexToBytes(appendixA.encapsulatedResponse));
    expect(bytesToHex(response)).toBe(appendixA.response);
  });
});

describe("sealRequest", () => {
  test("uses the contract header and length, and a fresh encapsulation per seal", async () => {
    const inner = await jsonRpcRequest();
    const first = await sealRequest(nodeKey, inner);
    const second = await sealRequest(nodeKey, inner);

    for (const sealed of [first, second]) {
      expect(bytesToHex(sealed.body.subarray(0, 7))).toBe("00002000010002");
      expect(sealed.body.length).toBe(7 + 32 + inner.length + 16);
    }
    expect(encOf(first)).not.toBe(encOf(second));
    expect(bytesToHex(first.body)).not.toBe(bytesToHex(second.body));
    // @ts-expect-error the opener only exports from its context
    void first.opener.context.seal;
  });

  test("a request without a body round-trips", async () => {
    const sealed = await sealRequest(
      nodeKey,
      await encodeInnerRequest({ method: "GET", path: "/" }),
    );
    const opened = await recipient.openRequest(sealed.body);
    expect(opened.request.method).toBe("GET");
    expect(new URL(opened.request.url).pathname).toBe("/");
    expect(await opened.request.text()).toBe("");

    const reply = await opened.respond({ status: 204 });
    const response = await decodeInnerResponse(await openResponse(sealed.opener, reply));
    expect(response.status).toBe(204);
    expect(response.body.length).toBe(0);
  });

  test("50 concurrent seals stay independent", async () => {
    const inner = await jsonRpcRequest();
    const sealed = await Promise.all(Array.from({ length: 50 }, () => sealRequest(nodeKey, inner)));
    expect(new Set(sealed.map(encOf)).size).toBe(50);

    const replies = await Promise.all(sealed.map((request, i) => replyTo(request, `reply ${i}`)));
    const order = sealed.map((_, i) => i).reverse();
    const opened = await Promise.all(
      order.map(async (i) => {
        const request = sealed[i];
        const reply = replies[i];
        if (request === undefined || reply === undefined) throw new Error("missing request");
        return decodeInnerResponse(await openResponse(request.opener, reply));
      }),
    );
    opened.forEach((response, position) => {
      expect(new TextDecoder().decode(response.body)).toBe(`reply ${order[position]}`);
    });

    const [first, second] = sealed;
    const [firstReply] = replies;
    if (first === undefined || second === undefined || firstReply === undefined) {
      throw new Error("missing request");
    }
    const error = await rejection(openResponse(second.opener, firstReply));
    expectTypedError(error, OhttpError, "open-failed", [firstReply, inner]);
  });
});

describe("openResponse rejects", () => {
  test("a reply with one flipped ciphertext byte", async () => {
    const sealed = await sealRequest(nodeKey, await jsonRpcRequest());
    const reply = await replyTo(sealed);
    const tampered = reply.slice();
    tampered[32] = (tampered[32] ?? 0) ^ 0x01;
    const error = await rejection(openResponse(sealed.opener, tampered));
    expectTypedError(error, OhttpError, "open-failed", [reply, tampered]);
  });

  test("a reply sealed for another request", async () => {
    const inner = await jsonRpcRequest();
    const sealed = await sealRequest(nodeKey, inner);
    const other = await sealRequest(nodeKey, inner);
    const substituted = await replyTo(other);
    const error = await rejection(openResponse(sealed.opener, substituted));
    expectTypedError(error, OhttpError, "open-failed", [substituted, inner]);
  });

  test("a reply shorter than the nonce and tag", async () => {
    const sealed = await sealRequest(nodeKey, await jsonRpcRequest());
    const reply = (await replyTo(sealed)).subarray(0, 47);
    const error = await rejection(openResponse(sealed.opener, reply));
    expectTypedError(error, OhttpError, "response-too-short", [reply]);
  });
});

describe("sealing to an unusable node key", () => {
  const cases = [
    { name: "a small-order X25519 key", key: new Uint8Array(32), reason: "encap-failed" },
    { name: "a 31-byte key", key: nodeKey.slice(0, 31), reason: "malformed" },
  ];

  test.each(cases)("sealRequest rejects $name", async ({ key, reason }) => {
    const inner = await jsonRpcRequest();
    const error = await rejection(sealRequest(key, inner));
    expectTypedError(error, InvalidNodeKey, reason, [key, inner]);
  });

  describe.each(KEMS)("with the %s KEM", (kem) => {
    test.each(cases)("seal rejects $name", async ({ key, reason }) => {
      const inner = await jsonRpcRequest();
      const error = await rejection(seal(createSuite(kem), 0x00, key, inner));
      expectTypedError(error, InvalidNodeKey, reason, [key, inner]);
    });
  });
});
