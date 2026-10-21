import type { CipherSuite } from "@hpke/core";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { createRecipient, hideX25519, NODE_SEED } from "@w3tech.io/vrpc-test-support";
import libsodium from "@w3tech.io/vrpc-test-support/vectors/ed25519-to-x25519.json";
import cfrg from "@w3tech.io/vrpc-test-support/vectors/hpke-cfrg-mode0-x25519-sha256-aes256gcm.json";
import rfc9292 from "@w3tech.io/vrpc-test-support/vectors/rfc9292-section5.json";
import appendixA from "@w3tech.io/vrpc-test-support/vectors/rfc9458-appendix-a.json";
import sidecar from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { decodeInnerResponse, encodeInnerRequest, MalformedInnerResponse } from "../src/bhttp";
import { nodeKeyFromEd25519 } from "../src/node-session";
import {
  createSuite,
  nativeX25519Works,
  openResponse,
  type ResponseOpener,
  seal,
  sealRequest,
  selectKem,
} from "../src/ohttp";

const REQUEST_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RESPONSE_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const utf8 = new TextEncoder();

interface CfrgOutput {
  enc: string;
  ciphertexts: string[];
}

async function runCfrgSender(suite: CipherSuite): Promise<CfrgOutput> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(hexToBytes(cfrg.pkRm));
  const context = await suite.createSenderContext({
    recipientPublicKey,
    info: hexToBytes(cfrg.info),
    ekm: hexToBytes(cfrg.ikmE),
  });
  const ciphertexts: string[] = [];
  for (const encryption of cfrg.encryptions) {
    const ct = await context.seal(hexToBytes(encryption.pt), hexToBytes(encryption.aad));
    ciphertexts.push(bytesToHex(new Uint8Array(ct)));
  }
  return { enc: bytesToHex(new Uint8Array(context.enc)), ciphertexts };
}

function sidecarEnvelope(name: string): (typeof sidecar.envelopes)[number] {
  const found = sidecar.envelopes.find((candidate) => candidate.name === name);
  if (found === undefined) throw new Error(`missing envelope ${name}`);
  return found;
}

describe("in a browser without WebCrypto X25519", () => {
  let restore: (() => void) | undefined;

  beforeAll(() => {
    restore = hideX25519();
  });

  afterAll(() => {
    restore?.();
  });

  test("runs in Chrome with no process global", () => {
    expect(typeof (globalThis as { process?: unknown }).process).toBe("undefined");
    expect(navigator.userAgent).toContain("Chrome");
  });

  test("the probe fails and selection falls back to JS", async () => {
    expect(await nativeX25519Works()).toBe(false);
    expect(await selectKem()).toBe("js");
  });

  test("the JS KEM reproduces the CFRG HPKE vector", async () => {
    expect(await runCfrgSender(createSuite("js"))).toEqual({
      enc: cfrg.enc,
      ciphertexts: cfrg.encryptions.map((encryption) => encryption.ct),
    });
  });

  test("RFC 9458 Appendix A seals byte-exact and opens the encapsulated response", async () => {
    const suite = createSuite("js", 0x0001);
    const ekm = {
      privateKey: await suite.kem.importKey("raw", hexToBytes(appendixA.skE).slice().buffer, false),
      publicKey: await suite.kem.importKey("raw", hexToBytes(appendixA.pkE).slice().buffer, true),
    };
    const gatewayKey = hexToBytes(appendixA.keyConfig).subarray(3, 35);

    const sealed = await seal(suite, 1, gatewayKey, hexToBytes(appendixA.request), ekm);

    expect(bytesToHex(sealed.body)).toBe(appendixA.encapsulatedRequest);
    const secret = await sealed.opener.context.export(utf8.encode("message/bhttp response"), 16);
    expect(bytesToHex(new Uint8Array(secret))).toBe(appendixA.secret);
    const response = await openResponse(sealed.opener, hexToBytes(appendixA.encapsulatedResponse));
    expect(bytesToHex(response)).toBe(appendixA.response);
  });

  test("converts the libsodium vector key", () => {
    const nodeKey = nodeKeyFromEd25519(hexToBytes(libsodium.ed25519PublicKey));
    expect(bytesToHex(nodeKey)).toBe(libsodium.x25519PublicKey);
  });

  test("decodes RFC 9292 Figure 13 and rejects Figure 11", async () => {
    const response = await decodeInnerResponse(hexToBytes(rfc9292.figure13KnownLengthResponse));
    expect(response.status).toBe(200);
    expect(response).not.toHaveProperty("contentType");
    expect(new TextDecoder().decode(response.body)).toBe("This content contains CRLF.\r\n");

    const [result] = await Promise.allSettled([
      decodeInnerResponse(hexToBytes(rfc9292.figure11IndeterminateResponse)),
    ]);
    expect(result?.status).toBe("rejected");
    const error = (result as PromiseRejectedResult).reason;
    expect(error).toBeInstanceOf(MalformedInnerResponse);
    expect((error as MalformedInnerResponse).reason).toBe("framing");
  });

  test("the sidecar post-json-rpc vector encodes and its response opens and decodes", async () => {
    const vector = sidecarEnvelope("post-json-rpc");
    const bytes = await encodeInnerRequest({
      method: vector.request.method,
      path: vector.request.path,
      contentType: "application/json",
      body: utf8.encode(vector.request.body),
    });
    expect(bytesToHex(bytes)).toBe(vector.bhttp_request);

    const suite = createSuite("js");
    const recipientKey = await suite.kem.importKey("raw", hexToBytes(vector.skR).buffer, false);
    const context = await suite.createRecipientContext({
      recipientKey,
      enc: hexToBytes(vector.enc),
      info: hexToBytes(vector.info),
    });
    const opener: ResponseOpener = { suite, context, enc: hexToBytes(vector.enc) };
    const secret = await opener.context.export(utf8.encode("message/bhttp response"), 32);
    expect(bytesToHex(new Uint8Array(secret))).toBe(vector.export_secret);

    const bhttp = await openResponse(opener, hexToBytes(vector.encapsulated_response));
    expect(bytesToHex(bhttp)).toBe(vector.bhttp_response);
    const response = await decodeInnerResponse(bhttp);
    expect(response.status).toBe(vector.response.status);
    expect(response.contentType).toBe("application/json");
    expect(new TextDecoder().decode(response.body)).toBe(vector.response.body);
  });

  test("a sealed JSON-RPC POST opens at the recipient and its sealed reply decodes", async () => {
    const recipient = createRecipient(NODE_SEED);
    const nodeKey = nodeKeyFromEd25519(recipient.ed25519PublicKey);
    const inner = await encodeInnerRequest({
      method: "POST",
      path: "/",
      contentType: "application/json",
      accept: "application/json",
      body: utf8.encode(REQUEST_BODY),
    });

    const sealed = await sealRequest(nodeKey, inner);
    const opened = await recipient.openRequest(sealed.body);

    expect(bytesToHex(opened.hdr)).toBe("00002000010002");
    expect(sealed.body.length).toBe(7 + 32 + inner.length + 16);
    expect(opened.request.method).toBe("POST");
    expect(new URL(opened.request.url).pathname).toBe("/");
    expect(opened.request.headers.get("content-type")).toBe("application/json");
    expect(await opened.request.text()).toBe(REQUEST_BODY);

    const reply = await opened.respond({
      status: 200,
      headers: { "content-type": "application/json" },
      body: RESPONSE_BODY,
    });
    const response = await decodeInnerResponse(await openResponse(sealed.opener, reply));

    expect(response.status).toBe(200);
    expect(response.contentType).toBe("application/json");
    expect(new TextDecoder().decode(response.body)).toBe(RESPONSE_BODY);
  });
});

describe("in a browser with WebCrypto X25519", () => {
  test("selection picks native X25519", async () => {
    expect(await selectKem()).toBe("native");
  });

  test("the native KEM produces the same CFRG bytes as the JS KEM", async () => {
    const js = await runCfrgSender(createSuite("js"));
    const native = await runCfrgSender(createSuite("native"));
    expect(js.enc).toBe(cfrg.enc);
    expect(native).toEqual(js);
  });
});
