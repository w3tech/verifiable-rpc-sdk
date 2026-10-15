import { readFileSync } from "node:fs";
import type { SenderContext } from "@hpke/core";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vitest";
import { createRecipient, x25519SecretFromSeed } from "../../test-support/src/index";
import vectors from "../../test-support/vectors/sidecar-confidential.json";
import { decodeInnerResponse, encodeInnerRequest, InvalidInnerRequest } from "../src/bhttp";
import { nodeKeyFromEd25519 } from "../src/node-key";
import { createSuite, OhttpError, openResponse, type ResponseOpener } from "../src/ohttp";

// w3tech/verifiable-rpc-sidecar tests/vectors/confidential.json at commit
// 8c168dc8fd5a911a13aa049cd7d642502257fbcf, sha256 342cb863ddcf741f78a984ebbb28c2672f9c1dc9cc69084e1fba5b8e625b2075.
const VECTORS_SHA256 = "342cb863ddcf741f78a984ebbb28c2672f9c1dc9cc69084e1fba5b8e625b2075";
const VECTORS_FILE = new URL(
  "../../test-support/vectors/sidecar-confidential.json",
  import.meta.url,
);
const HDR = "00002000010002";
const utf8 = new TextEncoder();

type Envelope = (typeof vectors.envelopes)[number];

const [keys] = vectors.key_conversion;
if (keys === undefined) throw new Error("missing key conversion vector");

function contentType(fields: readonly { name: string; value: string }[]): string | undefined {
  return fields.find((field) => field.name === "content-type")?.value;
}

function innerRequest(envelope: Envelope) {
  const type = contentType(envelope.request.fields);
  return {
    method: envelope.request.method,
    path: envelope.request.path,
    ...(type === undefined ? {} : { contentType: type }),
    body: utf8.encode(envelope.request.body),
  };
}

async function opener(envelope: Envelope): Promise<ResponseOpener> {
  const suite = createSuite("js");
  const recipientKey = await suite.kem.importKey("raw", hexToBytes(envelope.skR).buffer, false);
  const context = await suite.createRecipientContext({
    recipientKey,
    enc: hexToBytes(envelope.enc),
    info: hexToBytes(envelope.info),
  });
  return { suite, context: context as unknown as SenderContext, enc: hexToBytes(envelope.enc) };
}

function envelope(name: string): Envelope {
  const found = vectors.envelopes.find((candidate) => candidate.name === name);
  if (found === undefined) throw new Error(`missing envelope ${name}`);
  return found;
}

describe("sidecar known-answer vectors", () => {
  test("the vendored file is byte-identical to the pinned sidecar copy", () => {
    expect(bytesToHex(sha256(readFileSync(VECTORS_FILE)))).toBe(VECTORS_SHA256);
  });

  test("use the contract suite", () => {
    expect(vectors.suite).toEqual({ key_id: 0, kem_id: 0x0020, kdf_id: 0x0001, aead_id: 0x0002 });
    expect(vectors.envelopes.length).toBe(2);
    for (const { hdr, enc, encapsulated_request } of vectors.envelopes) {
      expect(hdr).toBe(HDR);
      expect(encapsulated_request.startsWith(hdr + enc)).toBe(true);
    }
  });

  test("convert the Ed25519 node key", () => {
    expect(bytesToHex(nodeKeyFromEd25519(hexToBytes(keys.ed25519_public_key)))).toBe(keys.pkR);
    expect(bytesToHex(x25519SecretFromSeed(hexToBytes(keys.seed)))).toBe(keys.skR);
    for (const { skR, pkR } of vectors.envelopes) {
      expect(skR).toBe(keys.skR);
      expect(pkR).toBe(keys.pkR);
    }
  });

  test("encode the JSON-RPC request byte for byte", async () => {
    const vector = envelope("post-json-rpc");
    const bytes = await encodeInnerRequest(innerRequest(vector));
    expect(bytesToHex(bytes)).toBe(vector.bhttp_request);
  });

  test("reject the request path the sidecar answers with a bad request", async () => {
    const vector = envelope("inner-error-bad-request");
    expect(vector.outer_status).toBe(400);
    const [result] = await Promise.allSettled([encodeInnerRequest(innerRequest(vector))]);
    expect(result?.status).toBe("rejected");
    const error = (result as PromiseRejectedResult).reason;
    expect(error).toBeInstanceOf(InvalidInnerRequest);
    expect((error as InvalidInnerRequest).reason).toBe("path");
  });

  describe.each(
    vectors.envelopes.map((vector) => [vector.name, vector] as const),
  )("envelope %s", (_, vector) => {
    test("opens at the recipient", async () => {
      const opened = await createRecipient(hexToBytes(keys.seed)).openRequest(
        hexToBytes(vector.encapsulated_request),
      );
      expect(bytesToHex(opened.bhttp)).toBe(vector.bhttp_request);
    });

    test("exports the response secret and opens the response", async () => {
      const responseOpener = await opener(vector);
      const secret = await responseOpener.context.export(utf8.encode("message/bhttp response"), 32);
      expect(bytesToHex(new Uint8Array(secret))).toBe(vector.export_secret);

      const bhttp = await openResponse(responseOpener, hexToBytes(vector.encapsulated_response));
      expect(bytesToHex(bhttp)).toBe(vector.bhttp_response);

      const response = await decodeInnerResponse(bhttp);
      expect(response.status).toBe(vector.response.status);
      expect(response.contentType).toBe(contentType(vector.response.fields) ?? null);
      expect(new TextDecoder().decode(response.body)).toBe(vector.response.body);
    });

    test("rejects a response with a flipped ciphertext byte", async () => {
      const tampered = hexToBytes(vector.encapsulated_response);
      tampered[32] = (tampered[32] ?? 0) ^ 0x01;
      const [result] = await Promise.allSettled([openResponse(await opener(vector), tampered)]);
      expect(result?.status).toBe("rejected");
      const error = (result as PromiseRejectedResult).reason;
      expect(error).toBeInstanceOf(OhttpError);
      expect((error as OhttpError).reason).toBe("open-failed");
    });
  });
});
