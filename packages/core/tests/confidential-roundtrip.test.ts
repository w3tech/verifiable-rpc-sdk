import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { createRecipient } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import { decodeInnerResponse, encodeInnerRequest } from "../src/bhttp";
import { nodeKeyFromEd25519 } from "../src/node-key";
import { openResponse, sealRequest } from "../src/ohttp";

const SEED = hexToBytes("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
const REQUEST_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';
const RESPONSE_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';

describe("confidential request round trip", () => {
  test("a sealed JSON-RPC POST opens at the recipient and its sealed reply decodes", async () => {
    const recipient = createRecipient(SEED);
    const nodeKey = nodeKeyFromEd25519(recipient.ed25519PublicKey);
    const inner = await encodeInnerRequest({
      method: "POST",
      path: "/",
      contentType: "application/json",
      accept: "application/json",
      body: new TextEncoder().encode(REQUEST_BODY),
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
