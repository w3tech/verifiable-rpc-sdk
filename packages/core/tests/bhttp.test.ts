import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  bhttpField,
  bhttpOkResponse,
  createRecipient,
  NODE_SEED,
  rejectionOf,
} from "@w3tech.io/vrpc-test-support";
import rfc9292 from "@w3tech.io/vrpc-test-support/vectors/rfc9292-section5.json";
import { BHttpDecoder, decodeVli } from "bhttp-ts";
import { describe, expect, test } from "vitest";
import { decodeInnerResponse, encodeInnerRequest, type InnerRequest } from "../src/bhttp";
import { InvalidInnerRequest, MalformedConfidentialResponse } from "../src/errors";
import { nodeKeyFromEd25519 } from "../src/node-session";
import { openResponse, sealRequest } from "../src/ohttp";

const PINNED_REQUEST =
  "0004504f5354056874747073096c6f63616c686f7374052f3f783d313606616363657074106170706c69636174696f6e2f6a736f6e0c636f6e74656e742d74797065106170706c69636174696f6e2f6a736f6e027b7d00";
const JSON_TYPE = "application/json";
const PROCESSING_THEN_OK = "0140660040c80002686900";
const utf8 = new TextEncoder();

async function encode(request: InnerRequest): Promise<Uint8Array> {
  const bytes = await encodeInnerRequest(request);
  expect(bytes[0]).toBe(0x00);
  return bytes;
}

async function expectRejected(request: InnerRequest, reason: string, secret?: string) {
  const error = await rejectionOf(encodeInnerRequest(request));
  expect(error).toBeInstanceOf(InvalidInnerRequest);
  expect((error as InvalidInnerRequest).reason).toBe(reason);
  if (secret !== undefined && secret.length > 1) {
    expect((error as InvalidInnerRequest).message).not.toContain(secret);
  }
}

function labelled(paths: readonly string[]): [string, string][] {
  return paths.map((path) => [
    path.length > 64 ? `${path.length}-byte path` : JSON.stringify(path),
    path,
  ]);
}

function pathAndQuery(request: Request): string {
  const url = new URL(request.url);
  return url.pathname + url.search;
}

describe("encodeInnerRequest", () => {
  test("encodes the contract request shape byte for byte", async () => {
    const bytes = await encode({
      method: "POST",
      path: "/?x=1",
      accept: JSON_TYPE,
      contentType: JSON_TYPE,
      body: utf8.encode("{}"),
    });

    expect(bytesToHex(bytes)).toBe(PINNED_REQUEST);
    const decoded = new BHttpDecoder().decodeRequest(bytes);
    expect(decoded.method).toBe("POST");
    expect(decoded.url).toBe("https://localhost/?x=1");
    expect([...decoded.headers.keys()]).toEqual(["accept", "content-type"]);
    expect(await decoded.text()).toBe("{}");
  });

  test("the RFC 9292 section 5 figures have their published sizes", () => {
    const figures = [
      [rfc9292.figure8KnownLengthRequest, 135, "00034745"],
      [rfc9292.figure9IndeterminateRequest, 144, "02034745"],
      [rfc9292.figure11IndeterminateResponse, 368, "03406607"],
      [rfc9292.figure13KnownLengthResponse, 48, "0140c800"],
    ] as const;
    for (const [hex, length, prefix] of figures) {
      expect(hexToBytes(hex).length).toBe(length);
      expect(hex.startsWith(prefix)).toBe(true);
    }
    const figure8 = new BHttpDecoder().decodeRequest(hexToBytes(rfc9292.figure8KnownLengthRequest));
    expect(figure8.method).toBe("GET");
    expect(pathAndQuery(figure8)).toBe("/hello.txt");
  });

  test.each([
    "",
    "CONNECT",
    "connect",
    "TRACE",
    "TRACK",
    "GE T",
    "GET\r\n",
    "post",
    "Get",
    "delete",
    "patch",
    "Patch",
  ])("rejects method %j", async (method) => {
    await expectRejected({ method, path: "/" }, "method");
  });

  test.each(["PATCH", "purge"])("keeps method %s byte for byte", async (method) => {
    const bytes = await encode({
      method,
      path: "/",
      contentType: JSON_TYPE,
      body: utf8.encode("{}"),
    });
    expect(new BHttpDecoder().decodeRequest(bytes).method).toBe(method);
  });

  test.each(
    labelled([
      "",
      "x",
      "//evil.example/x",
      "/a/../b",
      "/a b",
      "/é",
      "/?q=a b",
      "/a#frag",
      "/a\\b",
      "/%2e%2e/x",
      "@evil.example/x",
      `/${"a".repeat(65534)}`,
      '/x?a="b"',
      "/x?a=<b>",
      "/x?a=é",
      "/x?a=\tb",
      "/x?a#b",
      `/?${"'".repeat(21845)}`,
    ]),
  )("rejects path %s", async (_, path) => {
    await expectRejected({ method: "GET", path }, "path", path);
  });

  test.each(
    labelled(["/", "/x?y=%zz", "/eth?a=1&b=2", "/x?a=[1]|{2}^`\\/..?", `/${"a".repeat(65533)}`]),
  )("keeps path %s unchanged", async (_, path) => {
    const bytes = await encode({ method: "GET", path });
    expect(pathAndQuery(new BHttpDecoder().decodeRequest(bytes))).toBe(path);
  });

  test.each([
    ["/x?", "/x"],
    ["/?a='b'", "/?a=%27b%27"],
  ])("sends path %s as the URL serializer writes it", async (path, sent) => {
    const bytes = await encode({ method: "GET", path });
    expect(pathAndQuery(new BHttpDecoder().decodeRequest(bytes))).toBe(sent);
  });

  test("limits the serialized path to 65534 bytes", async () => {
    const bytes = await encode({ method: "GET", path: `/?${"'".repeat(21844)}` });
    expect(pathAndQuery(new BHttpDecoder().decodeRequest(bytes))).toBe(`/?${"%27".repeat(21844)}`);
  });

  test.each([
    { contentType: "" },
    { contentType: "application/json\r\nx: y" },
    { contentType: " application/json" },
    { contentType: "application/json\t" },
    { accept: "ü" },
    { accept: "a\u0000b" },
  ])("rejects header values %j", async (fields) => {
    const request = { method: "POST", path: "/", contentType: JSON_TYPE, ...fields };
    await expectRejected(
      { ...request, body: utf8.encode("{}") },
      "header",
      fields.contentType ?? fields.accept,
    );
  });

  test("limits the header section to 65536 bytes", async () => {
    // content-type field 1+12+1+16 bytes; accept field 1+6 bytes, a 4-byte length prefix, the value.
    const request = (acceptLength: number): InnerRequest => ({
      method: "POST",
      path: "/",
      contentType: JSON_TYPE,
      accept: "a".repeat(acceptLength),
      body: utf8.encode("{}"),
    });
    await expectRejected(request(65496), "header");

    const bytes = await encode(request(65495));
    expect(decodeVli(bytes, 24)?.value).toBe(65536);
  });

  test.each([
    new Uint8Array(0),
    utf8.encode("{}"),
  ])("rejects a body without content-type", async (body) => {
    await expectRejected({ method: "POST", path: "/", body }, "content-type-required");
  });

  test.each(["GET", "HEAD"])("rejects %s with a body as a method error", async (method) => {
    await expectRejected(
      { method, path: "/", contentType: JSON_TYPE, body: utf8.encode("{}") },
      "method",
    );
  });

  test("a request without a body needs no content-type", async () => {
    const decoded = new BHttpDecoder().decodeRequest(await encode({ method: "GET", path: "/" }));
    expect(decoded.headers.has("content-type")).toBe(false);
    expect(await decoded.text()).toBe("");
  });

  test("concurrent encodes of one request are byte-identical", async () => {
    const request = {
      method: "POST",
      path: "/?x=1",
      accept: JSON_TYPE,
      contentType: JSON_TYPE,
      body: utf8.encode("{}"),
    };
    const [first, second] = await Promise.all([encode(request), encode(request)]);
    expect(first && bytesToHex(first)).toBe(PINNED_REQUEST);
    expect(second && bytesToHex(second)).toBe(PINNED_REQUEST);
  });
});

async function expectMalformed(hex: string, reason: string) {
  const error = await rejectionOf(decodeInnerResponse(hexToBytes(hex)));
  expect(error).toBeInstanceOf(MalformedConfidentialResponse);
  expect((error as MalformedConfidentialResponse).reason).toBe(reason);
}

describe("decodeInnerResponse", () => {
  test("decodes RFC 9292 Figure 13 and drops its trailers", async () => {
    const response = await decodeInnerResponse(hexToBytes(rfc9292.figure13KnownLengthResponse));
    expect(response.status).toBe(200);
    expect(response).not.toHaveProperty("contentType");
    expect(new TextDecoder().decode(response.body)).toBe("This content contains CRLF.\r\n");
  });

  test.each([
    ["empty input", ""],
    ["RFC 9292 Figure 11", rfc9292.figure11IndeterminateResponse],
    ["a two-byte framing indicator", `4001${rfc9292.figure13KnownLengthResponse.slice(2)}`],
    ["RFC 9292 Figure 8", rfc9292.figure8KnownLengthRequest],
  ])("rejects framing of %s", async (_, hex) => {
    await expectMalformed(hex, "framing");
  });

  test.each([
    ["102 then 200", PROCESSING_THEN_OK],
    ["100 alone", "01406400"],
  ])("rejects an informational response: %s", async (_, hex) => {
    await expectMalformed(hex, "informational");
  });

  test.each([
    ["a truncated header section", "0140c8"],
    ["content past the end", "0140c800056869"],
    ["non-zero padding", "0140c8000268690001"],
    ["status 700", "0142bc000000"],
    ["status 0", "0100000000"],
    ["status 99", "014063000000"],
    ["a field name with a space", "0140c8060361206201780000"],
  ])("rejects %s", async (_, hex) => {
    await expectMalformed(hex, "decode-failed");
  });

  test.each([
    ["0140c800", ""],
    ["0140c8000268690000", "hi"],
  ])("decodes %s", async (hex, body) => {
    const response = await decodeInnerResponse(hexToBytes(hex));
    expect(response.status).toBe(200);
    expect(new TextDecoder().decode(response.body)).toBe(body);
  });

  test.each([
    [204, "0140cc0002686900"],
    [205, "0140cd0002686900"],
    [304, "0141300002686900"],
  ])("returns no body for status %i", async (status, hex) => {
    const response = await decodeInnerResponse(hexToBytes(hex));
    expect(response.status).toBe(status);
    expect(response.body.length).toBe(0);
  });

  test.each([
    [["application/json", "text/plain"], "application/json, text/plain"],
    [["text/plain", "application/json"], "text/plain, application/json"],
  ])("keeps repeated content-type lines in order: %j", async (values, joined) => {
    const hex = bhttpOkResponse(
      values.map((value) => bhttpField("content-type", value)),
      "{}",
    );
    const response = await decodeInnerResponse(hexToBytes(hex));
    expect(response.contentType).toBe(joined);
    expect(new TextDecoder().decode(response.body)).toBe("{}");
  });

  test("decodes recipient replies and rejects an informational one", async () => {
    const recipient = createRecipient(NODE_SEED);
    const nodeKey = nodeKeyFromEd25519(recipient.ed25519PublicKey);
    const roundTrip = async (
      reply: (opened: Awaited<ReturnType<typeof recipient.openRequest>>) => Promise<Uint8Array>,
    ) => {
      const sealed = await sealRequest(
        nodeKey,
        await encodeInnerRequest({ method: "GET", path: "/" }),
      );
      const opened = await recipient.openRequest(sealed.body);
      return decodeInnerResponse(await openResponse(sealed.opener, await reply(opened)));
    };

    const noContent = await roundTrip((opened) => opened.respond({ status: 204 }));
    expect(noContent.status).toBe(204);
    expect(noContent.body.length).toBe(0);

    const problem = '{"type":"about:blank","title":"Not Found"}';
    const notFound = await roundTrip((opened) =>
      opened.respond({
        status: 404,
        headers: { "content-type": "application/problem+json" },
        body: problem,
      }),
    );
    expect(notFound.status).toBe(404);
    expect(notFound.contentType).toBe("application/problem+json");
    expect(new TextDecoder().decode(notFound.body)).toBe(problem);

    const error = await rejectionOf(
      roundTrip((opened) => opened.sealResponse(hexToBytes(PROCESSING_THEN_OK))),
    );
    expect(error).toBeInstanceOf(MalformedConfidentialResponse);
    expect((error as MalformedConfidentialResponse).reason).toBe("informational");
  });
});
