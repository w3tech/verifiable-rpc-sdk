import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { BHttpDecoder, decodeVli } from "bhttp-ts";
import { describe, expect, test } from "vitest";
import rfc9292 from "../../test-support/vectors/rfc9292-section5.json";
import { encodeInnerRequest, type InnerRequest, InvalidInnerRequest } from "../src/bhttp";

const PINNED_REQUEST =
  "0004504f5354056874747073096c6f63616c686f7374052f3f783d313606616363657074106170706c69636174696f6e2f6a736f6e0c636f6e74656e742d74797065106170706c69636174696f6e2f6a736f6e027b7d00";
const JSON_TYPE = "application/json";
const utf8 = new TextEncoder();

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  const [result] = await Promise.allSettled([promise]);
  if (result?.status !== "rejected") throw new Error("expected a rejection");
  return result.reason;
}

async function encode(request: InnerRequest): Promise<Uint8Array> {
  const bytes = await encodeInnerRequest(request);
  expect(bytes[0]).toBe(0x00);
  return bytes;
}

async function expectRejected(request: InnerRequest, reason: string, secret?: string) {
  const error = await rejection(encodeInnerRequest(request));
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
  ])("rejects method %j", async (method) => {
    await expectRejected({ method, path: "/" }, "method");
  });

  test.each(["PATCH", "patch"])("keeps method %s byte for byte", async (method) => {
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
    ]),
  )("rejects path %s", async (_, path) => {
    await expectRejected({ method: "GET", path }, "path", path);
  });

  test.each(
    labelled(["/", "/x?y=%zz", "/eth?a=1&b=2", `/${"a".repeat(65533)}`]),
  )("keeps path %s unchanged", async (_, path) => {
    const bytes = await encode({ method: "GET", path });
    expect(pathAndQuery(new BHttpDecoder().decodeRequest(bytes))).toBe(path);
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
