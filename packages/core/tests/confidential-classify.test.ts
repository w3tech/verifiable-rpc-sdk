import { hexToBytes } from "@noble/hashes/utils.js";
import {
  CHAIN_ID,
  type ConfidentialContext,
  createTestNode,
  jsonRpcCall,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import sidecarVectors from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { describe, expect, test } from "vitest";
import { ConfidentialClient } from "../src/confidential-client";
import {
  MissingHeader,
  RequestRejected,
  TransportFailed,
  UnavailableError,
  UnexpectedResponse,
} from "../src/errors";

const utf8 = new TextEncoder();
const EMPTY = new Uint8Array(0);

interface PreDecapsulationError {
  name: string;
  status: number;
  content_type?: string;
  body: string;
}

const vectors = sidecarVectors as { pre_decapsulation_errors: PreDecapsulationError[] };

function vector(name: string): PreDecapsulationError {
  const entry = vectors.pre_decapsulation_errors.find((candidate) => candidate.name === name);
  if (entry === undefined) throw new Error(`missing vector ${name}`);
  return entry;
}

function plain(status: number, contentType?: string, body: Uint8Array = EMPTY): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body,
  };
}

function fromVector(name: string): TestOuterResponse {
  const entry = vector(name);
  return plain(entry.status, entry.content_type, hexToBytes(entry.body));
}

async function withContentType(
  context: ConfidentialContext,
  contentType: string,
  status?: number,
): Promise<TestOuterResponse> {
  const normal = await context.normal();
  return {
    status: status ?? normal.status,
    headers: { ...normal.headers, "content-type": contentType },
    body: normal.body,
  };
}

function setup(upstream?: Parameters<typeof createTestNode>[0]["upstream"]) {
  const node = createTestNode({
    seed: NODE_SEED,
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

type Answer = (context: ConfidentialContext) => TestOuterResponse | Promise<TestOuterResponse>;

interface Row {
  title: string;
  answer: Answer;
  status: number;
  contentType?: string;
}

async function failedCallAfterWarmup(answer: Answer) {
  const { node, client } = setup();
  await client.request(jsonRpcCall());
  node.setConfidential(answer);
  const posts = node.requests.filter((request) => request.method === "POST").length;
  const err = await rejectionOf(client.request(jsonRpcCall()));
  expect(node.requests.filter((request) => request.method === "POST").length).toBe(posts + 1);
  return err;
}

function expectReported(err: RequestRejected | UnexpectedResponse, row: Row): void {
  expect(err.status).toBe(row.status);
  expect(err.nodeId).toBe(NODE_ID);
  if (row.contentType === undefined) {
    expect("contentType" in err).toBe(false);
  } else {
    expect(err.contentType).toBe(row.contentType);
  }
  expect("body" in err).toBe(false);
}

const rejectedRows: Row[] = [
  {
    title: "node rejected the key configuration 400",
    answer: () => fromVector("ohttp-key"),
    status: 400,
    contentType: "application/problem+json",
  },
  {
    title: "node request too large 413",
    answer: () => fromVector("request-too-large"),
    status: 413,
  },
  {
    title: "node method not allowed 405",
    answer: () => fromVector("method-not-allowed"),
    status: 405,
  },
  ...[400, 403, 404, 413, 429].map((status) => ({
    title: `gateway ${status} text/plain`,
    answer: () => plain(status, "text/plain", utf8.encode("message: refused")),
    status,
    contentType: "text/plain",
  })),
  {
    title: "gateway API key 401 application/json",
    answer: () => plain(401, "application/json", utf8.encode('{"error":"unauthorized"}')),
    status: 401,
    contentType: "application/json",
  },
  ...[413, 429].map((status) => ({
    title: `edge proxy ${status} text/html`,
    answer: () => plain(status, "text/html", utf8.encode("<html></html>")),
    status,
    contentType: "text/html",
  })),
  {
    title: "older node signed 404 with no content-type and an empty body",
    answer: (context: ConfidentialContext) => ({
      status: 404,
      headers: context.sign(EMPTY),
      body: EMPTY,
    }),
    status: 404,
  },
  { title: "400 with no content-type header", answer: () => plain(400), status: 400 },
];

const unexpectedRows: Row[] = [
  { title: "node plaintext 500 with an empty body", answer: () => plain(500), status: 500 },
  ...[500, 502].map((status) => ({
    title: `gateway ${status} text/plain`,
    answer: () => plain(status, "text/plain", utf8.encode("message: failed")),
    status,
    contentType: "text/plain",
  })),
  ...[502, 503, 504].map((status) => ({
    title: `edge proxy ${status} text/html`,
    answer: () => plain(status, "text/html", utf8.encode("<html></html>")),
    status,
    contentType: "text/html",
  })),
  {
    title: "redirect 302 text/html",
    answer: () => plain(302, "text/html"),
    status: 302,
    contentType: "text/html",
  },
  {
    title: "captive page 200 text/html",
    answer: () => plain(200, "text/html", utf8.encode("<html></html>")),
    status: 200,
    contentType: "text/html",
  },
  ...[0, 99, 101, 600, 204].map((status) => ({
    title: `status ${status} with no body`,
    answer: () => plain(status),
    status,
  })),
  ...[205, 304].map((status) => ({
    title: `signed message/ohttp-res under status ${status}`,
    answer: async (context: ConfidentialContext) => ({ ...(await context.normal()), status }),
    status,
    contentType: "message/ohttp-res",
  })),
  {
    title: "valid sealed answer under application/octet-stream",
    answer: (context: ConfidentialContext) =>
      withContentType(context, "application/octet-stream", 200),
    status: 200,
    contentType: "application/octet-stream",
  },
  ...["message/ohttp-resx", "message/ohttp-req", "message/ohttp-res-foo"].map((contentType) => ({
    title: `look-alike ${contentType} under status 200`,
    answer: (context: ConfidentialContext) => withContentType(context, contentType, 200),
    status: 200,
    contentType,
  })),
];

const neverDecryptedRejectedRows: Row[] = [
  {
    title: "valid sealed answer under text/plain with status 429",
    answer: (context: ConfidentialContext) => withContentType(context, "text/plain", 429),
    status: 429,
    contentType: "text/plain",
  },
  ...["message/ohttp-resx", "message/ohttp-req", "message/ohttp-res-foo"].map((contentType) => ({
    title: `look-alike ${contentType} under status 404`,
    answer: (context: ConfidentialContext) => withContentType(context, contentType, 404),
    status: 404,
    contentType,
  })),
];

describe("answers that are not encrypted responses", () => {
  test("the vendored pre_decapsulation_errors are all covered", () => {
    expect(vectors.pre_decapsulation_errors.map((entry) => entry.name).sort()).toEqual([
      "method-not-allowed",
      "ohttp-key",
      "request-too-large",
    ]);
  });

  test.each([
    ...rejectedRows,
    ...neverDecryptedRejectedRows,
  ])("$title is RequestRejected", async (row) => {
    const err = await failedCallAfterWarmup(row.answer);
    expect(err).toBeInstanceOf(RequestRejected);
    expect((err as RequestRejected).executed).toBe("no");
    expectReported(err as RequestRejected, row);
  });

  test.each(unexpectedRows)("$title is UnexpectedResponse", async (row) => {
    const err = await failedCallAfterWarmup(row.answer);
    expect(err).toBeInstanceOf(UnexpectedResponse);
    expect((err as UnexpectedResponse).executed).toBe("unknown");
    expectReported(err as UnexpectedResponse, row);
  });

  test("the ohttp-key answer is reported without its body", async () => {
    const err = (await failedCallAfterWarmup(() => fromVector("ohttp-key"))) as RequestRejected;
    expect(Object.values(err).some((value) => value instanceof Uint8Array)).toBe(false);
  });
});

describe("content-type matching", () => {
  test.each([
    "Message/OHTTP-Res; charset=binary",
    " message/ohttp-res ",
  ])("%j is accepted and decrypted", async (contentType) => {
    const { node, client } = setup();
    node.setConfidential((context) => withContentType(context, contentType));
    const response = await client.request(jsonRpcCall());
    expect(response.status).toBe(200);
    expect(response.contentType).toBe("application/json");
  });
});

describe("transport failures", () => {
  test("a throwing transport is TransportFailed network", async () => {
    const err = await failedCallAfterWarmup(() => {
      throw new TypeError("fetch failed");
    });

    expect(err).toBeInstanceOf(TransportFailed);
    expect(err).toBeInstanceOf(UnavailableError);
    const failed = err as TransportFailed;
    expect(failed.kind).toBe("TransportFailed");
    expect(failed.reason).toBe("network");
    expect(failed.executed).toBe("unknown");
    expect(failed.nodeId).toBe(NODE_ID);
  });

  test("a body of 201326593 bytes is TransportFailed too-large", async () => {
    const err = await failedCallAfterWarmup(() => ({
      status: 200,
      headers: { "content-type": "message/ohttp-res" },
      body: new Uint8Array(201326593),
    }));

    expect(err).toBeInstanceOf(TransportFailed);
    expect((err as TransportFailed).reason).toBe("too-large");
    expect((err as TransportFailed).executed).toBe("unknown");
    expect("cause" in (err as TransportFailed)).toBe(false);
  });

  test("a body of exactly 201326592 bytes goes on to verification", async () => {
    const err = await failedCallAfterWarmup(() => ({
      status: 200,
      headers: { "content-type": "message/ohttp-res" },
      body: new Uint8Array(201326592),
    }));

    expect(err).toBeInstanceOf(MissingHeader);
  });
});
