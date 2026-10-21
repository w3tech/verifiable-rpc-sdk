import { hexToBytes } from "@noble/hashes/utils.js";
import { AttestationError } from "@w3tech.io/dstack-verify";
import {
  CHAIN_ID,
  type CollectingLogger,
  type ConfidentialContext,
  type ConfidentialHandler,
  collectingLogger,
  createTestNode,
  jsonRpcCall,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  rejectionOf,
  TEST_SEED,
  type TestNode,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import sidecarVectors from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { describe, expect, test, vi } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import {
  AttestationFailed,
  AttestationUnavailable,
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  InternalError,
  InvalidInnerRequest,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
  type VrpcError,
} from "../src/errors";
import { sealRequest } from "../src/ohttp";
import { type OuterResponse, ResponseTooLarge } from "../src/transport";

vi.mock("../src/ohttp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/ohttp")>();
  return { ...actual, sealRequest: vi.fn(actual.sealRequest) };
});

interface Harness {
  node: TestNode;
  client: ConfidentialClient;
  logger: CollectingLogger;
  posts: number;
  onPost?: (() => OuterResponse | Promise<OuterResponse>) | undefined;
}

function harness(verifierFailure?: Error): Harness {
  const node = createTestNode({ seed: NODE_SEED, chainId: CHAIN_ID, nodeId: NODE_ID });
  const logger = collectingLogger();
  const h = { node, logger, posts: 0 } as Harness;
  h.client = new ConfidentialClient({
    url: "https://rpc.example/eth_vrpc",
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(verifierFailure ? { fail: verifierFailure } : {}),
    logger,
    transport: async (request) => {
      if (request.method !== "POST") return node.transport(request);
      h.posts += 1;
      return h.onPost ? h.onPost() : node.transport(request);
    },
  });
  return h;
}

function plain(status: number, contentType?: string, body = new Uint8Array(0)): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body,
  };
}

const vectors = sidecarVectors as {
  pre_decapsulation_errors: { name: string; status: number; content_type?: string; body: string }[];
};

function fromVector(name: string): TestOuterResponse {
  const entry = vectors.pre_decapsulation_errors.find((candidate) => candidate.name === name);
  if (entry === undefined) throw new Error(`missing vector ${name}`);
  return plain(entry.status, entry.content_type, hexToBytes(entry.body));
}

function signed(context: ConfidentialContext, body: Uint8Array): TestOuterResponse {
  return {
    status: 200,
    headers: { "content-type": "message/ohttp-res", ...context.sign(body) },
    body,
  };
}

function edited(
  edit: (answer: TestOuterResponse, context: ConfidentialContext) => TestOuterResponse,
): ConfidentialHandler {
  return async (context) => edit(await context.normal(), context);
}

function resigned(options: Parameters<ConfidentialContext["sign"]>[1]): ConfidentialHandler {
  return edited((a, context) => ({
    ...a,
    headers: { ...a.headers, ...context.sign(a.body, options) },
  }));
}

function flipped(body: Uint8Array): Uint8Array {
  const copy = body.slice();
  copy[40] = (copy[40] ?? 0) ^ 0x01;
  return copy;
}

function throwing(value: unknown): () => never {
  return () => {
    throw value;
  };
}

interface Extra {
  verifierFailure?: Error;
  call?: InnerRequest;
  attestation?: Parameters<TestNode["setAttestation"]>[0];
  seal?: Error;
  onPost?: Harness["onPost"];
  answer?: ConfidentialHandler;
  cause?: unknown;
  reason?: string;
}

interface Row extends Extra {
  name: string;
  error: abstract new (...args: never[]) => VrpcError;
  executed: "no" | "unknown";
  /** "cold": the failure happens before any pin exists. */
  pin: "keep" | "drop" | "cold";
}

function row(
  name: string,
  error: Row["error"],
  executed: Row["executed"],
  pin: Row["pin"],
  extra: Extra = {},
): Row {
  return { name, error, executed, pin, ...extra };
}

const verifierTypeError = new TypeError("verifier bug");
const badCall = { ...jsonRpcCall(), path: "x" };
const emptyJson = { "content-type": "application/json", "vRPC-NodeId": NODE_ID };
const curlyBody = new TextEncoder().encode("{}");

const rows: Row[] = [
  row("invalid inner request", InvalidInnerRequest, "no", "keep", { call: badCall }),
  row("attestation TypeError", AttestationUnavailable, "no", "cold", {
    attestation: throwing(new TypeError("fetch failed")),
  }),
  row("attestation 503", AttestationUnavailable, "no", "cold", {
    attestation: () => plain(503, "text/plain"),
  }),
  row("attestation body {}", AttestationFailed, "no", "cold", {
    attestation: () => ({ status: 200, headers: emptyJson, body: curlyBody }),
  }),
  row("verifier AttestationError", AttestationFailed, "no", "cold", {
    verifierFailure: new AttestationError("CHK-P1", "down"),
  }),
  row("verifier TypeError", AttestationFailed, "no", "cold", {
    verifierFailure: verifierTypeError,
    cause: verifierTypeError,
  }),
  ...[new TypeError("no subtle"), new RangeError("bad length")].map((e) =>
    row(`seal ${e.name}`, InternalError, "no", "keep", { seal: e, cause: e }),
  ),
  row("transport TypeError", TransportFailed, "unknown", "keep", {
    onPost: throwing(new TypeError("fetch failed")),
    reason: "network",
  }),
  row("transport ResponseTooLarge", TransportFailed, "unknown", "keep", {
    onPost: throwing(new ResponseTooLarge()),
    reason: "too-large",
  }),
  row("transport answer without headers", InternalError, "unknown", "drop", {
    onPost: () => ({ status: 200, body: new Uint8Array(0) }) as unknown as OuterResponse,
  }),
  row("404", RequestRejected, "no", "drop", { answer: () => plain(404, "text/plain") }),
  row("413", RequestRejected, "no", "keep", { answer: () => fromVector("request-too-large") }),
  row("429", RequestRejected, "no", "keep", { answer: () => plain(429, "text/plain") }),
  row("502", UnexpectedResponse, "unknown", "drop", { answer: () => plain(502, "text/plain") }),
  row("0", UnexpectedResponse, "unknown", "drop", {
    onPost: () => ({ status: 0, headers: new Headers(), body: new Uint8Array(0) }),
  }),
  row("302 message/ohttp-res", UnexpectedResponse, "unknown", "drop", {
    answer: () => plain(302, "message/ohttp-res"),
  }),
  row("no vRPC-Signature", MissingHeader, "unknown", "drop", {
    answer: edited(({ headers: { "vRPC-Signature": _, ...headers }, ...a }) => ({ ...a, headers })),
  }),
  row("vRPC-Timestamp x", MalformedHeader, "unknown", "drop", {
    answer: edited((a) => ({ ...a, headers: { ...a.headers, "vRPC-Timestamp": "x" } })),
  }),
  row("body changed after signing", BadSignature, "unknown", "drop", {
    answer: edited((a) => ({ ...a, body: flipped(a.body) })),
  }),
  row("signed 61 s ago", StaleTimestamp, "unknown", "keep", {
    answer: resigned({ timestampMs: Date.now() - 61_000 }),
  }),
  row("signed by another seed", ConfidentialSignerMismatch, "unknown", "drop", {
    answer: resigned({ seed: TEST_SEED }),
  }),
  row("signed corrupted ciphertext", ConfidentialDecryptFailed, "unknown", "drop", {
    answer: edited((a, context) => signed(context, flipped(a.body))),
  }),
  row("signed short body", MalformedConfidentialResponse, "unknown", "drop", {
    answer: (context) => signed(context, new Uint8Array(4)),
    reason: "too-short",
  }),
];

describe("every failure of request()", () => {
  test.each(rows)("$name", async (row) => {
    const h = harness(row.verifierFailure);
    if (row.pin !== "cold") await h.client.request(jsonRpcCall());
    if (row.answer !== undefined) h.node.setConfidential(row.answer);
    if (row.attestation !== undefined) h.node.setAttestation(row.attestation);
    if (row.seal !== undefined) vi.mocked(sealRequest).mockRejectedValueOnce(row.seal);
    h.onPost = row.onPost;
    const postsBefore = h.posts;

    const err = await rejectionOf(h.client.request(row.call ?? jsonRpcCall()));
    expect(err).toBeInstanceOf(row.error);
    const failure = err as VrpcError;
    expect(failure.executed).toBe(row.executed);
    const posted = row.executed === "unknown" || failure instanceof RequestRejected;
    expect(h.posts - postsBefore).toBe(posted ? 1 : 0);
    if (row.cause !== undefined) expect(failure.cause).toBe(row.cause);
    if (row.reason !== undefined) expect(failure).toHaveProperty("reason", row.reason);
    if (row.pin === "cold") return;

    expect(h.client.getConfidentialInfo() === undefined).toBe(row.pin === "drop");
    const evicted = h.logger.calls.some(([event]) => event === "confidential.evict");
    expect(evicted).toBe(row.pin === "drop");
    h.onPost = undefined;
    h.node.setConfidential();
    expect((await h.client.request(jsonRpcCall())).status).toBe(200);
    expect(h.node.attestations()).toBe(row.pin === "keep" ? 1 : 2);
  });

  test.each([
    [
      "while sealing",
      0,
      (_h: Harness, abort: () => void) =>
        vi.mocked(sealRequest).mockImplementationOnce(async (key, bhttp) => {
          abort();
          const actual = await vi.importActual<typeof import("../src/ohttp")>("../src/ohttp");
          return actual.sealRequest(key, bhttp);
        }),
    ],
    [
      "during the POST",
      1,
      (h: Harness, abort: () => void) => {
        h.onPost = () => {
          abort();
          return new Promise<OuterResponse>(() => {});
        };
      },
    ],
  ])("an abort %s rejects with the reason itself and keeps the pin", async (_label, posted, arrange) => {
    const h = harness();
    await h.client.request(jsonRpcCall());
    const controller = new AbortController();
    const reason = new Error("caller gave up");
    arrange(h, () => controller.abort(reason));
    const postsBefore = h.posts;

    const err = await rejectionOf(h.client.request(jsonRpcCall(), { signal: controller.signal }));
    expect(err).toBe(reason);
    expect("executed" in reason).toBe(false);
    expect(h.posts - postsBefore).toBe(posted);
    expect(h.client.getConfidentialInfo()).toBeDefined();
    h.onPost = undefined;
    expect((await h.client.request(jsonRpcCall())).status).toBe(200);
    expect(h.node.attestations()).toBe(1);
  });
});
