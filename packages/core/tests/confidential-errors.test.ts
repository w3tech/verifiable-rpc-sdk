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
  MalformedAttestationResponse,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
  type VrpcError,
} from "../src/errors";
import { OhttpError, sealRequest } from "../src/ohttp";
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
  onPost?: () => OuterResponse | Promise<OuterResponse>;
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

interface Row {
  name: string;
  error: abstract new (...args: never[]) => VrpcError;
  executed: "no" | "unknown";
  /** Absent when the failure happens before any pin exists. */
  pin?: "keep" | "drop";
  posted: boolean;
  verifierFailure?: Error;
  call?: InnerRequest;
  answer?: ConfidentialHandler;
  arrange?(h: Harness): void;
  check?(err: VrpcError): void;
}

const verifierTypeError = new TypeError("verifier bug");

const rows: Row[] = [
  {
    name: "invalid inner request",
    error: InvalidInnerRequest,
    executed: "no",
    pin: "keep",
    posted: false,
    call: { ...jsonRpcCall(), path: "x" },
  },
  {
    name: "attestation transport TypeError",
    error: AttestationUnavailable,
    executed: "no",
    posted: false,
    arrange: (h) => h.node.setAttestation(throwing(new TypeError("fetch failed"))),
  },
  {
    name: "attestation 503",
    error: AttestationUnavailable,
    executed: "no",
    posted: false,
    arrange: (h) => h.node.setAttestation(() => plain(503, "text/plain")),
  },
  {
    name: "attestation body {}",
    error: MalformedAttestationResponse,
    executed: "no",
    posted: false,
    arrange: (h) =>
      h.node.setAttestation(() => ({
        status: 200,
        headers: { "content-type": "application/json", "vRPC-NodeId": NODE_ID },
        body: new TextEncoder().encode("{}"),
      })),
  },
  {
    name: "hardware verifier AttestationError",
    error: AttestationFailed,
    executed: "no",
    posted: false,
    verifierFailure: new AttestationError("CHK-P1", "down"),
  },
  {
    name: "hardware verifier TypeError",
    error: InternalError,
    executed: "no",
    posted: false,
    verifierFailure: verifierTypeError,
    check: (err) => expect(err.cause).toBe(verifierTypeError),
  },
  ...[new OhttpError("seal-failed"), new TypeError("no subtle"), new RangeError("bad length")].map(
    (failure): Row => ({
      name: `seal ${failure.name}`,
      error: InternalError,
      executed: "no",
      pin: "keep",
      posted: false,
      arrange: () => vi.mocked(sealRequest).mockRejectedValueOnce(failure),
      check: (err) => expect(err.cause).toBe(failure),
    }),
  ),
  ...[new TypeError("socket closed"), new RangeError("out of range")].map(
    (failure): Row => ({
      name: `transport ${failure.name}`,
      error: TransportFailed,
      executed: "unknown",
      pin: "keep",
      posted: true,
      arrange: (h) => {
        h.onPost = throwing(failure);
      },
      check: (err) => {
        expect((err as TransportFailed).reason).toBe("network");
        expect(err.cause).toBe(failure);
      },
    }),
  ),
  {
    name: "transport ResponseTooLarge",
    error: TransportFailed,
    executed: "unknown",
    pin: "keep",
    posted: true,
    arrange: (h) => {
      h.onPost = throwing(new ResponseTooLarge());
    },
    check: (err) => expect((err as TransportFailed).reason).toBe("too-large"),
  },
  {
    name: "transport answer without headers",
    error: InternalError,
    executed: "unknown",
    pin: "drop",
    posted: true,
    arrange: (h) => {
      h.onPost = () => ({ status: 200, body: new Uint8Array(0) }) as unknown as OuterResponse;
    },
  },
  ...(
    [
      ["ohttp-key 400", () => fromVector("ohttp-key"), "drop"],
      ["404", () => plain(404, "text/plain"), "drop"],
      ["401", () => plain(401, "application/json"), "drop"],
      ["request-too-large 413", () => fromVector("request-too-large"), "keep"],
      ["429 text/plain", () => plain(429, "text/plain"), "keep"],
    ] as const
  ).map(
    ([name, answer, pin]): Row => ({
      name,
      error: RequestRejected,
      executed: "no",
      pin,
      posted: true,
      answer,
    }),
  ),
  ...(
    [
      ["502 text/plain", () => plain(502, "text/plain")],
      ["500 text/plain", () => plain(500, "text/plain")],
      ["200 text/html", () => plain(200, "text/html")],
      ["302", () => plain(302)],
      ["204", () => plain(204)],
    ] as const
  ).map(
    ([name, answer]): Row => ({
      name,
      error: UnexpectedResponse,
      executed: "unknown",
      pin: "drop",
      posted: true,
      answer,
    }),
  ),
  {
    name: "answer without vRPC-Signature",
    error: MissingHeader,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: edited((answer) => {
      const { "vRPC-Signature": _, ...headers } = answer.headers;
      return { ...answer, headers };
    }),
  },
  {
    name: "vRPC-Timestamp x",
    error: MalformedHeader,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: edited((answer) => ({
      ...answer,
      headers: { ...answer.headers, "vRPC-Timestamp": "x" },
    })),
  },
  {
    name: "body changed after signing",
    error: BadSignature,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: edited((answer) => ({ ...answer, body: flipped(answer.body) })),
  },
  {
    name: "signed 61 s in the past",
    error: StaleTimestamp,
    executed: "unknown",
    pin: "keep",
    posted: true,
    answer: edited((answer, context) => ({
      ...answer,
      headers: {
        ...answer.headers,
        ...context.sign(answer.body, { timestampMs: Date.now() - 61_000 }),
      },
    })),
  },
  {
    name: "signed by another seed",
    error: ConfidentialSignerMismatch,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: edited((answer, context) => ({
      ...answer,
      headers: { ...answer.headers, ...context.sign(answer.body, { seed: TEST_SEED }) },
    })),
  },
  {
    name: "signed corrupted ciphertext",
    error: ConfidentialDecryptFailed,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: edited((answer, context) => signed(context, flipped(answer.body))),
  },
  {
    name: "signed short body",
    error: MalformedConfidentialResponse,
    executed: "unknown",
    pin: "drop",
    posted: true,
    answer: (context) => signed(context, new Uint8Array(4)),
    check: (err) => expect((err as MalformedConfidentialResponse).reason).toBe("too-short"),
  },
];

describe("every failure of request()", () => {
  test.each(rows)("$name", async (row) => {
    const h = harness(row.verifierFailure);
    if (row.pin !== undefined) await h.client.request(jsonRpcCall());
    if (row.answer !== undefined) h.node.setConfidential(row.answer);
    row.arrange?.(h);
    const postsBefore = h.posts;

    const err = await rejectionOf(h.client.request(row.call ?? jsonRpcCall()));
    expect(err).toBeInstanceOf(row.error);
    const failure = err as VrpcError;
    expect(failure.executed).toBe(row.executed);
    expect(h.posts - postsBefore).toBe(row.posted ? 1 : 0);
    row.check?.(failure);
    if (row.pin === undefined) return;

    expect(h.client.getConfidentialInfo() === undefined).toBe(row.pin === "drop");
    const evicted = h.logger.calls.some(([event]) => event === "confidential.evict");
    expect(evicted).toBe(row.pin === "drop");
    delete h.onPost;
    h.node.setConfidential();
    expect((await h.client.request(jsonRpcCall())).status).toBe(200);
    expect(h.node.attestations()).toBe(row.pin === "keep" ? 1 : 2);
  });

  test.each([
    ["before the call", 0, (_h: Harness, abort: () => void) => abort()],
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
  });
});
