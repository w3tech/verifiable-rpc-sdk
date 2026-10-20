import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { AttestationError } from "@w3tech.io/dstack-verify";
import {
  CHAIN_ID,
  type CollectingLogger,
  collectingLogger,
  createTestNode,
  mockHardwareVerifier,
  NODE_ID,
  NODE_SEED,
  type TestNode,
  type TestOuterResponse,
  x25519SecretFromSeed,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { InnerRequest } from "../src/bhttp";
import { ConfidentialClient } from "../src/confidential-client";
import {
  AttestationFailed,
  AttestationUnavailable,
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  InvalidInnerRequest,
  MalformedAttestationResponse,
  MalformedConfidentialResponse,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
} from "../src/errors";
import type { Logger } from "../src/logger";
import type { ConfidentialTransport } from "../src/transport";

const OTHER_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BASE_URL = "https://rpc.example/eth_vrpc";
const API_KEY = "Sentinelkey0123456789abcdefghijk";
const INNER_PATH = "/sentinel-path?q=sentinel-query";
const INNER_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":["sentinel-plaintext"]}';
const UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"sentinel-reply"}';
const SAFE_FIELDS = new Set([
  "nodeId",
  "pubkey",
  "composeHash",
  "durationMs",
  "kind",
  "requestBytes",
  "status",
  "contentType",
  "responseBytes",
]);
const EVENTS = [
  "confidential.attest.start",
  "confidential.attest.ok",
  "confidential.attest.fail",
  "confidential.request",
  "confidential.response",
  "confidential.evict",
];
const CONSOLE_METHODS = ["log", "info", "warn", "error", "debug"] as const;
const utf8 = new TextEncoder();

type ErrorClass = abstract new (...args: never[]) => Error;

interface Scenario {
  name: string;
  expected?: ErrorClass;
  inner?: InnerRequest;
  failPost?: boolean;
  hardwareFail?: boolean;
  arrange?(node: TestNode): void;
}

interface Capture {
  sentinels: Set<string>;
  errors: unknown[];
}

function call(path = INNER_PATH): InnerRequest {
  return {
    method: "POST",
    path,
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode(INNER_BODY),
  };
}

function plain(status: number, contentType: string, body: string): TestOuterResponse {
  return { status, headers: { "content-type": contentType }, body: utf8.encode(body) };
}

function random(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

const SCENARIOS: Scenario[] = [
  { name: "success" },
  {
    name: "rejected",
    expected: RequestRejected,
    arrange: (node) => node.setConfidential(() => plain(429, "text/plain", "sentinel-body")),
  },
  {
    name: "unexpected",
    expected: UnexpectedResponse,
    arrange: (node) => node.setConfidential(() => plain(502, "text/html", "<p>sentinel-body</p>")),
  },
  { name: "transport", expected: TransportFailed, failPost: true },
  {
    name: "signer mismatch",
    expected: ConfidentialSignerMismatch,
    arrange: (node) =>
      node.setConfidential(async (context) => {
        const normal = await context.normal();
        const headers = context.sign(normal.body, { seed: hexToBytes(OTHER_SEED_HEX) });
        return { ...normal, headers: { ...normal.headers, ...headers } };
      }),
  },
  {
    name: "bad signature",
    expected: BadSignature,
    arrange: (node) =>
      node.setConfidential(async (context) => {
        const normal = await context.normal();
        const headers = context.sign(normal.body, {
          seed: hexToBytes(OTHER_SEED_HEX),
          pubkeyHex: node.pubkeyHex,
        });
        return { ...normal, headers: { ...normal.headers, ...headers } };
      }),
  },
  {
    name: "stale",
    expected: StaleTimestamp,
    arrange: (node) =>
      node.setConfidential(async (context) => {
        const normal = await context.normal();
        const headers = context.sign(normal.body, { timestampMs: Date.now() - 61_000 });
        return { ...normal, headers: { ...normal.headers, ...headers } };
      }),
  },
  {
    name: "decrypt",
    expected: ConfidentialDecryptFailed,
    arrange: (node) =>
      node.setConfidential((context) => {
        const body = random(96);
        return {
          status: 200,
          headers: { "content-type": "message/ohttp-res", ...context.sign(body) },
          body,
        };
      }),
  },
  {
    name: "too short",
    expected: MalformedConfidentialResponse,
    arrange: (node) =>
      node.setConfidential((context) => {
        const body = random(47);
        return {
          status: 200,
          headers: { "content-type": "message/ohttp-res", ...context.sign(body) },
          body,
        };
      }),
  },
  { name: "invalid inner", expected: InvalidInnerRequest, inner: call("/sentinel-path#frag") },
  {
    name: "attestation 503",
    expected: AttestationUnavailable,
    arrange: (node) => node.setAttestation(() => plain(503, "text/html", "<p>sentinel-body</p>")),
  },
  {
    name: "node id missing",
    expected: AttestationUnavailable,
    arrange: (node) =>
      node.setAttestation(async (context) => {
        const normal = await context.normal();
        const { "vRPC-NodeId": _dropped, ...headers } = normal.headers;
        return { ...normal, headers };
      }),
  },
  {
    name: "attestation not JSON",
    expected: MalformedAttestationResponse,
    arrange: (node) =>
      node.setAttestation(() => ({
        status: 200,
        headers: { "content-type": "text/html", "vRPC-NodeId": NODE_ID },
        body: utf8.encode("<p>sentinel-body</p>"),
      })),
  },
  { name: "attestation failed", expected: AttestationFailed, hardwareFail: true },
];

function baseSentinels(): Set<string> {
  const secret = x25519SecretFromSeed(NODE_SEED);
  return new Set([
    API_KEY,
    "Sentinelkey",
    "sentinel-path",
    "sentinel-query",
    "sentinel-plaintext",
    "sentinel-reply",
    "sentinel-body",
    bytesToHex(NODE_SEED),
    bytesToHex(secret),
    bytesToHex(x25519.getPublicKey(secret)),
  ]);
}

function addWindows(sentinels: Set<string>, body: Uint8Array): void {
  const hex = bytesToHex(body);
  for (let i = 0; i + 32 <= hex.length; i += 32) sentinels.add(hex.slice(i, i + 32));
}

function testNode(): TestNode {
  return createTestNode({
    seed: NODE_SEED,
    chainId: CHAIN_ID,
    nodeId: NODE_ID,
    upstream: () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: UPSTREAM_BODY,
    }),
  });
}

// The client's signal handling is under test, not the in-test transport's listeners.
function capturing(
  node: TestNode,
  sentinels: Set<string>,
  failPost = false,
): ConfidentialTransport {
  return async ({ signal: _signal, ...request }) => {
    if (request.body !== undefined) {
      sentinels.add(bytesToHex(request.body.subarray(7, 39)));
      addWindows(sentinels, request.body);
    }
    if (failPost && request.method === "POST") throw new TypeError("fetch failed");
    const response = await node.transport(request);
    addWindows(sentinels, response.body);
    return response;
  };
}

function clientFor(
  keyIn: "path" | "header",
  transport: ConfidentialTransport,
  logger: Logger | undefined,
  hardwareFail = false,
): ConfidentialClient {
  return new ConfidentialClient({
    url: keyIn === "path" ? `${BASE_URL}/${API_KEY}` : BASE_URL,
    ...(keyIn === "header" ? { headers: { "x-api-key": API_KEY } } : {}),
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(
      hardwareFail ? { fail: new AttestationError("CHK-P1", "hardware check rejected") } : {},
    ),
    transport,
    ...(logger === undefined ? {} : { logger }),
  });
}

async function runSuite(logger: Logger | undefined): Promise<Capture> {
  const capture: Capture = { sentinels: baseSentinels(), errors: [] };
  for (const keyIn of ["path", "header"] as const) {
    for (const scenario of SCENARIOS) {
      const node = testNode();
      scenario.arrange?.(node);
      const transport = capturing(node, capture.sentinels, scenario.failPost);
      const client = clientFor(keyIn, transport, logger, scenario.hardwareFail);
      let outcome: unknown;
      try {
        await client.request(scenario.inner ?? call());
        outcome = "resolved";
      } catch (err) {
        outcome = err;
        capture.errors.push(err);
      }
      if (scenario.expected === undefined) {
        expect(outcome, scenario.name).toBe("resolved");
      } else {
        expect(outcome, scenario.name).toBeInstanceOf(scenario.expected);
      }
    }
  }
  return capture;
}

function replacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

function errorTexts(err: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<unknown>();
  let current = err;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    if (current instanceof Error) out.push(current.message, String(current), current.stack ?? "");
    else out.push(String(current));
    out.push(JSON.stringify(current, replacer) ?? "");
    current = (current as { cause?: unknown }).cause;
  }
  return out;
}

function leaks(haystack: string, sentinels: Set<string>): string[] {
  const lower = haystack.toLowerCase();
  return [...sentinels].filter((sentinel) => lower.includes(sentinel.toLowerCase()));
}

function logText(logger: CollectingLogger): string {
  return logger.calls.map((entry) => JSON.stringify(entry, replacer)).join("\n");
}

function watchOutput(): { consoleCalls(): number; warnings: unknown[] } {
  const spies = CONSOLE_METHODS.map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
  const warnings: unknown[] = [];
  const listener = (warning: unknown) => {
    warnings.push(warning);
  };
  process.on("warning", listener);
  cleanups.push(() => {
    process.off("warning", listener);
  });
  return {
    consoleCalls: () => spies.reduce((sum, spy) => sum + spy.mock.calls.length, 0),
    warnings,
  };
}

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
  vi.restoreAllMocks();
});

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("logging", () => {
  test("without a logger nothing is printed and no process warning is raised", async () => {
    const output = watchOutput();
    await runSuite(undefined);
    await settle();

    expect(output.consoleCalls()).toBe(0);
    expect(output.warnings).toEqual([]);
  });

  test("with a logger the confidential events carry only safe fields", async () => {
    const logger = collectingLogger();
    await runSuite(logger);
    const names = new Set(logger.calls.map(([event]) => event));

    for (const event of EVENTS) expect(names, event).toContain(event);
    for (const [event, data] of logger.calls) {
      if (!event.startsWith("confidential.")) continue;
      for (const key of Object.keys(data ?? {}))
        expect(SAFE_FIELDS, `${event}.${key}`).toContain(key);
    }
    const ok = logger.calls.find(([event]) => event === "confidential.attest.ok")?.[1];
    expect(ok).toMatchObject({ nodeId: NODE_ID, composeHash: "deadbeef" });
    expect(ok?.pubkey).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("no sentinel appears in any log event, error message, stack, JSON form or cause", async () => {
    const logger = collectingLogger();
    const capture = await runSuite(logger);
    const errors = capture.errors.flatMap(errorTexts).join("\n");

    expect(capture.errors).toHaveLength((SCENARIOS.length - 1) * 2);
    expect(leaks(logText(logger), capture.sentinels)).toEqual([]);
    expect(leaks(errors, capture.sentinels)).toEqual([]);
  });

  test("50 concurrent calls sharing one signal log no sentinel", async () => {
    const logger = collectingLogger();
    const sentinels = baseSentinels();
    const node = testNode();
    const client = clientFor("path", capturing(node, sentinels), logger);
    const controller = new AbortController();

    const responses = await Promise.all(
      Array.from({ length: 50 }, () => client.request(call(), { signal: controller.signal })),
    );

    expect(responses).toHaveLength(50);
    expect(logger.calls.filter(([event]) => event === "confidential.response")).toHaveLength(50);
    expect(leaks(logText(logger), sentinels)).toEqual([]);
  });

  test("50 concurrent calls sharing one signal print nothing without a logger", async () => {
    const output = watchOutput();
    const node = testNode();
    const client = clientFor("header", capturing(node, new Set()), undefined);
    const controller = new AbortController();

    await Promise.all(
      Array.from({ length: 50 }, () => client.request(call(), { signal: controller.signal })),
    );
    await settle();

    expect(output.consoleCalls()).toBe(0);
    expect(output.warnings).toEqual([]);
  });
});

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

// Stays bound and drops every connection, so no other process can take the port.
async function droppingEveryConnection(): Promise<string> {
  const server = createServer();
  server.on("connection", (socket) => socket.destroy());
  const origin = await listen(server);
  cleanups.push(() => {
    server.close();
  });
  return origin;
}

// Answers the attestation, then drops the connection on the sealed request.
async function droppingOrigin(node: TestNode): Promise<string> {
  let origin = "";
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (req.method === "POST") {
        req.socket.destroy();
        return;
      }
      void node
        .transport({ method: "GET", url: `${origin}${req.url ?? "/"}`, headers: {} })
        .then((answer) => {
          res.writeHead(answer.status, answer.headers);
          res.end(answer.body);
        })
        .catch(() => res.destroy());
    });
  });
  origin = await listen(server);
  cleanups.push(() => {
    server.closeAllConnections();
    server.close();
  });
  return origin;
}

describe("real network failures through the default transport", () => {
  test.each([
    ["attestation", AttestationUnavailable],
    ["sealed request", TransportFailed],
  ] as const)("a failed %s leaks no sentinel", async (leg, expected) => {
    const logger = collectingLogger();
    const origin =
      leg === "attestation" ? await droppingEveryConnection() : await droppingOrigin(testNode());
    for (const keyIn of ["path", "header"] as const) {
      const client = new ConfidentialClient({
        url: keyIn === "path" ? `${origin}/eth_vrpc/${API_KEY}` : `${origin}/eth_vrpc`,
        ...(keyIn === "header" ? { headers: { "x-api-key": API_KEY } } : {}),
        chainId: CHAIN_ID,
        hardwareVerifier: mockHardwareVerifier(),
        logger,
      });
      let err: unknown;
      try {
        await client.request(call());
      } catch (caught) {
        err = caught;
      }

      expect(err, keyIn).toBeInstanceOf(expected);
      expect(((err as Error).cause as Error).message, keyIn).toBe("The request failed.");
      expect(leaks(errorTexts(err).join("\n"), baseSentinels()), keyIn).toEqual([]);
    }
    expect(leaks(logText(logger), baseSentinels())).toEqual([]);
  });

  test.each([
    ["attestation", AttestationUnavailable],
    ["sealed request", TransportFailed],
  ] as const)("a fetch error quoting the keyed URL on the %s keeps only its code", async (leg, expected) => {
    const node = testNode();
    const original = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if ((init?.method === "GET") === (leg === "attestation")) {
        throw Object.assign(new Error(`request to ${url} failed, reason: socket hang up`), {
          code: "ECONNRESET",
        });
      }
      return original(input, init);
    });
    const origin = await droppingOrigin(node);
    const client = new ConfidentialClient({
      url: `${origin}/eth_vrpc/${API_KEY}`,
      chainId: CHAIN_ID,
      hardwareVerifier: mockHardwareVerifier(),
    });
    let err: unknown;
    try {
      await client.request(call());
    } catch (caught) {
      err = caught;
    }

    expect(err).toBeInstanceOf(expected);
    expect((err as Error).cause).toMatchObject({
      message: "The request failed.",
      code: "ECONNRESET",
    });
    expect(leaks(errorTexts(err).join("\n"), baseSentinels())).toEqual([]);
  });
});

describe("invalid caller headers", () => {
  test("a header value that fetch rejects fails at construction without echoing it", async () => {
    const bad = `${API_KEY}\nX`;
    let fetchError: unknown;
    try {
      await fetch("http://127.0.0.1:9/", { headers: { "x-api-key": bad } });
    } catch (err) {
      fetchError = err;
    }
    expect(leaks(errorTexts(fetchError).join("\n"), baseSentinels())).toContain(API_KEY);

    const fetchSpy = vi.spyOn(globalThis, "fetch");
    let err: unknown;
    try {
      new ConfidentialClient({
        url: BASE_URL,
        headers: { "x-api-key": bad },
        chainId: CHAIN_ID,
        hardwareVerifier: mockHardwareVerifier(),
      });
    } catch (caught) {
      err = caught;
    }
    expect(err).toBeInstanceOf(TypeError);
    expect((err as TypeError).cause).toBeUndefined();
    expect(leaks(errorTexts(err).join("\n"), baseSentinels())).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
