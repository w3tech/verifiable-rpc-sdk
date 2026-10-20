// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode: logs and error bodies carry no path, query, plaintext, key or client header.

import { AttestationError, type HardwareVerifier } from "@w3tech.io/dstack-verify";
import type { TestOuterResponse } from "@w3tech.io/vrpc-test-support";
import { TEST_SEED } from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { LogLevel } from "../src/logger";
import {
  type RawResponse,
  rawRequest,
  startConfidentialProxy,
  startTestNodeServer,
} from "./support/test-node-server";
import { TEST_CHAIN_ID } from "./support/test-overrides";

const API_KEY = "abcdef0123456789".repeat(4);
const PLAINTEXT_HEX = "73656e74696e656c2d706c61696e74657874";
const SENTINELS = [
  "sentinel-path",
  "sentinel-query",
  "sentinel-plaintext",
  PLAINTEXT_HEX,
  API_KEY,
  "sentinel-auth",
  "sentinel-client-key",
];
const CLIENT_HEADERS = {
  authorization: "Bearer sentinel-auth",
  "x-api-key": "sentinel-client-key",
};
const RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":["sentinel-plaintext"]}';
const BATCH_BODY = `[${RPC_BODY},{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}]`;
const TIMEOUT_MS = 300;

const EVENT_FIELDS: Record<string, { required: string[]; optional: string[] }> = {
  "proxy.attested": { required: ["nodeId", "durationMs"], optional: [] },
  "proxy.relay": {
    required: ["status", "requestBytes", "responseBytes", "durationMs", "nodeId"],
    optional: [],
  },
  "proxy.error": { required: ["kind", "status", "message"], optional: ["executed"] },
  "proxy.attestFailed": { required: ["kind", "message"], optional: ["executed"] },
  "proxy.clientAborted": { required: [], optional: [] },
};

const CONSOLE_METHODS = ["log", "info", "warn", "error", "debug"] as const;

interface Capture {
  stderr: string[];
  console: { method: string; text: string }[];
  errorBodies: string[];
}

const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  return (
    JSON.stringify(value, (_, v: unknown) => (typeof v === "bigint" ? v.toString() : v)) ??
    String(value)
  );
}

function plain(status: number, body: string): TestOuterResponse {
  return { status, headers: { "content-type": "application/json" }, body: Buffer.from(body) };
}

function capture(): Capture {
  const out: Capture = { stderr: [], console: [], errorBodies: [] };
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    out.stderr.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
    return true;
  });
  for (const method of CONSOLE_METHODS) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      out.console.push({ method, text: args.map(stringify).join(" ") });
    });
  }
  return out;
}

function keep(out: Capture, res: RawResponse): RawResponse {
  if (res.headers["content-type"] === "application/json" && res.status >= 400) {
    out.errorBodies.push(res.body.toString());
  }
  return res;
}

/** Every scenario of the sweep at one log level; returns what was written and answered. */
async function drive(logLevel: LogLevel): Promise<Capture> {
  const node = await startTestNodeServer({
    seed: TEST_SEED,
    chainId: TEST_CHAIN_ID,
    nodeId: "logging-node-1",
    upstream: () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"jsonrpc":"2.0","id":1,"result":"0x10"}',
    }),
  });
  cleanups.push(() => node.close());
  const out = capture();
  const config = { logLevel, upstreamTimeoutMs: TIMEOUT_MS };

  const proxy = await startConfidentialProxy(node, {
    ...config,
    upstreamUrl: `${node.url}/${API_KEY}`,
  });
  cleanups.push(() => proxy.close());
  await vi.waitFor(() => expect(node.node.attestations()).toBe(1));

  const send = async (method: string, path: string, body?: string, contentType?: string) =>
    keep(
      out,
      await rawRequest(proxy.url, {
        method,
        path,
        headers: {
          ...CLIENT_HEADERS,
          ...(contentType === undefined ? {} : { "content-type": contentType }),
        },
        ...(body === undefined ? {} : { body }),
      }),
    );

  expect(
    (await send("POST", "/sentinel-path/rpc?sentinel-query=1", RPC_BODY, "application/json"))
      .status,
  ).toBe(200);
  expect(
    (await send("POST", "/sentinel-path/rpc?sentinel-query=1", BATCH_BODY, "application/json"))
      .status,
  ).toBe(200);
  expect((await send("GET", "/sentinel-path/x?sentinel-query=1")).status).toBe(200);
  expect((await send("GET", "/sentinel-path/../x?sentinel-query=1")).status).toBe(400);
  expect((await send("POST", "/sentinel-path/rpc?sentinel-query=1", RPC_BODY)).status).toBe(415);

  node.node.setConfidential(() => plain(401, '{"error":"unauthorized"}'));
  expect(
    (await send("POST", "/sentinel-path/rpc?sentinel-query=1", RPC_BODY, "application/json"))
      .status,
  ).toBe(502);
  node.node.setConfidential();

  node.setWire({ delayMs: 1000, only: "POST" });
  expect(
    (await send("POST", "/sentinel-path/rpc?sentinel-query=1", RPC_BODY, "application/json"))
      .status,
  ).toBe(504);
  node.setWire({ cutAfterBytes: 10, only: "POST" });
  expect(
    (await send("POST", "/sentinel-path/rpc?sentinel-query=1", RPC_BODY, "application/json"))
      .status,
  ).toBe(502);
  node.setWire();

  const unreachable = await startConfidentialProxy(node, {
    ...config,
    upstreamUrl: `http://127.0.0.1:9/${API_KEY}`,
  });
  cleanups.push(() => unreachable.close());
  const failing: HardwareVerifier = {
    async verifyHardware() {
      throw new AttestationError("CHK-P1", "hardware check failed");
    },
  };
  const unverified = await startConfidentialProxy(
    node,
    { ...config, upstreamUrl: `${node.url}/${API_KEY}` },
    { hardwareVerifier: failing },
  );
  cleanups.push(() => unverified.close());
  for (const target of [unreachable, unverified]) {
    const res = keep(
      out,
      await rawRequest(target.url, {
        method: "POST",
        path: "/sentinel-path/rpc?sentinel-query=1",
        headers: { ...CLIENT_HEADERS, "content-type": "application/json" },
        body: RPC_BODY,
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(500);
  }
  if (logLevel !== "silent") {
    await vi.waitFor(() =>
      expect(out.stderr.filter((l) => l.includes(" proxy.attestFailed")).length).toBe(2),
    );
  }
  return out;
}

function expectNoSentinel(out: Capture): void {
  const texts = [...out.stderr, ...out.console.map((c) => c.text), ...out.errorBodies];
  for (const text of texts) {
    for (const sentinel of SENTINELS) expect(text).not.toContain(sentinel);
  }
}

function parseLine(line: string): {
  severity: string;
  event: string;
  fields: Record<string, unknown>;
} {
  const match = /^\[vrpc-proxy\] (error|debug) (\S+)(?: (\{.*\}))?\n$/s.exec(line);
  expect(match, line).not.toBeNull();
  const [, severity = "", event = "", json] = match ?? [];
  return {
    severity,
    event,
    fields: json === undefined ? {} : (JSON.parse(json) as Record<string, unknown>),
  };
}

describe("confidential logging", () => {
  test("debug: no sentinel anywhere, and every proxy event carries only its own fields", async () => {
    const out = await drive("debug");
    expectNoSentinel(out);
    expect(out.errorBodies.length).toBeGreaterThanOrEqual(6);
    expect(out.console.some((c) => c.method === "debug")).toBe(true);

    const lines = out.stderr.filter((l) => l.startsWith("[vrpc-proxy] "));
    expect(lines).toHaveLength(out.stderr.length);
    const seen = new Set<string>();
    for (const line of lines) {
      const { event, fields } = parseLine(line);
      const spec = EVENT_FIELDS[event];
      expect(spec, event).toBeDefined();
      const keys = Object.keys(fields);
      for (const key of spec?.required ?? []) expect(keys, event).toContain(key);
      for (const key of keys) {
        expect([...(spec?.required ?? []), ...(spec?.optional ?? [])], event).toContain(key);
      }
      expect(keys).not.toContain("url");
      expect(keys).not.toContain("method");
      seen.add(event);
    }
    for (const event of ["proxy.attested", "proxy.relay", "proxy.error", "proxy.attestFailed"]) {
      expect(seen).toContain(event);
    }
  }, 20_000);

  test("error: only failure events reach stderr and core's console logger stays quiet", async () => {
    const out = await drive("error");
    expectNoSentinel(out);
    expect(out.stderr.length).toBeGreaterThan(0);
    for (const line of out.stderr) {
      expect(line).toMatch(/^\[vrpc-proxy\] error proxy\.(error|attestFailed) /);
    }
    expect(out.console.filter((c) => c.method === "debug")).toHaveLength(0);
  }, 20_000);

  test("silent: no stderr write and no console call", async () => {
    const out = await drive("silent");
    expectNoSentinel(out);
    expect(out.errorBodies.length).toBeGreaterThanOrEqual(6);
    expect(out.stderr).toHaveLength(0);
    expect(out.console).toHaveLength(0);
  }, 20_000);
});
