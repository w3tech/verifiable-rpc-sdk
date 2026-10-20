// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Interop stack for tests: dstack simulator, sidecar binary, echo upstream and a loopback relay. Node only.

import { type ChildProcess, spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import {
  createServer as createHttpServer,
  type Server as HttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
} from "node:http";
import { type AddressInfo, createServer as createNetServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const integrationEnabled: boolean =
  !!process.env.DSTACK_SIMULATOR_BIN &&
  !!process.env.DSTACK_SIMULATOR_FIXTURES_DIR &&
  !!process.env.SIDECAR_BIN;

export const INTEROP_SKIP_MESSAGE =
  "[integration] skipping — set DSTACK_SIMULATOR_BIN, DSTACK_SIMULATOR_FIXTURES_DIR, SIDECAR_BIN to run";

interface UpstreamRecord {
  method: string;
  url: string;
  contentType: string | null;
  accept: string | null;
  bodyLength: number;
  jsonArrayLength: number | null;
}

interface EchoUpstream {
  url: string;
  requests(): UpstreamRecord[];
  kill(): Promise<void>;
}

type RelayMode = "pass" | "flip" | "replay";

interface RelayRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Uint8Array;
  status: number;
}

interface Relay {
  url: string;
  set(options: { mode?: RelayMode; confidentialTarget?: string | null }): void;
  requests(): RelayRecord[];
  attestations(): number;
  kill(): Promise<void>;
}

interface InteropSidecar {
  url: string;
  pubkeyHex: string;
  kill(): Promise<void>;
}

export interface InteropOptions {
  chainId?: string;
  nodeId?: string;
  sidecarArgs?: string[];
}

export interface Interop {
  chainId: string;
  nodeId: string;
  sidecar: InteropSidecar;
  upstream: EchoUpstream;
  relay: Relay;
  spawnExtraSidecar(args: string[]): Promise<InteropSidecar>;
  kill(): Promise<void>;
}

interface Simulator {
  socketPath: string;
  kill(): Promise<void>;
}

interface Answer {
  status: number;
  headers: OutgoingHttpHeaders;
  body: Buffer;
}

const SIM_FIXTURES = [
  "app-compose.json",
  "appkeys.json",
  "attestation.bin",
  "dstack.toml",
  "sys-config.json",
] as const;

const RPC_RESULTS: Record<string, string> = {
  eth_blockNumber: "0x1234",
  eth_chainId: "0xa4b1",
  eth_getBalance: "0x5",
  eth_getTransactionCount: "0x3",
};

export async function spawnInterop(options: InteropOptions = {}): Promise<Interop> {
  const chainId = options.chainId ?? "42161";
  const nodeId = options.nodeId ?? "interop-node-1";
  const started: { kill(): Promise<void> }[] = [];
  try {
    const simulator = await spawnSimulator();
    started.push(simulator);
    const upstream = await spawnEchoUpstream();
    started.push(upstream);
    const sidecar = await spawnSidecar(
      simulator.socketPath,
      upstream.url,
      chainId,
      options.sidecarArgs ?? [],
    );
    started.push(sidecar);
    const relay = await spawnRelay(sidecar.url, nodeId);
    started.push(relay);

    const extras: InteropSidecar[] = [];
    return {
      chainId,
      nodeId,
      sidecar,
      upstream,
      relay,
      spawnExtraSidecar: async (args) => {
        const extra = await spawnSidecar(simulator.socketPath, upstream.url, chainId, args);
        extras.push(extra);
        return extra;
      },
      kill: () => stopAll([relay, ...extras, sidecar, upstream, simulator]),
    };
  } catch (err) {
    await stopAll(started.reverse());
    throw err;
  }
}

async function stopAll(handles: ReadonlyArray<{ kill(): Promise<void> }>): Promise<void> {
  for (const handle of handles) {
    try {
      await handle.kill();
    } catch {
      // best-effort
    }
  }
}

async function spawnSimulator(): Promise<Simulator> {
  const bin = requireEnv("DSTACK_SIMULATOR_BIN");
  const fixtures = requireEnv("DSTACK_SIMULATOR_FIXTURES_DIR");
  const dir = await fs.mkdtemp(join(tmpdir(), "vrpc-interop-"));
  const kill = async (proc?: ChildProcess) => {
    if (proc) await stopProcess(proc);
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
  };

  let proc: ChildProcess | undefined;
  try {
    for (const f of SIM_FIXTURES) {
      await fs.copyFile(join(fixtures, f), join(dir, f));
    }
    proc = spawn(bin, [], { cwd: dir, stdio: "ignore" });
    await waitForPath(join(dir, "dstack.sock"), 10_000, bootCheck(proc, "dstack simulator"));
  } catch (err) {
    await kill(proc);
    throw err;
  }
  const child = proc;
  return { socketPath: join(dir, "dstack.sock"), kill: () => kill(child) };
}

async function spawnSidecar(
  simSocketPath: string,
  upstreamUrl: string,
  chainId: string,
  extraArgs: string[],
): Promise<InteropSidecar> {
  const bin = requireEnv("SIDECAR_BIN");
  const port = await freePort();
  const args = [
    "--listen-addr",
    `127.0.0.1:${port}`,
    "--upstream-url",
    upstreamUrl,
    "--chain-id",
    chainId,
    "--dstack-endpoint",
    simSocketPath,
    ...extraArgs,
  ];
  const proc = spawn(bin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SIDECAR_ALLOW_EMPTY_COMPOSE_HASH: "true", RUST_LOG: "info" },
  });
  const check = bootCheck(proc, "sidecar");
  const captured: string[] = [];
  const capture = (chunk: Buffer) => captured.push(chunk.toString("utf8"));
  proc.stdout?.on("data", capture);
  proc.stderr?.on("data", capture);

  let pubkeyHex: string;
  try {
    pubkeyHex = await waitForMatch(
      captured,
      /signing_pubkey=(?:")?(0x[0-9a-fA-F]{64})(?:")?/,
      15_000,
      check,
    );
    await waitForListener(port, 10_000, check);
  } catch (err) {
    await stopProcess(proc);
    const output = captured.join("").slice(-2_000);
    throw new Error(`sidecar boot failed: ${(err as Error).message}\n${output}`);
  }
  return { url: `http://127.0.0.1:${port}`, pubkeyHex, kill: () => stopProcess(proc) };
}

async function spawnEchoUpstream(): Promise<EchoUpstream> {
  const records: UpstreamRecord[] = [];
  const server = createHttpServer(async (req, res) => {
    const body = await readBody(req);
    let parsed: unknown;
    let isJson = false;
    try {
      parsed = JSON.parse(body.toString("utf8"));
      isJson = true;
    } catch {
      // not JSON
    }
    const url = req.url ?? "/";
    records.push({
      method: req.method ?? "",
      url,
      contentType: req.headers["content-type"] ?? null,
      accept: req.headers.accept ?? null,
      bodyLength: body.length,
      jsonArrayLength: isJson && Array.isArray(parsed) ? parsed.length : null,
    });

    const json = (status: number, value: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (req.method === "POST") {
      if (!isJson) {
        json(400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      } else {
        json(200, Array.isArray(parsed) ? parsed.map(rpcAnswer) : rpcAnswer(parsed));
      }
      return;
    }
    const statusMatch = req.method === "GET" ? /^\/status\/(\d{3})$/.exec(url) : null;
    if (statusMatch) {
      const status = Number(statusMatch[1]);
      if (status === 204 || status === 205 || status === 304) {
        res.writeHead(status);
        res.end();
      } else {
        res.writeHead(status, { "content-type": "text/plain" });
        res.end(`status ${status}`);
      }
      return;
    }
    json(200, { method: req.method, url });
  });
  const url = await listen(server);
  return { url, requests: () => [...records], kill: () => closeServer(server) };
}

function rpcAnswer(call: unknown): unknown {
  const fields = typeof call === "object" && call !== null ? (call as Record<string, unknown>) : {};
  const method = typeof fields.method === "string" ? fields.method : "";
  return { jsonrpc: "2.0", id: fields.id ?? null, result: RPC_RESULTS[method] ?? "0x0" };
}

async function spawnRelay(sidecarUrl: string, nodeId: string): Promise<Relay> {
  const records: RelayRecord[] = [];
  let mode: RelayMode = "pass";
  let confidentialTarget: string | null = null;
  let attestations = 0;
  let lastConfidential: Answer | undefined;

  const server = createHttpServer(async (req, res) => {
    const method = req.method ?? "GET";
    const path = req.url ?? "/";
    const pathname = new URL(path, "http://relay.invalid").pathname;
    const body = await readBody(req);
    const callerHeaders = omit(req.headers, ["host", "connection"]);

    let answer: Answer;
    try {
      if (method === "GET" && pathname.endsWith("/attestation")) {
        attestations++;
        answer = await attestation(path, req.headers);
      } else if (method === "POST" && pathname.endsWith("/confidential")) {
        answer = await confidential(path, callerHeaders, body);
      } else {
        answer = await forward(sidecarUrl, method, path, callerHeaders, body);
      }
    } catch (err) {
      answer = text(502, `relay error: ${(err as Error).message}`);
    }

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(", ") : value;
    }
    records.push({ method, url: path, headers, body: new Uint8Array(body), status: answer.status });
    res.writeHead(answer.status, responseHeaders(answer));
    res.end(answer.body);
  });

  // The simulator fixtures are self-inconsistent (attestation.bin bakes a compose hash no
  // app-compose.json hashes to), so a blank app_compose takes the compose-hash check's skip path.
  async function attestation(path: string, headers: IncomingHttpHeaders): Promise<Answer> {
    const upstream = await forward(sidecarUrl, "GET", path, {
      ...omit(headers, ["host", "connection", "accept-encoding"]),
      "accept-encoding": "identity",
    });
    if (upstream.status < 200 || upstream.status >= 300) return upstream;
    const bundle = JSON.parse(upstream.body.toString("utf8")) as Record<string, unknown>;
    if ("app_compose" in bundle) bundle.app_compose = "";
    const body = Buffer.from(JSON.stringify(bundle));
    return {
      status: upstream.status,
      headers: {
        ...omit(upstream.headers, ["content-length", "content-encoding", "transfer-encoding"]),
        "vRPC-NodeId": nodeId,
        "content-length": String(body.length),
      },
      body,
    };
  }

  async function confidential(
    path: string,
    headers: OutgoingHttpHeaders,
    body: Buffer,
  ): Promise<Answer> {
    if (mode === "replay") return lastConfidential ?? text(502, "no stored answer");
    const answer = await forward(confidentialTarget ?? sidecarUrl, "POST", path, headers, body);
    lastConfidential = answer;
    if (mode === "flip" && answer.body.length > 0) {
      const flipped = Buffer.from(answer.body);
      flipped[flipped.length - 1] = (flipped[flipped.length - 1] ?? 0) ^ 0x01;
      return { ...answer, body: flipped };
    }
    return answer;
  }

  const url = await listen(server);
  return {
    url,
    set: (options) => {
      if (options.mode !== undefined) mode = options.mode;
      if (options.confidentialTarget !== undefined) confidentialTarget = options.confidentialTarget;
    },
    requests: () => [...records],
    attestations: () => attestations,
    kill: () => closeServer(server),
  };
}

function forward(
  target: string,
  method: string,
  path: string,
  headers: OutgoingHttpHeaders,
  body?: Buffer,
): Promise<Answer> {
  const { hostname, port } = new URL(target);
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname, port, method, path, headers, agent: false }, (res) => {
      readBody(res).then(
        (resBody) =>
          resolve({ status: res.statusCode ?? 502, headers: res.headers, body: resBody }),
        reject,
      );
    });
    req.on("error", reject);
    req.end(body);
  });
}

function responseHeaders(answer: Answer): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = omit(answer.headers, [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
  ]);
  if (answer.status !== 204 && answer.status !== 304) {
    headers["content-length"] = String(answer.body.length);
  }
  return headers;
}

function text(status: number, message: string): Answer {
  return { status, headers: { "content-type": "text/plain" }, body: Buffer.from(message) };
}

function omit(headers: OutgoingHttpHeaders, names: readonly string[]): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined && !names.includes(name.toLowerCase())) out[name] = value;
  }
  return out;
}

function readBody(stream: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

async function listen(server: HttpServer): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function closeServer(server: HttpServer): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`env var ${name} is required for integration tests`);
  return value;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

// The returned check throws once the process failed to spawn or exited, so a boot wait ends early.
function bootCheck(proc: ChildProcess, what: string): () => void {
  let spawnError: Error | undefined;
  proc.on("error", (err) => {
    spawnError ??= err;
  });
  return () => {
    if (spawnError) throw new Error(`${what} failed to start: ${spawnError.message}`);
    if (proc.exitCode !== null || proc.signalCode !== null) {
      throw new Error(`${what} exited early (code ${proc.exitCode}, signal ${proc.signalCode})`);
    }
  };
}

async function waitForPath(path: string, maxMs: number, check: () => void): Promise<void> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    try {
      await fs.access(path);
      return;
    } catch {
      await sleep(50);
    }
    check();
  }
  throw new Error(`timeout waiting for path ${path}`);
}

async function waitForMatch(
  buffer: readonly string[],
  re: RegExp,
  maxMs: number,
  check: () => void,
): Promise<string> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    const match = buffer.join("").match(re);
    if (match?.[1]) return match[1];
    await sleep(50);
    check();
  }
  throw new Error(`timeout waiting for ${re}`);
}

function waitForListener(port: number, maxMs: number, check: () => void): Promise<void> {
  const deadline = Date.now() + maxMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = new Socket();
      sock.unref();
      sock.once("connect", () => {
        sock.destroy();
        resolve();
      });
      sock.once("error", () => {
        sock.destroy();
        try {
          check();
        } catch (err) {
          reject(err);
          return;
        }
        if (Date.now() >= deadline) {
          reject(new Error(`timeout waiting for TCP listener on 127.0.0.1:${port}`));
        } else {
          setTimeout(attempt, 50);
        }
      });
      sock.connect(port, "127.0.0.1");
    };
    attempt();
  });
}

async function stopProcess(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => proc.once("exit", () => resolve()));
  proc.kill("SIGTERM");
  let timer: NodeJS.Timeout | undefined;
  const stuck = await Promise.race([
    exited.then(() => false),
    new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(true), 5_000);
    }),
  ]);
  clearTimeout(timer);
  if (stuck) {
    proc.kill("SIGKILL");
    await exited;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
