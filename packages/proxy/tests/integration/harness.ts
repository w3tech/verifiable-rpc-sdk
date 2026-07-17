// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Integration test harness — spawns the dstack simulator, the sidecar binary,
// an in-process mock upstream, and the in-process verifying proxy under test.
//
// Local copy of packages/core/tests/integration/harness.ts (cross-package test
// import is awkward under this package's tsconfig/vitest resolver). Keep the
// shared spawn helpers byte-identical with the canonical copy; this copy adds
// two proxy-specific extensions: request capture on the mock upstream and the
// `spawnProxy` helper wrapping `createProxyServer`.
//
// This file deliberately does NOT end in `.test.ts` — the test runner only
// picks up `*.test.ts`, so importers can pull these helpers without the file
// being treated as a test suite.
//
// Required env vars (when running `pnpm --filter '@w3tech.io/vrpc-proxy' test:integration`):
//   DSTACK_SIMULATOR_BIN          — absolute path to the simulator binary
//   DSTACK_SIMULATOR_FIXTURES_DIR — directory with app-compose.json, appkeys.json, etc.
//   SIDECAR_BIN                   — absolute path to the rpc-attest-sidecar binary
//
// When any of these are unset, `integrationEnabled` is `false` and the test
// files skip their `describe` blocks cleanly.

import { type ChildProcess, spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { type AddressInfo, createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  type AttestationBundle,
  type VerifyPolicy,
  verifyDstackAttestation,
} from "@w3tech.io/dstack-verify";

import { createProxyServer } from "../../src/server";
import { mockHardwareVerifier } from "../support/mock-hardware-verifier";
import { testConfig } from "../support/test-overrides";

/** True when all required integration env vars are set and non-empty. */
export const integrationEnabled: boolean =
  !!process.env.DSTACK_SIMULATOR_BIN &&
  !!process.env.DSTACK_SIMULATOR_FIXTURES_DIR &&
  !!process.env.SIDECAR_BIN;

/** Handle returned by {@link spawnSimulator}. */
export interface SimulatorHandle {
  /** UDS path the dstack simulator listens on. */
  socketPath: string;
  /** Fresh tmpdir holding fixtures + socket; removed by `kill()`. */
  tmpDir: string;
  /** Terminate the simulator and remove the tmpdir. Best-effort, never throws. */
  kill: () => Promise<void>;
}

/** Handle returned by {@link spawnSidecar}. */
export interface SidecarHandle {
  /** Base URL where the sidecar is listening (no trailing slash). */
  url: string;
  /** Ed25519 signing pubkey advertised in the boot log (`0x` + 64 hex). */
  pubkeyHex: string;
  /** Chain ID the sidecar was started with — the exact string it signs with. */
  chainId: string;
  /** Terminate the sidecar process. Best-effort, never throws. */
  kill: () => Promise<void>;
}

/** One request observed by the mock upstream. */
export interface CapturedRequest {
  /** HTTP method as received (e.g. `GET`, `POST`). */
  method: string;
  /** Request target as received — path plus query string. */
  url: string;
}

/** Handle returned by {@link spawnMockUpstream}. */
export interface MockUpstreamHandle {
  /** Base URL where the mock is listening (no trailing slash). */
  url: string;
  /** Number of requests received so far. */
  receivedCount: () => number;
  /** Every request received so far, in arrival order. */
  requests: () => ReadonlyArray<CapturedRequest>;
  /** Stop the mock server. Best-effort, never throws. */
  kill: () => Promise<void>;
}

/** Handle returned by {@link spawnProxy}. */
export interface ProxyHandle {
  /** Base URL where the proxy is listening (no trailing slash). */
  url: string;
  /** Stop the proxy server. Best-effort, never throws. */
  kill: () => Promise<void>;
}

const SIM_FIXTURES = [
  "app-compose.json",
  "appkeys.json",
  "attestation.bin",
  "dstack.toml",
  "sys-config.json",
] as const;

/**
 * Spawn the dstack simulator. Mirrors `spawn_simulator` from the Rust harness:
 * fresh tmpdir, fixture files copied in, simulator launched with cwd=tmpdir,
 * UDS socket appears within 5s.
 */
export async function spawnSimulator(): Promise<SimulatorHandle> {
  const bin = requireEnv("DSTACK_SIMULATOR_BIN");
  const fixtures = requireEnv("DSTACK_SIMULATOR_FIXTURES_DIR");

  const dir = await fs.mkdtemp(join(tmpdir(), "vrpc-sim-"));
  for (const f of SIM_FIXTURES) {
    await fs.copyFile(join(fixtures, f), join(dir, f));
  }

  const proc = spawn(bin, [], { cwd: dir, stdio: "ignore" });

  const socketPath = join(dir, "dstack.sock");
  try {
    await waitForPath(socketPath, 5_000);
  } catch (err) {
    // Boot failure happens inside beforeAll before the handle is assigned, so
    // afterAll's cleanup() can never reap this child — kill it here and remove
    // the tmpdir before rethrowing (mirrors spawnSidecar's kill-on-failure).
    proc.kill("SIGTERM");
    await waitExit(proc).catch(() => undefined);
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
    throw err;
  }

  return {
    socketPath,
    tmpDir: dir,
    kill: async () => {
      try {
        proc.kill("SIGTERM");
      } catch {
        // already dead
      }
      try {
        await fs.rm(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    },
  };
}

/**
 * Spawn the sidecar binary. Mirrors `spawn_sidecar` from the Rust harness:
 * pre-bind an ephemeral port, pass it via `--listen-addr`, set the
 * `SIDECAR_ALLOW_EMPTY_COMPOSE_HASH=true` env, wait for `signing_pubkey=0x…`
 * in stdout/stderr, then wait until the TCP port accepts connections.
 *
 * Throws (after killing the child) when either deadline fires; the error
 * message embeds the captured stdout+stderr for diagnostics.
 */
export async function spawnSidecar(
  simSocketPath: string,
  upstreamUrl: string,
  chainId: string,
): Promise<SidecarHandle> {
  const bin = requireEnv("SIDECAR_BIN");
  const port = await ephemeralPort();

  const args = [
    "--listen-addr",
    `127.0.0.1:${port}`,
    "--upstream-url",
    upstreamUrl,
    "--chain-id",
    chainId,
    "--dstack-endpoint",
    simSocketPath,
  ];

  const proc = spawn(bin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SIDECAR_ALLOW_EMPTY_COMPOSE_HASH: "true",
      RUST_LOG: "info",
    },
  });

  const captured: string[] = [];
  const pushChunk = (chunk: Buffer | string) => {
    captured.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
  };
  proc.stdout?.on("data", pushChunk);
  proc.stderr?.on("data", pushChunk);

  const pubkeyRe = /signing_pubkey=(?:")?(0x[0-9a-fA-F]{64})(?:")?/;
  let pubkeyHex: string;
  try {
    pubkeyHex = await waitForMatch(captured, pubkeyRe, 10_000);
    await waitForListener(port, 5_000);
  } catch (err) {
    proc.kill("SIGTERM");
    await waitExit(proc).catch(() => undefined);
    const snapshot = captured.join("");
    throw new Error(
      `sidecar boot failed: ${(err as Error).message}\n--- captured ---\n${snapshot}`,
    );
  }

  return {
    url: `http://127.0.0.1:${port}`,
    pubkeyHex,
    chainId,
    kill: async () => {
      try {
        proc.kill("SIGTERM");
      } catch {
        // already dead
      }
      await waitExit(proc).catch(() => undefined);
    },
  };
}

/**
 * Spawn an in-process mock upstream. Defaults to a canned
 * `eth_blockNumber`-style success body; pass `canned` to override. Records
 * every inbound request's method and url (path + query) so tests can assert
 * what actually traversed proxy → sidecar → upstream.
 */
export async function spawnMockUpstream(canned?: string): Promise<MockUpstreamHandle> {
  const body = canned ?? '{"jsonrpc":"2.0","id":1,"result":"0x1234"}';
  let received = 0;
  const captured: CapturedRequest[] = [];

  const server = createHttpServer((req, res) => {
    received++;
    captured.push({ method: req.method ?? "", url: req.url ?? "" });
    // Drain the request body so the socket can be reused/closed cleanly.
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    receivedCount: () => received,
    requests: () => captured,
    kill: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}

/**
 * `verifyAttestation` override: the REAL `verifyDstackAttestation` with the
 * bundle's `app_compose` cleared so CHK-A2 (compose-hash self-consistency)
 * dormant-skips via its own designed skip path. The upstream dstack simulator
 * fixtures are inherently self-inconsistent — `attestation.bin` bakes
 * compose_hash c143116f… while no checked-in `app-compose.json` revision ever
 * hashed to it — so CHK-A2 can never pass against a simulator quote. Every
 * other check (CHK-A1 report_data binding, quote parsing, hardware gate)
 * still runs for real. CHK-A2 is self-consistency only, not a trust anchor
 * (both fields are self-reported by the same node).
 */
function simulatorVerifyAttestation(bundle: AttestationBundle, policy: VerifyPolicy) {
  return verifyDstackAttestation(
    { ...bundle, tcbInfo: { ...bundle.tcbInfo, app_compose: "" } },
    policy,
  );
}

/**
 * Spawn the verifying proxy in-process via `createProxyServer` on an ephemeral
 * port. Injects the no-network hardware-verifier mock (a simulator quote is
 * not real TDX) and the CHK-A2-skipping attestation verifier above — the
 * attestation leg still hits the real sidecar (that is what makes the suite a
 * real-wire test); everything else (attestation fetch, Ed25519 verify, replay
 * window) runs the production `TrustedVerifier` path. The attestation URL is
 * set explicitly to `${upstreamUrl}/attestation` (same as `deriveVrpcUrls`
 * would produce for a bare-origin upstream — the raw sidecar serves
 * `/attestation`); the CLI has no override flag (SDK-style single-URL
 * derivation) — this programmatic seam exists for tests.
 */
export async function spawnProxy(opts: {
  upstreamUrl: string;
  chainId: string;
}): Promise<ProxyHandle> {
  const config = testConfig(opts.upstreamUrl, {
    chainId: opts.chainId,
    attestationUrl: `${opts.upstreamUrl}/attestation`,
  });
  const server = createProxyServer(config, {
    hardwareVerifier: mockHardwareVerifier(),
    verifyAttestation: simulatorVerifyAttestation,
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    kill: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}

/**
 * Best-effort kill of every handle in reverse order. Swallows errors so a
 * single bad handle never derails the rest of the cleanup chain. Use from
 * `afterAll` so test failures don't leak processes.
 */
export async function cleanup(
  handles: ReadonlyArray<{ kill(): Promise<void> } | undefined>,
): Promise<void> {
  for (let i = handles.length - 1; i >= 0; i--) {
    const h = handles[i];
    if (!h) continue;
    try {
      await h.kill();
    } catch {
      // swallow
    }
  }
}

// ===== helpers =====

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(`env var ${name} is required for integration tests`);
  }
  return v;
}

/** Bind an OS-assigned ephemeral port then immediately close so a child can claim it. */
function ephemeralPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv: Server = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr === null || typeof addr === "string") {
        srv.close();
        reject(new Error("ephemeralPort: no address from listen()"));
        return;
      }
      const port = addr.port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitForPath(p: string, maxMs: number): Promise<void> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    try {
      await fs.access(p);
      return;
    } catch {
      // not yet
    }
    await sleep(50);
  }
  throw new Error(`timeout waiting for path ${p}`);
}

async function waitForMatch(buffer: readonly string[], re: RegExp, maxMs: number): Promise<string> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    const joined = buffer.join("");
    const m = joined.match(re);
    if (m?.[1]) return m[1];
    await sleep(50);
  }
  throw new Error(`timeout waiting for ${re}`);
}

/** Probe a TCP listener with short-lived connects until success or deadline. */
function waitForListener(port: number, maxMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + maxMs;
    const tryOnce = () => {
      const sock: Socket = new (require("node:net").Socket as typeof Socket)();
      sock.unref();
      let done = false;
      const succeed = () => {
        if (done) return;
        done = true;
        sock.destroy();
        resolve();
      };
      const fail = () => {
        if (done) return;
        sock.destroy();
        if (Date.now() >= deadline) {
          done = true;
          reject(new Error(`timeout waiting for TCP listener on 127.0.0.1:${port}`));
          return;
        }
        setTimeout(tryOnce, 50);
      };
      sock.once("connect", succeed);
      sock.once("error", fail);
      sock.connect(port, "127.0.0.1");
    };
    tryOnce();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function waitExit(proc: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (proc.exitCode !== null || proc.signalCode !== null) {
      resolve();
      return;
    }
    proc.once("exit", () => resolve());
  });
}
