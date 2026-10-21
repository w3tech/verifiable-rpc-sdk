// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Loopback HTTP server around the in-test node, with wire capture, plus proxy and raw request helpers.

import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { gzipSync } from "node:zlib";
import {
  createTestNode,
  mockHardwareVerifier,
  type TestNode,
  type TestNodeOptions,
} from "@w3tech.io/vrpc-test-support";
import type { ProxyConfig } from "../../src/config";
import { createProxyServer, type ProxyTestOverrides } from "../../src/server";
import { testConfig } from "./test-overrides";

export interface WireRequest {
  method: string;
  path: string;
  query: string;
  /** Lowercased names; repeated values comma-joined. */
  headers: Record<string, string>;
  rawHeaders: string[];
  body: Buffer;
  socket: Socket;
}

/** Wire-level changes to the outer answer; `only` limits them to one method. */
interface WireHooks {
  /** Gzip answers below 400. */
  gzip?: boolean;
  /** `content-encoding: gzip` on bytes that are not gzip. */
  corruptGzip?: boolean;
  /** Wait before the status line. */
  delayMs?: number;
  /** Never answer; the request ends when the client closes the socket. */
  hang?: boolean;
  /** Close the socket without writing anything. */
  destroyBeforeHeaders?: boolean;
  /** Declare the full length, send this many body bytes, then close the socket. */
  cutAfterBytes?: number;
  extraHeaders?: Record<string, string | string[]>;
  only?: "GET" | "POST";
}

export interface TestNodeServer {
  url: string;
  node: TestNode;
  wire: WireRequest[];
  /** No argument restores plain answers. */
  setWire(hooks?: WireHooks): void;
  close(): Promise<void>;
}

export interface RunningProxy {
  url: string;
  server: http.Server;
  close(): Promise<void>;
}

export interface RawRequestOptions {
  method: string;
  path: string;
  /** An array value is sent as repeated header lines. */
  headers?: Record<string, string | string[]>;
  body?: Buffer | string;
}

export interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  rawHeaders: string[];
  body: Buffer;
}

export function listen(server: http.Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

export function closeServer(server: http.Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

async function readAll(stream: AsyncIterable<Buffer | Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Header names of a captured request as sent, lowercased, in wire order. */
export function wireHeaderNames(request: WireRequest): string[] {
  return request.rawHeaders.filter((_, i) => i % 2 === 0).map((name) => name.toLowerCase());
}

export async function startTestNodeServer(options: TestNodeOptions): Promise<TestNodeServer> {
  const node = createTestNode(options);
  const wire: WireRequest[] = [];
  let url = "";
  let wireHooks: WireHooks = {};

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readAll(req);
    const target = req.url ?? "/";
    const q = target.indexOf("?");
    const headers: Record<string, string> = {};
    for (const [name, values] of Object.entries(req.headersDistinct)) {
      if (values !== undefined) headers[name] = values.join(", ");
    }
    wire.push({
      method: req.method ?? "",
      path: q === -1 ? target : target.slice(0, q),
      query: q === -1 ? "" : target.slice(q + 1),
      headers,
      rawHeaders: [...req.rawHeaders],
      body,
      socket: req.socket,
    });
    const hooks = wireHooks.only === undefined || wireHooks.only === req.method ? wireHooks : {};
    if (hooks.hang === true) return;
    if (hooks.destroyBeforeHeaders === true) {
      req.socket.destroy();
      return;
    }
    if (hooks.delayMs !== undefined) {
      await delay(hooks.delayMs);
      if (req.socket.destroyed) return;
    }
    const answer = await node.transport({
      method: req.method ?? "GET",
      url: url + target,
      headers,
      ...(body.length > 0 ? { body } : {}),
    });
    let out = Buffer.from(answer.body);
    const outHeaders: Record<string, string | string[]> = {
      ...answer.headers,
      ...hooks.extraHeaders,
    };
    if (hooks.gzip === true && answer.status < 400) {
      out = gzipSync(out);
      outHeaders["content-encoding"] = "gzip";
    }
    if (hooks.corruptGzip === true) {
      out = Buffer.concat([Buffer.from("not gzip:"), out]);
      outHeaders["content-encoding"] = "gzip";
    }
    res.writeHead(answer.status, { ...outHeaders, "content-length": String(out.byteLength) });
    if (hooks.cutAfterBytes !== undefined) {
      res.write(out.subarray(0, hooks.cutAfterBytes), () => req.socket.destroy());
      return;
    }
    res.end(out);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => res.destroy());
  });
  url = await listen(server);
  return {
    url,
    node,
    wire,
    setWire(hooks) {
      wireHooks = hooks ?? {};
    },
    close: () => closeServer(server),
  };
}

export async function startConfidentialProxy(
  nodeServer: TestNodeServer,
  configOverrides: Partial<ProxyConfig> = {},
  overrides: ProxyTestOverrides = {},
): Promise<RunningProxy> {
  const config = testConfig(`${nodeServer.url}/test_vrpc`, {
    confidential: true,
    ...configOverrides,
  });
  const server = createProxyServer(config, {
    hardwareVerifier: mockHardwareVerifier(),
    ...overrides,
  });
  const url = await listen(server);
  return { url, server, close: () => closeServer(server) };
}

export function rawRequest(baseUrl: string, options: RawRequestOptions): Promise<RawResponse> {
  const base = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: base.hostname,
        port: base.port,
        method: options.method,
        path: options.path,
        headers: options.headers ?? {},
      },
      (res) => {
        readAll(res).then(
          (body) =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              rawHeaders: [...res.rawHeaders],
              body,
            }),
          reject,
        );
      },
    );
    req.on("error", reject);
    req.end(options.body);
  });
}
