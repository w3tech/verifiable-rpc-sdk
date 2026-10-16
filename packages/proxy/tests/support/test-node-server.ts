// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Loopback HTTP server around the in-test node, with wire capture, plus proxy and raw request helpers.

import http from "node:http";
import type { AddressInfo } from "node:net";

import {
  createTestNode,
  type TestNode,
  type TestNodeOptions,
} from "../../../test-support/src/index";
import type { ProxyConfig } from "../../src/config";
import { createProxyServer, type ProxyTestOverrides } from "../../src/server";
import { mockHardwareVerifier } from "./mock-hardware-verifier";
import { testConfig } from "./test-overrides";

export interface WireRequest {
  method: string;
  path: string;
  query: string;
  /** Lowercased names; repeated values comma-joined. */
  headers: Record<string, string>;
  rawHeaders: string[];
  body: Buffer;
}

export interface TestNodeServer {
  url: string;
  node: TestNode;
  wire: WireRequest[];
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

function listen(server: http.Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
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
    });
    const answer = await node.transport({
      method: req.method ?? "GET",
      url: url + target,
      headers,
      ...(body.length > 0 ? { body } : {}),
    });
    res.writeHead(answer.status, {
      ...answer.headers,
      "content-length": String(answer.body.byteLength),
    });
    res.end(answer.body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => res.destroy());
  });
  url = await listen(server);
  return { url, node, wire, close: () => closeServer(server) };
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
