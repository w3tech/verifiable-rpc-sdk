// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Proxy test helpers: a confidential proxy in front of a test node server, and raw HTTP requests.

import http from "node:http";
import { mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import {
  closeServer,
  listen,
  type ServedRequest,
  type TestNodeServer,
} from "@w3tech.io/vrpc-test-support/server";
import type { ProxyConfig } from "../../src/config";
import { createServerWith, type ProxyTestOverrides } from "../../src/server";
import { testConfig } from "./test-overrides";

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

async function readAll(stream: AsyncIterable<Buffer | Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Header names of a captured request as sent, lowercased, in wire order. */
export function wireHeaderNames(request: ServedRequest): string[] {
  return request.rawHeaders.filter((_, i) => i % 2 === 0).map((name) => name.toLowerCase());
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
  const server = createServerWith(config, {
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
