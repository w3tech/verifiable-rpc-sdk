// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Loopback HTTP server fronting an in-test node, with a request log and per-test answers.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { gzipSync } from "node:zlib";
import {
  createTestNode,
  type TestNode,
  type TestNodeOptions,
  type TestOuterResponse,
} from "./node";

export interface ServedRequest {
  method: string;
  /** Path and query as received. */
  url: string;
  path: string;
  /** Lowercase names; repeated values joined with ", ". */
  headers: Record<string, string>;
  rawHeaders: string[];
  body: Uint8Array;
  gzipped: boolean;
  socket: Socket;
}

export interface ServedAnswer {
  status: number;
  /** An array value is sent as repeated header lines. */
  headers?: Record<string, string | string[]>;
  body?: Uint8Array | string;
  /** Declares the full length, writes this many body bytes, then destroys the socket. */
  cutAfter?: number;
}

/** Returns the answer, or `undefined` to send the node's own answer. */
type ServedHandler = (
  request: ServedRequest,
  forward: () => Promise<TestOuterResponse>,
) => ServedAnswer | undefined | Promise<ServedAnswer | undefined>;

export interface TestNodeServerOptions {
  /** Gzips answers below 400 when the request accepts gzip. */
  gzipWhenAccepted?: boolean;
}

export interface TestNodeServer {
  readonly url: string;
  readonly node: TestNode;
  readonly requests: ServedRequest[];
  /** Sets the handler for later requests; no argument restores plain forwarding. */
  answer(handler?: ServedHandler): void;
  close(): Promise<void>;
}

function flatten(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, values] of Object.entries(req.headersDistinct)) {
    if (values !== undefined) out[name] = values.join(", ");
  }
  return out;
}

export function listen(server: Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
    });
  });
}

export function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

function acceptsGzip(value: string | undefined): boolean {
  return (value ?? "").split(",").some((item) => {
    const [coding, ...params] = item.split(";").map((part) => part.trim().toLowerCase());
    return coding === "gzip" && !params.some((param) => /^q=0(\.0*)?$/.test(param));
  });
}

export async function serveTestNode(
  node: TestNode,
  options: TestNodeServerOptions = {},
): Promise<TestNodeServer> {
  const requests: ServedRequest[] = [];
  let handler: ServedHandler | undefined;
  let origin = "";

  function write(entry: ServedRequest, answer: ServedAnswer, res: ServerResponse): void {
    const raw = answer.body ?? new Uint8Array(0);
    let body = typeof raw === "string" ? Buffer.from(raw, "utf8") : Buffer.from(raw);
    const headers = Object.fromEntries(
      Object.entries(answer.headers ?? {}).filter(
        ([name]) => name.toLowerCase() !== "content-length",
      ),
    );
    if (
      options.gzipWhenAccepted === true &&
      answer.status < 400 &&
      acceptsGzip(entry.headers["accept-encoding"])
    ) {
      body = gzipSync(body);
      headers["content-encoding"] = "gzip";
      entry.gzipped = true;
    }
    res.writeHead(answer.status, { ...headers, "content-length": String(body.byteLength) });
    if (answer.cutAfter === undefined) {
      res.end(body);
      return;
    }
    res.write(body.subarray(0, answer.cutAfter), () => res.socket?.destroy());
  }

  const server = createServer((req, res) => {
    res.on("error", () => {});
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const url = req.url ?? "/";
      const entry: ServedRequest = {
        method: req.method ?? "",
        url,
        path: url.split("?", 1)[0] ?? url,
        headers: flatten(req),
        rawHeaders: [...req.rawHeaders],
        body: new Uint8Array(Buffer.concat(chunks)),
        gzipped: false,
        socket: req.socket,
      };
      requests.push(entry);
      const forward = () =>
        node.transport({
          method: entry.method,
          url: `${origin}${url}`,
          headers: { ...entry.headers },
          ...(entry.body.byteLength === 0 ? {} : { body: entry.body }),
        });
      const current = handler;
      Promise.resolve()
        .then(() => current?.(entry, forward))
        .then(async (answer) => {
          // A request whose client left during the handler never reaches the node.
          if (req.socket.destroyed) return;
          write(entry, answer ?? (await forward()), res);
        })
        .catch(() => res.destroy());
    });
  });
  origin = await listen(server);

  return {
    url: origin,
    node,
    requests,
    answer(next) {
      handler = next;
    },
    close: () => closeServer(server),
  };
}

/** Serves a default test node in front of `upstream`. */
export function serveUpstream(
  upstream: NonNullable<TestNodeOptions["upstream"]>,
  options?: TestNodeServerOptions,
): Promise<TestNodeServer> {
  return serveTestNode(createTestNode({ upstream }), options);
}

/** Leaves every later sealed POST unanswered; returns the bodies received. */
export function holdPosts(server: TestNodeServer): Uint8Array[] {
  const sent: Uint8Array[] = [];
  server.answer((request) => {
    if (!isPost(request)) return undefined;
    sent.push(request.body);
    return new Promise<undefined>(() => {});
  });
  return sent;
}

export const isPost = (request: ServedRequest) => request.method === "POST";

export const countOf = (server: TestNodeServer, match: (request: ServedRequest) => boolean) =>
  server.requests.filter(match).length;

/** A 429 with retry-after, a redirect to `/elsewhere` on the same server, or a plain-text failure. */
export function failureAnswer(server: TestNodeServer, status: number): ServedAnswer {
  if (status === 429) {
    return { status, headers: { "content-type": "text/plain", "retry-after": "1" }, body: "slow" };
  }
  if (status >= 300 && status < 400) {
    return { status, headers: { location: `${server.url}/elsewhere` } };
  }
  return { status, headers: { "content-type": "text/plain" }, body: "gateway failure" };
}
