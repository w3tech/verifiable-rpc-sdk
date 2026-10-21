// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// End-to-end pipeline tests against the signing mock sidecar: happy paths
// (identity/gzip/zstd), the fail-closed tamper matrix, byte-exact request
// forwarding, verbatim relay, body caps, transport error
// kinds, and the silent-by-default guarantee. All requests use undici.request
// (raw wire bytes — global fetch would auto-decompress); all verification legs
// are injected via testOverrides(), so no test touches the network.

import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import * as zlib from "node:zlib";
import { verifyAsync } from "@noble/ed25519";
import { buildPreImage } from "@w3tech.io/vrpc-core";
import {
  attestationStub,
  mockHardwareVerifier,
  TEST_PUBKEY_HEX,
} from "@w3tech.io/vrpc-test-support";
import { closeServer, listen } from "@w3tech.io/vrpc-test-support/server";
import { request } from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createServerWith } from "../src/server";
import {
  type MockSidecar,
  type MockSidecarOptions,
  startMockSidecar,
} from "./support/mock-sidecar";
import { TEST_CHAIN_ID, testConfig, testOverrides } from "./support/test-overrides";

interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** POST raw bytes to the proxy and collect the raw (non-decoded) response. */
async function post(
  url: string,
  body: Buffer | string,
  headers: Record<string, string> = {},
): Promise<RawResponse> {
  const res = await request(url, { method: "POST", headers, body });
  const chunks: Buffer[] = [];
  for await (const chunk of res.body) {
    chunks.push(chunk as Buffer);
  }
  return { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) };
}

/** Reserve a loopback port and release it — a guaranteed-unbound upstream. */
async function unboundPort(): Promise<number> {
  const srv = createServer();
  const port = await new Promise<number>((resolve) => {
    srv.listen(0, "127.0.0.1", () => resolve((srv.address() as AddressInfo).port));
  });
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return port;
}

let cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  for (const fn of cleanups.reverse()) {
    await fn();
  }
  cleanups = [];
  vi.restoreAllMocks();
});

/** Start mock sidecar + proxy wired together; both are closed in afterEach. */
async function startProxy(
  mockOpts: MockSidecarOptions = {},
  configOverrides: Parameters<typeof testConfig>[1] = {},
): Promise<{ mock: MockSidecar; url: string }> {
  const mock = await startMockSidecar(mockOpts);
  cleanups.push(() => mock.close());
  const server = createServerWith(testConfig(mock.url, configOverrides), testOverrides());
  const url = await listen(server);
  cleanups.push(() => closeServer(server));
  return { mock, url };
}

const RPC_REQUEST = '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}';

async function expectErrorKind(res: RawResponse, status: number, kind: string): Promise<void> {
  expect(res.status).toBe(status);
  const parsed = JSON.parse(res.body.toString()) as { error: { kind: string; message: string } };
  expect(parsed.error.kind).toBe(kind);
}

describe("proxy pipeline", () => {
  test("happyPathIdentityRelaysVerbatimWithVrpcHeaders", async () => {
    const plaintext = '{"jsonrpc":"2.0","id":1,"result":"0xabc123"}';
    const { url } = await startProxy({ plaintext });

    const res = await post(url, RPC_REQUEST, { "content-type": "application/json" });

    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe(plaintext);

    // vRPC-* passthrough (R4): pubkey/nodeid exact, signature re-verifiable
    // client-side over the relayed headers + body.
    expect(res.headers["vrpc-pubkey"]).toBe(TEST_PUBKEY_HEX);
    expect(res.headers["vrpc-nodeid"]).toBe("node-test");
    const sigHeader = res.headers["vrpc-signature"] as string;
    const tsHeader = res.headers["vrpc-timestamp"] as string;
    expect(sigHeader).toMatch(/^0x[0-9a-f]{128}$/);
    const preImage = buildPreImage(
      TEST_CHAIN_ID,
      Buffer.from(RPC_REQUEST),
      res.body,
      BigInt(tsHeader),
    );
    const signature = Uint8Array.from(Buffer.from(sigHeader.slice(2), "hex"));
    await expect(
      verifyAsync(signature, preImage, Buffer.from(TEST_PUBKEY_HEX.slice(2), "hex")),
    ).resolves.toBe(true);
  });

  test("happyPathGzipRelaysExactCompressedBytes", async () => {
    const plaintext = '{"jsonrpc":"2.0","id":1,"result":"0xgzipbody"}';
    const { mock, url } = await startProxy({ encoding: "gzip", plaintext });

    const res = await post(url, RPC_REQUEST, { "accept-encoding": "gzip" });

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
    // Byte-identical relay: the exact compressed bytes the fixture sent.
    expect(Buffer.compare(res.body, mock.lastCompressedBody)).toBe(0);
    expect(zlib.gunzipSync(res.body).toString()).toBe(plaintext);
    expect(typeof res.headers["vrpc-signature"]).toBe("string");
  });

  test("forwardsRequestBytesByteExactWithVerbatimHeaders", async () => {
    const { mock, url } = await startProxy();
    const sent = Buffer.concat([
      Buffer.from("héllo → 世界 ", "utf8"),
      Buffer.from([0x00, 0xff, 0x80, 0x01, 0x7f]),
    ]);

    // Raw node:http client — undici refuses to set hop-by-hop headers, and
    // this test plants client hop-by-hop markers to prove they are stripped.
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        url,
        {
          method: "POST",
          headers: {
            "content-type": "application/octet-stream",
            "accept-encoding": "gzip, br",
            connection: "close",
            "proxy-authorization": "Basic Zm9v",
            te: "trailers",
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        },
      );
      req.on("error", reject);
      req.end(sent);
    });

    expect(status).toBe(200);
    expect(mock.received).toHaveLength(1);
    const received = mock.received[0];
    if (received === undefined) throw new Error("unreachable");
    // R2: the upstream saw exactly the bytes the client sent.
    expect(Buffer.compare(received.bytes, sent)).toBe(0);
    // Client headers forwarded verbatim (R1)...
    expect(received.headers["content-type"]).toBe("application/octet-stream");
    expect(received.headers["accept-encoding"]).toBe("gzip, br");
    // ...while the client's hop-by-hop headers never arrive upstream. The
    // upstream leg carries undici's OWN connection management header
    // (`connection: keep-alive`) — per-hop headers are per hop — so the
    // assertion is that the CLIENT's values do not propagate.
    expect(received.headers["proxy-authorization"]).toBeUndefined();
    expect(received.headers.te).toBeUndefined();
    expect(received.headers["transfer-encoding"]).toBeUndefined();
    expect(received.headers.connection).not.toBe("close");
  });

  test("tamperedBodyFailsClosedWithBadSignatureAndWithholdsBody", async () => {
    const marker = "MARKER_do_not_leak_9f8e7d6c";
    const plaintext = `{"jsonrpc":"2.0","id":1,"result":"${marker}"}`;
    const { url } = await startProxy({ tamper: "flip-byte", plaintext });

    const res = await post(url, RPC_REQUEST);

    await expectErrorKind(res, 502, "BadSignature");
    // Fail-closed body withholding (R3): no fragment of the upstream
    // plaintext may appear in the error response.
    expect(res.body.toString()).not.toContain(marker);
  });

  test("droppedTimestampHeaderFailsClosedWithMissingHeader", async () => {
    const { url } = await startProxy({ tamper: "drop-timestamp-header" });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "MissingHeader");
  });

  test("staleTimestampFailsClosedWithStaleTimestamp", async () => {
    const { url } = await startProxy({ tamper: "stale-timestamp" });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "StaleTimestamp");
  });

  test.each([
    {
      name: "vRPC-Timestamp above u64",
      extraHeaders: { "vRPC-Timestamp": "18446744073709551616" },
    },
    { name: "a repeated vRPC-NodeId", extraHeaders: { "vrpc-nodeid": ["n1", "n2"] } },
    {
      name: "a repeated vRPC-Signature",
      extraHeaders: { "vrpc-signature": `0x${"ab".repeat(64)}` },
    },
  ])("$name fails closed with MalformedHeader", async ({ extraHeaders }) => {
    const { url } = await startProxy({ extraHeaders });
    await expectErrorKind(await post(url, RPC_REQUEST), 502, "MalformedHeader");
  });

  test("repeatedContentEncodingIsDecodedAsAListAndRelayedVerbatim", async () => {
    const { mock, url } = await startProxy({
      encoding: "gzip",
      extraHeaders: { "content-encoding": ["gzip", "identity"] },
    });
    const res = await post(url, RPC_REQUEST);
    expect(res.status).toBe(200);
    expect(Buffer.compare(res.body, mock.lastCompressedBody)).toBe(0);
    expect(res.headers["content-encoding"]).toEqual(["gzip", "identity"]);
  });

  test("wrongChainIdFailsClosedWithBadSignature", async () => {
    // The chain hash is baked into the pre-image, so a response signed for a
    // different chain fails as BadSignature.
    const { url } = await startProxy({ tamper: "wrong-chain" });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "BadSignature");
  });

  test("unsignedUpstreamFailsClosedRegardlessOfUpstreamStatus", async () => {
    const ok = await startProxy({ tamper: "unsigned", status: 200 });
    const res200 = await post(ok.url, RPC_REQUEST);
    await expectErrorKind(res200, 502, "UnsignedUpstream");
    expect(JSON.parse(res200.body.toString()).error.message).toContain("200");

    const err = await startProxy({ tamper: "unsigned", status: 503 });
    const res503 = await post(err.url, RPC_REQUEST);
    await expectErrorKind(res503, 502, "UnsignedUpstream");
    expect(JSON.parse(res503.body.toString()).error.message).toContain("503");
  });

  test("upstreamRedirectIsNeverFollowed", async () => {
    // undici v8 follows redirects only via an opt-in redirect interceptor,
    // which the proxy does not compose. Pin that: an unsigned 302 fails
    // closed instead of being chased to its Location target. Catches anyone
    // ever composing interceptors.redirect onto the upstream dispatcher.
    const { mock, url } = await startProxy({
      tamper: "unsigned",
      status: 302,
      extraHeaders: { location: "/elsewhere" },
    });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "UnsignedUpstream");
    expect(JSON.parse(res.body.toString()).error.message).toContain("302");
    // Exactly one upstream request — nothing chased the Location target.
    expect(mock.received).toHaveLength(1);
  });

  test("upstreamTraceIdAppendedToErrorMessage", async () => {
    const traceId = "0a2d2888c132131e6350a26ddcd9d5a8";
    const { url } = await startProxy({
      tamper: "unsigned",
      status: 403,
      extraHeaders: { "x-shark-trace-id": traceId },
    });
    const res = await post(url, RPC_REQUEST);
    expect(res.status).toBe(502);
    const parsed = JSON.parse(res.body.toString()) as {
      error: { kind: string; message: string; traceId?: string };
    };
    expect(parsed.error.kind).toBe("UnsignedUpstream");
    expect(parsed.error.traceId).toBe(traceId);
    expect(parsed.error.message).not.toContain(traceId);
  });

  test("signedErrorBodyWithUpstream500IsRelayedVerbatim", async () => {
    // Verified content is relayed even when the upstream status is 5xx — a
    // signed JSON-RPC error body is verified content.
    const plaintext = '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}';
    const { url } = await startProxy({ plaintext, status: 500 });

    const res = await post(url, RPC_REQUEST);

    expect(res.status).toBe(500);
    expect(res.body.toString()).toBe(plaintext);
    expect(typeof res.headers["vrpc-signature"]).toBe("string");
  });

  test("relaysUpstreamEncodingVerbatimRegardlessOfClientAcceptEncoding", async () => {
    const plaintext = '{"jsonrpc":"2.0","id":1,"result":"0xverbatim"}';
    const { mock, url } = await startProxy({ encoding: "gzip", plaintext });

    // No accept-encoding header — the proxy still relays what it received.
    const res = await post(url, RPC_REQUEST);

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(Buffer.compare(res.body, mock.lastCompressedBody)).toBe(0);
    expect(typeof res.headers["vrpc-signature"]).toBe("string");
  });

  test("unsupportedUpstreamEncodingFailsClosed", async () => {
    const { url } = await startProxy({ encoding: { rawToken: "snappy" } });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "DecodeFailed");
  });

  test("undecodableGzipBodyFailsClosedWithDecodeFailed", async () => {
    // content-encoding claims gzip but the bytes are uncompressed plaintext.
    const { url } = await startProxy({ encoding: { rawToken: "gzip" } });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 502, "DecodeFailed");
  });

  test("oversizedRequestBodyRejectedBeforeUpstreamIO", async () => {
    const { mock, url } = await startProxy({}, { maxBodyBytes: 1024 });

    const res = await post(url, Buffer.alloc(4096, 0x61));

    await expectErrorKind(res, 413, "BodyTooLarge");
    // Cap enforced before any upstream I/O.
    expect(mock.received).toHaveLength(0);
  });

  test("upstreamTimeoutMapsTo504", async () => {
    const { url } = await startProxy({ delayMs: 1000 }, { upstreamTimeoutMs: 200 });
    const res = await post(url, RPC_REQUEST);
    await expectErrorKind(res, 504, "UpstreamTimeout");
  });

  test("upstreamConnectErrorMapsTo502", async () => {
    const port = await unboundPort();
    const server = createServerWith(testConfig(`http://127.0.0.1:${port}`), testOverrides());
    const url = await listen(server);
    cleanups.push(() => closeServer(server));

    const res = await post(url, RPC_REQUEST);

    await expectErrorKind(res, 502, "UpstreamConnect");
  });

  test("aClientDisconnectAbortsTheUpstreamRequest", async () => {
    const sockets: Socket[] = [];
    const upstream = createServer((req) => sockets.push(req.socket));
    const upstreamUrl = await listen(upstream);
    cleanups.push(() => closeServer(upstream));
    const config = testConfig(upstreamUrl, { upstreamTimeoutMs: 60_000 });
    const server = createServerWith(config, testOverrides());
    const url = await listen(server);
    cleanups.push(() => closeServer(server));
    const req = httpRequest(url, { method: "POST" });
    req.on("error", () => {});
    req.end(RPC_REQUEST);
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    req.destroy();
    await vi.waitFor(() => expect(sockets[0]?.destroyed).toBe(true));
  });

  test("decompressionBombFailsClosedWithDecodeFailed", async () => {
    // 8 MiB of zeros gzips to a tiny wire body — the wire cap passes, but the
    // decode-side maxOutputLength guard trips.
    const { url } = await startProxy(
      { encoding: "gzip", plaintext: Buffer.alloc(8 * 1024 * 1024) },
      { maxBodyBytes: 1024 * 1024 },
    );

    const res = await post(url, RPC_REQUEST, { "accept-encoding": "gzip" });

    await expectErrorKind(res, 502, "DecodeFailed");
  });

  test.each([
    "silent",
    "debug",
  ] as const)("%s: parallel cold verifies share one attestation and write nothing to stdout or console", async (logLevel) => {
    const methods = ["log", "info", "warn", "error", "debug"] as const;
    const consoles = methods.map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    const mock = await startMockSidecar();
    cleanups.push(() => mock.close());
    const stub = attestationStub();
    // Answers once every request has reached the upstream.
    const fetch = (async (input: string) => {
      await vi.waitFor(() => expect(mock.received).toHaveLength(10), { interval: 1 });
      return stub.fetch(input);
    }) as typeof globalThis.fetch;
    const overrides = { fetch, hardwareVerifier: mockHardwareVerifier() };
    const server = createServerWith(testConfig(mock.url, { logLevel }), overrides);
    const url = await listen(server);
    cleanups.push(() => closeServer(server));

    const sends = Array.from({ length: 10 }, () =>
      post(`${url}/sentinel-path?key=sentinel-query`, RPC_REQUEST, {
        "content-type": "application/json",
      }),
    );
    const statuses = (await Promise.all(sends)).map((res) => res.status);

    expect(statuses).toEqual(Array(10).fill(200));
    expect(stderr.join("")).not.toContain("sentinel");
    expect(stub.urls).toHaveLength(1);
    for (const spy of consoles) expect(spy).not.toHaveBeenCalled();
    expect(stdout).not.toHaveBeenCalled();
    const starts = stderr.filter((l) => l.startsWith("[vrpc-proxy] debug verify.start "));
    expect(starts).toHaveLength(logLevel === "debug" ? 10 : 0);
    if (logLevel === "silent") expect(stderr).toEqual([]);
  });
});

// Gated by the SAME runtime detect the production decode layer uses — CI's
// zstd landed in Node 23.8 — both the fixture compression and the decode side
// need the native codec; older runtimes skip.
describe.skipIf(typeof zlib.zstdDecompressSync !== "function")("proxy pipeline (zstd)", () => {
  test("happyPathZstdRelaysExactCompressedBytes", async () => {
    const plaintext = '{"jsonrpc":"2.0","id":1,"result":"0xzstdbody"}';
    const { mock, url } = await startProxy({ encoding: "zstd", plaintext });

    const res = await post(url, RPC_REQUEST, { "accept-encoding": "zstd" });

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("zstd");
    expect(Buffer.compare(res.body, mock.lastCompressedBody)).toBe(0);
    expect(zlib.zstdDecompressSync(res.body).toString()).toBe(plaintext);
  });
});
