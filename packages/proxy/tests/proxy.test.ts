// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// End-to-end pipeline tests against the signing mock sidecar: happy paths
// (identity/gzip/zstd), the fail-closed tamper matrix, byte-exact request
// forwarding, verbatim relay, body caps, transport error
// kinds, and the silent-by-default guarantee. All requests use undici.request
// (raw wire bytes — global fetch would auto-decompress); all verification legs
// are injected via testOverrides(), so no test touches the network.

import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as zlib from "node:zlib";

import { getPublicKeyAsync, verifyAsync } from "@noble/ed25519";
import { buildPreImage } from "@w3tech.io/vrpc-core";
import { request } from "undici";
import { afterEach, describe, expect, test, vi } from "vitest";

import { createProxyServer } from "../src/index";
import {
  type MockSidecar,
  type MockSidecarOptions,
  startMockSidecar,
} from "./support/mock-sidecar";
import {
  TEST_CHAIN_ID,
  TEST_SEED,
  testConfig,
  testOverrides,
  toHex,
} from "./support/test-overrides";

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

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
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
  const server = createProxyServer(testConfig(mock.url, configOverrides), testOverrides());
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
    const pubkeyHex = `0x${toHex(await getPublicKeyAsync(TEST_SEED))}`;
    expect(res.headers["vrpc-pubkey"]).toBe(pubkeyHex);
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
      verifyAsync(signature, preImage, await getPublicKeyAsync(TEST_SEED)),
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
    await expectErrorKind(res, 502, "UnsupportedEncoding");
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
    const server = createProxyServer(testConfig(`http://127.0.0.1:${port}`), testOverrides());
    const url = await listen(server);
    cleanups.push(() => closeServer(server));

    const res = await post(url, RPC_REQUEST);

    await expectErrorKind(res, 502, "UpstreamConnect");
  });

  test("silentLevelProducesZeroConsoleOutput", async () => {
    const spies = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "info").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {}),
      vi.spyOn(console, "error").mockImplementation(() => {}),
      vi.spyOn(console, "debug").mockImplementation(() => {}),
    ];

    const { url } = await startProxy();
    const res = await post(url, RPC_REQUEST);
    expect(res.status).toBe(200);

    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });
});

// Gated by the SAME runtime detect the production decode layer uses — CI's
// The fixture COMPRESSES with native zstd (landed in Node 23.8); decode-side
// http-encoding falls back to WASM, but without native compression there is
// no fixture body to test against.
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
