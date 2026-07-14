// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Signing mock sidecar: a real node:http upstream that signs responses exactly
// like the production sidecar — Ed25519 over core's buildPreImage — and
// compresses strictly AFTER signing (the sidecar's CompressionLayer ordering:
// the signature covers the plaintext). Per-instance tamper and encoding modes
// drive the proxy's fail-closed matrix; the `received` capture array proves
// byte-exact request forwarding (R2). Sync zlib is acceptable — test-only.

import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import * as zlib from "node:zlib";

import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { buildPreImage } from "@w3tech.io/vrpc-core";

import { TEST_CHAIN_ID, TEST_SEED, toHex } from "./test-overrides";

/**
 * Wire encoding applied AFTER signing. `{ rawToken }` sets an arbitrary
 * content-encoding header while sending the UNENCODED plaintext bytes — use it
 * to drive UnsupportedEncoding (unknown token) or DecodeFailed (a known token
 * such as "gzip" whose bytes then fail to decode).
 */
export type MockSidecarEncoding = "identity" | "gzip" | "zstd" | { rawToken: string };

export type MockSidecarTamper =
  | "none"
  | "flip-byte"
  | "drop-timestamp-header"
  | "unsigned"
  | "stale-timestamp"
  | "wrong-chain";

export interface MockSidecarOptions {
  /** Wire encoding, applied after signing. Default: identity. */
  encoding?: MockSidecarEncoding;
  /** Tamper mode, applied after signing (and after encoding). Default: none. */
  tamper?: MockSidecarTamper;
  /** Fixed response plaintext. Default: a small JSON-RPC result. */
  plaintext?: Buffer | string;
  /** HTTP status of the response. Default: 200. */
  status?: number;
  /** Delay before responding, for upstream-timeout tests. */
  delayMs?: number;
}

export interface MockSidecar {
  /** Base URL of the mock (http://127.0.0.1:PORT). */
  url: string;
  /** Every request the mock received — raw body bytes plus headers. */
  received: { bytes: Buffer; headers: IncomingHttpHeaders }[];
  /** The exact wire bytes of the LAST response body the mock sent. */
  readonly lastCompressedBody: Buffer;
  close(): Promise<void>;
}

const DEFAULT_PLAINTEXT = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x12345" });

/** Start the signing mock sidecar on an ephemeral loopback port. */
export async function startMockSidecar(opts: MockSidecarOptions = {}): Promise<MockSidecar> {
  const encoding = opts.encoding ?? "identity";
  const tamper = opts.tamper ?? "none";
  const plaintext = Buffer.isBuffer(opts.plaintext)
    ? opts.plaintext
    : Buffer.from(opts.plaintext ?? DEFAULT_PLAINTEXT);
  const status = opts.status ?? 200;

  const received: { bytes: Buffer; headers: IncomingHttpHeaders }[] = [];
  const state: { lastCompressedBody: Buffer } = { lastCompressedBody: Buffer.alloc(0) };

  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(chunk as Buffer);
      }
      const bytes = Buffer.concat(chunks);
      received.push({ bytes, headers: req.headers });

      // Sign the plaintext over the request bytes exactly as received.
      let ts = BigInt(Date.now());
      if (tamper === "stale-timestamp") {
        // 600s in the past — far outside the default 60s replay window.
        ts -= 600_000n;
      }
      const signingChainId = tamper === "wrong-chain" ? "some-other-chain" : TEST_CHAIN_ID;
      const preImage = buildPreImage(signingChainId, bytes, plaintext, ts);
      const signature = await signAsync(preImage, TEST_SEED);
      const pubkey = await getPublicKeyAsync(TEST_SEED);

      // Encoding strictly AFTER signing (sidecar CompressionLayer ordering).
      let wire: Buffer = plaintext;
      let contentEncoding: string | undefined;
      if (encoding === "gzip") {
        wire = zlib.gzipSync(plaintext);
        contentEncoding = "gzip";
      } else if (encoding === "zstd") {
        // Caller gates on runtime availability (same detect as production).
        wire = zlib.zstdCompressSync(plaintext);
        contentEncoding = "zstd";
      } else if (typeof encoding === "object") {
        contentEncoding = encoding.rawToken;
      }

      // Tamper modes applied AFTER signing (flip-byte also after encoding —
      // it corrupts the wire bytes the client sees).
      if (tamper === "flip-byte") {
        wire = Buffer.from(wire);
        wire[0] = (wire[0] ?? 0) ^ 0xff;
      }

      const headers: Record<string, string> = {};
      if (tamper !== "unsigned") {
        headers["vRPC-Signature"] = `0x${toHex(signature)}`;
        if (tamper !== "drop-timestamp-header") {
          headers["vRPC-Timestamp"] = ts.toString();
        }
        headers["vRPC-Pubkey"] = `0x${toHex(pubkey)}`;
        headers["vRPC-NodeId"] = "node-test";
      }
      if (contentEncoding !== undefined) {
        headers["content-encoding"] = contentEncoding;
      }
      headers["content-length"] = String(wire.length);
      state.lastCompressedBody = wire;

      const respond = () => {
        if (res.destroyed || res.writableEnded) return;
        res.writeHead(status, headers);
        res.end(wire);
      };
      if (opts.delayMs !== undefined) {
        setTimeout(respond, opts.delayMs).unref();
      } else {
        respond();
      }
    })();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${address.port}`,
    received,
    get lastCompressedBody(): Buffer {
      return state.lastCompressedBody;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
