// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Signing mock sidecar: a real node:http upstream that signs responses exactly
// like the production sidecar — Ed25519 over the vRPC pre-image — and
// compresses strictly AFTER signing (the sidecar's CompressionLayer ordering:
// the signature covers the plaintext). Per-instance tamper and encoding modes
// drive the proxy's fail-closed matrix; the `received` capture array proves
// byte-exact request forwarding (R2). Sync zlib is acceptable — test-only.

import { createServer, type IncomingHttpHeaders } from "node:http";
import { buffer } from "node:stream/consumers";
import * as zlib from "node:zlib";
import { signResponse } from "@w3tech.io/vrpc-test-support";
import { closeServer, listen } from "@w3tech.io/vrpc-test-support/server";

import { TEST_CHAIN_ID } from "./test-overrides";

/**
 * Wire encoding applied AFTER signing. `{ rawToken }` sets an arbitrary
 * content-encoding header while sending the UNENCODED plaintext bytes — use it
 * to drive DecodeFailed (an unknown token, or a known token such as "gzip"
 * whose bytes then fail to decode).
 */
type MockSidecarEncoding = "identity" | "gzip" | "zstd" | { rawToken: string };

type MockSidecarTamper =
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
  /** Never responds, for upstream-timeout tests. */
  stall?: boolean;
  /** Extra response headers (e.g. an upstream gateway trace id). */
  extraHeaders?: Record<string, string | string[]>;
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
      const bytes = await buffer(req);
      received.push({ bytes, headers: req.headers });

      // Sign the plaintext over the request bytes exactly as received.
      let ts = BigInt(Date.now());
      if (tamper === "stale-timestamp") {
        // 600s in the past — far outside the default 60s replay window.
        ts -= 600_000n;
      }
      const signingChainId = tamper === "wrong-chain" ? "some-other-chain" : TEST_CHAIN_ID;
      const signed = signResponse(signingChainId, bytes, plaintext, {
        timestampMs: ts,
        nodeId: "node-test",
      });

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

      const headers: Record<string, string | string[]> = tamper === "unsigned" ? {} : signed;
      if (tamper === "drop-timestamp-header") {
        delete headers["vRPC-Timestamp"];
      }
      if (contentEncoding !== undefined) {
        headers["content-encoding"] = contentEncoding;
      }
      headers["content-length"] = String(wire.length);
      Object.assign(headers, opts.extraHeaders ?? {});
      state.lastCompressedBody = wire;

      if (opts.stall) return;
      res.writeHead(status, headers);
      res.end(wire);
    })();
  });

  return {
    url: await listen(server),
    received,
    get lastCompressedBody(): Buffer {
      return state.lastCompressedBody;
    },
    close: () => closeServer(server),
  };
}
