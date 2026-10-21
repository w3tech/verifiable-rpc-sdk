import { rejectionOf, signResponse } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";

import {
  BadSignature,
  InvalidChainId,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
} from "../src/errors";
import { isSignedVrpcResponse, type ResponseHeaders, verifyResponse } from "../src/verify";

const CHAIN_ID = "1";

interface SignedTriple {
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  headers: Record<string, string>;
}

/**
 * Sign a (request, response) pair with TEST_SEED over the canonical 104-byte
 * pre-image and emit the matching `vRPC-*` headers. No fetch — drives
 * `verifyResponse` directly.
 */
async function signTriple(
  request: string,
  response: string,
  timestampMs: bigint,
  opts: { signingChainId?: string; nodeId?: string } = {},
): Promise<SignedTriple> {
  const requestBytes = new TextEncoder().encode(request);
  const responseBytes = new TextEncoder().encode(response);
  const headers = signResponse(opts.signingChainId ?? CHAIN_ID, requestBytes, responseBytes, {
    timestampMs,
    nodeId: opts.nodeId,
  });
  return { requestBytes, responseBytes, headers };
}

const REQUEST = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] });
const RESPONSE = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x12345" });

describe("verifyResponse", () => {
  test("happyPathReturnsVerifiedPair", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    const pair = await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
      chainId: CHAIN_ID,
      nowMs,
    });
    expect(pair.responseBytes).toBeInstanceOf(Uint8Array);
    expect(pair.responseBytes.length).toBe(t.responseBytes.length);
    expect(pair.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(pair.verification.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(pair.verification.timestampMs).toBe(nowMs);
    expect(pair.verification.preImageSha256.length).toBe(32);
  });

  test("tamperedResponseBytesThrowBadSignature", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    const tampered = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0xdeadbeef" }),
    );
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, tampered, t.headers, { chainId: CHAIN_ID, nowMs }),
    );
    expect(caught).toBeInstanceOf(BadSignature);
    if (caught instanceof BadSignature) {
      expect(caught.kind).toBe("BadSignature");
      expect(caught.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
      expect(caught.preImageSha256.length).toBe(32);
    }
  });

  test("chainIdMismatchThrowsBadSignature", async () => {
    const nowMs = BigInt(Date.now());
    // Signed with chain id "137", verified expecting "1" -> wrong pre-image.
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { signingChainId: "137" });
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, { chainId: "1", nowMs }),
    );
    expect(caught).toBeInstanceOf(BadSignature);
  });

  test("invalidChainIdThrowsAtEntry", async () => {
    // Fail-fast: an invalid configured chain id rejects with InvalidChainId
    // before any header parsing — even with completely empty headers.
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    await expect(
      verifyResponse(t.requestBytes, t.responseBytes, {}, { chainId: "", nowMs }),
    ).rejects.toBeInstanceOf(InvalidChainId);
    await expect(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, { chainId: "a b", nowMs }),
    ).rejects.toBeInstanceOf(InvalidChainId);
  });

  test("missingSignatureHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Signature"];
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Signature");
    }
  });

  test("missingTimestampHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Timestamp"];
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Timestamp");
    }
  });

  test("missingPubkeyHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Pubkey"];
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Pubkey");
    }
  });

  const twice = (v: string) => `${v}, ${v}`;
  test.each([
    { label: "a short vRPC-Signature", name: "vRPC-Signature", value: () => "0xnotcorrectlength" },
    { label: "a short vRPC-Pubkey", name: "vRPC-Pubkey", value: () => "deadbeef" },
    { label: "a non-numeric vRPC-Timestamp", name: "vRPC-Timestamp", value: () => "nope" },
    {
      label: "a vRPC-Timestamp above u64",
      name: "vRPC-Timestamp",
      value: () => (1n << 64n).toString(),
    },
    { label: "a repeated vRPC-Signature", name: "vRPC-Signature", value: twice },
    { label: "a repeated vRPC-Pubkey", name: "vRPC-Pubkey", value: twice },
    { label: "a repeated vRPC-Timestamp", name: "vRPC-Timestamp", value: twice },
    { label: "a repeated vRPC-NodeId", name: "vRPC-NodeId", value: () => "n1, n2" },
    { label: "an empty vRPC-NodeId", name: "vRPC-NodeId", value: () => "" },
  ])("$label throws MalformedHeader", async ({ name, value }) => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { nodeId: "n1" });
    t.headers[name] = value(t.headers[name] ?? "");
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, { chainId: CHAIN_ID, nowMs }),
    );
    expect(caught).toBeInstanceOf(MalformedHeader);
    expect((caught as MalformedHeader).headerName).toBe(name);
  });

  test("timestampAtU64MaxIsNotMalformed", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    t.headers["vRPC-Timestamp"] = ((1n << 64n) - 1n).toString();
    await expect(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, { chainId: CHAIN_ID, nowMs }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  test("staleTimestampPastThrowsStaleTimestamp", async () => {
    const nowMs = BigInt(Date.now());
    const staleMs = nowMs - 120_000n;
    const t = await signTriple(REQUEST, RESPONSE, staleMs);
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.allowedWindowMs).toBe(60_000);
      // Deterministic clock: skew is exactly -120_000.
      expect(caught.skewMs).toBe(-120_000n);
    }
  });

  test("staleTimestampFutureThrowsStaleTimestamp", async () => {
    const nowMs = BigInt(Date.now());
    const futureMs = nowMs + 120_000n;
    const t = await signTriple(REQUEST, RESPONSE, futureMs);
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.skewMs).toBe(120_000n);
    }
  });

  test("replayWindowZeroRejectsAnythingButExactMatch", async () => {
    const nowMs = BigInt(Date.now());
    const slightlyOldMs = nowMs - 1n;
    const t = await signTriple(REQUEST, RESPONSE, slightlyOldMs);
    const caught = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        replayWindowMs: 0,
        nowMs,
      }),
    );
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.allowedWindowMs).toBe(0);
    }
  });

  test("replayWindowZeroAcceptsExactMatch", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    const pair = await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
      chainId: CHAIN_ID,
      replayWindowMs: 0,
      nowMs,
    });
    expect(pair.verification.timestampMs).toBe(nowMs);
  });

  test("caseInsensitiveHeadersYieldIdenticalResults", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { nodeId: "node-abc" });

    // Variant A: as built (mixed-case vRPC-* Record).
    const mixedCase: Record<string, string> = { ...t.headers };

    // Variant B: lowercased ethers-style Record.
    const lowercased: Record<string, string> = {};
    for (const [k, v] of Object.entries(t.headers)) {
      lowercased[k.toLowerCase()] = v;
    }

    // Variant C: Headers object (fetch / viem).
    const headersObj = new Headers(t.headers);

    const shapes: ResponseHeaders[] = [mixedCase, lowercased, headersObj];
    const baseline = await verifyResponse(t.requestBytes, t.responseBytes, mixedCase, {
      chainId: CHAIN_ID,
      nowMs,
    });
    for (const h of shapes) {
      const r = await verifyResponse(t.requestBytes, t.responseBytes, h, {
        chainId: CHAIN_ID,
        nowMs,
      });
      expect(r.verification.signatureHex).toBe(baseline.verification.signatureHex);
      expect(r.verification.pubkeyHex).toBe(baseline.verification.pubkeyHex);
      expect(r.verification.timestampMs).toBe(baseline.verification.timestampMs);
      expect(r.nodeId).toBe("node-abc");
    }
  });

  test("nodeIdCapturedWhenHeaderPresent", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { nodeId: "region/node 7" });
    const pair = await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
      chainId: CHAIN_ID,
      nowMs,
    });
    expect(pair.nodeId).toBe("region/node 7");
  });

  test("nodeIdOmittedWhenHeaderAbsent", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    const pair = await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
      chainId: CHAIN_ID,
      nowMs,
    });
    expect(pair.nodeId).toBeUndefined();
    expect("nodeId" in pair).toBe(false);
  });
});

describe("header objects whose get returns undefined on a miss", () => {
  function mapHeaders(headers: Record<string, string>): ResponseHeaders {
    return new Map(Object.entries(headers)) as unknown as ResponseHeaders;
  }

  test("isSignedVrpcResponse is false for an unsigned response and true for a signed one", async () => {
    const t = await signTriple(REQUEST, RESPONSE, BigInt(Date.now()));
    expect(isSignedVrpcResponse(mapHeaders({ "content-type": "application/json" }))).toBe(false);
    expect(isSignedVrpcResponse(mapHeaders(t.headers))).toBe(true);
  });

  test("an absent vRPC-Signature is MissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Signature"];
    const err = await rejectionOf(
      verifyResponse(t.requestBytes, t.responseBytes, mapHeaders(t.headers), {
        chainId: CHAIN_ID,
        nowMs,
      }),
    );
    expect(err).toBeInstanceOf(MissingHeader);
    expect((err as MissingHeader).headerName).toBe("vRPC-Signature");
  });
});
