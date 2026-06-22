import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { describe, expect, test } from "vitest";

import { BadSignature, MalformedHeader, MissingHeader, StaleTimestamp } from "../src/errors";
import { buildPreImage } from "../src/preimage";
import { type ResponseHeaders, verifyResponse } from "../src/verify";

const TEST_SEED = new Uint8Array(32).fill(0x42);
const CHAIN_ID = 1n;

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

interface SignedTriple {
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  headers: Record<string, string>;
}

/**
 * Sign a (request, response) pair with TEST_SEED over the canonical 80-byte
 * pre-image and emit the matching `vRPC-*` headers. No fetch / no
 * VerifierClient — drives `verifyResponse` directly (CORE-02 unit, TEST-01).
 */
async function signTriple(
  request: string,
  response: string,
  timestampMs: bigint,
  opts: { signingChainId?: bigint; nodeId?: string } = {},
): Promise<SignedTriple> {
  const requestBytes = new TextEncoder().encode(request);
  const responseBytes = new TextEncoder().encode(response);
  const preImage = buildPreImage(
    opts.signingChainId ?? CHAIN_ID,
    requestBytes,
    responseBytes,
    timestampMs,
  );
  const signature = await signAsync(preImage, TEST_SEED);
  const pubkey = await getPublicKeyAsync(TEST_SEED);
  const headers: Record<string, string> = {
    "vRPC-Signature": `0x${toHex(signature)}`,
    "vRPC-Timestamp": timestampMs.toString(),
    "vRPC-Pubkey": `0x${toHex(pubkey)}`,
  };
  if (opts.nodeId !== undefined) {
    headers["vRPC-NodeId"] = opts.nodeId;
  }
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
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, tampered, t.headers, { chainId: CHAIN_ID, nowMs });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BadSignature);
    if (caught instanceof BadSignature) {
      expect(caught.kind).toBe("BadSignature");
      expect(caught.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
      expect(caught.preImageSha256.length).toBe(32);
    }
  });

  test("chainIdMismatchThrowsBadSignature", async () => {
    const nowMs = BigInt(Date.now());
    // Signed with chain id 137n, verified expecting 1n -> wrong pre-image.
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { signingChainId: 137n });
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, { chainId: 1n, nowMs });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BadSignature);
  });

  test("missingSignatureHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Signature"];
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Signature");
    }
  });

  test("missingTimestampHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Timestamp"];
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Timestamp");
    }
  });

  test("missingPubkeyHeaderThrowsMissingHeader", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    delete t.headers["vRPC-Pubkey"];
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Pubkey");
    }
  });

  test("malformedSignatureHexThrowsMalformed", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    t.headers["vRPC-Signature"] = "0xnotcorrectlength";
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Signature");
    }
  });

  test("malformedPubkeyHexThrowsMalformed", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    t.headers["vRPC-Pubkey"] = "deadbeef";
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Pubkey");
    }
  });

  test("malformedTimestampNotNumericThrowsMalformed", async () => {
    const nowMs = BigInt(Date.now());
    const t = await signTriple(REQUEST, RESPONSE, nowMs);
    t.headers["vRPC-Timestamp"] = "nope";
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Timestamp");
    }
  });

  test("staleTimestampPastThrowsStaleTimestamp", async () => {
    const nowMs = BigInt(Date.now());
    const staleMs = nowMs - 120_000n;
    const t = await signTriple(REQUEST, RESPONSE, staleMs);
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
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
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.skewMs).toBe(120_000n);
    }
  });

  test("replayWindowZeroRejectsAnythingButExactMatch", async () => {
    const nowMs = BigInt(Date.now());
    const slightlyOldMs = nowMs - 1n;
    const t = await signTriple(REQUEST, RESPONSE, slightlyOldMs);
    let caught: unknown;
    try {
      await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
        chainId: CHAIN_ID,
        replayWindowMs: 0,
        nowMs,
      });
    } catch (err) {
      caught = err;
    }
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
    const t = await signTriple(REQUEST, RESPONSE, nowMs, { nodeId: "node-xyz" });
    const pair = await verifyResponse(t.requestBytes, t.responseBytes, t.headers, {
      chainId: CHAIN_ID,
      nowMs,
    });
    expect(pair.nodeId).toBe("node-xyz");
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
