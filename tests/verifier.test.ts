import { describe, expect, test } from "bun:test";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";

import { BadSignature, MalformedHeader, MissingHeader, StaleTimestamp } from "../src/errors";
import { buildPreImage } from "../src/preimage";
import { VerifierClient } from "../src/verifier";

const TEST_URL = "http://test.local:8545/";
const TEST_SEED = new Uint8Array(32).fill(0x42);

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

interface MockOverrides {
  /** Replace the response body bytes the SDK will see (signature stays computed over `signedBody`). */
  responseBodyOverride?: Uint8Array;
  /** Force a specific `vRPC-Timestamp` header (ms as string). */
  timestampMsOverride?: string;
  /** Drop one or more headers entirely. */
  dropHeaders?: Array<"vRPC-Signature" | "vRPC-Timestamp" | "vRPC-Pubkey">;
  /** Replace a single header value. */
  headerOverrides?: Partial<Record<"vRPC-Signature" | "vRPC-Timestamp" | "vRPC-Pubkey", string>>;
  /** Override the chainId baked into the signature. Defaults to opts.chainId. */
  signingChainIdOverride?: bigint;
}

/**
 * Build a deterministic mock `fetch` that signs the response with TEST_SEED
 * over the canonical 80-byte pre-image. The mock also records the request bodies it saw
 * so tests can assert on JSON-RPC id auto-increment.
 */
function makeMockFetch(
  signedBody: Uint8Array,
  chainId: bigint,
  timestampMs: bigint,
  overrides: MockOverrides = {},
): { fetch: typeof fetch; requestsSeen: Uint8Array[] } {
  const requestsSeen: Uint8Array[] = [];

  const fetchImpl = async (_input: string | URL, init?: RequestInit): Promise<Response> => {
    // Capture the request body for assertions.
    let reqBytes: Uint8Array;
    const body = init?.body;
    if (body instanceof Uint8Array) {
      reqBytes = body;
    } else if (typeof body === "string") {
      reqBytes = new TextEncoder().encode(body);
    } else if (body instanceof ArrayBuffer) {
      reqBytes = new Uint8Array(body);
    } else {
      reqBytes = new Uint8Array(0);
    }
    requestsSeen.push(reqBytes);

    // Sign the (intended) signed body — not the override body, that's the whole point.
    const signingChainId = overrides.signingChainIdOverride ?? chainId;
    const preImage = buildPreImage(signingChainId, reqBytes, signedBody, timestampMs);
    const signature = await signAsync(preImage, TEST_SEED);
    const pubkey = await getPublicKeyAsync(TEST_SEED);

    const baseHeaders: Record<string, string> = {
      "content-type": "application/json",
      "vRPC-Signature": `0x${toHex(signature)}`,
      "vRPC-Timestamp": overrides.timestampMsOverride ?? timestampMs.toString(),
      "vRPC-Pubkey": `0x${toHex(pubkey)}`,
    };
    for (const drop of overrides.dropHeaders ?? []) {
      delete baseHeaders[drop];
    }
    for (const [name, value] of Object.entries(overrides.headerOverrides ?? {})) {
      baseHeaders[name] = value;
    }

    const responseBytes = overrides.responseBodyOverride ?? signedBody;
    return new Response(responseBytes, { status: 200, headers: baseHeaders });
  };

  return { fetch: fetchImpl as typeof fetch, requestsSeen };
}

function makeSignedJsonRpcBody(id: number, result: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id, result }));
}

describe("VerifierClient", () => {
  test("happyPathReturnsVerifiedResponse", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const responseBody = makeSignedJsonRpcBody(1, "0x12345");
    const { fetch: mockFetch } = makeMockFetch(responseBody, chainId, nowMs);

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    const verified = await client.call<string>("eth_blockNumber", []);

    expect(verified.result).toBe("0x12345");
    expect(verified.raw.request).toBeInstanceOf(Uint8Array);
    expect(verified.raw.response).toBeInstanceOf(Uint8Array);
    expect(verified.raw.response.length).toBe(responseBody.length);
    expect(verified.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(verified.verification.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(typeof verified.verification.timestampMs).toBe("bigint");
    expect(verified.verification.timestampMs).toBe(nowMs);
    expect(verified.verification.preImageSha256.length).toBe(32);
  });

  test("tamperedResponseBodyThrowsBadSignature", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const signedBody = makeSignedJsonRpcBody(1, "0x12345");
    // Same shape, different value — body A signed, body B served.
    const tamperedBody = makeSignedJsonRpcBody(1, "0xdeadbeef");
    const { fetch: mockFetch } = makeMockFetch(signedBody, chainId, nowMs, {
      responseBodyOverride: tamperedBody,
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call<string>("eth_blockNumber", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BadSignature);
    if (caught instanceof BadSignature) {
      expect(caught.kind).toBe("BadSignature");
      expect(caught.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
      expect(caught.pubkeyHex).toMatch(/^0x[0-9a-f]{64}$/);
      expect(caught.preImageSha256.length).toBe(32);
    }
  });

  test("missingSignatureHeaderThrowsMissingHeader", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      dropHeaders: ["vRPC-Signature"],
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Signature");
    }
  });

  test("missingTimestampHeaderThrowsMissingHeader", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      dropHeaders: ["vRPC-Timestamp"],
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Timestamp");
    }
  });

  test("missingPubkeyHeaderThrowsMissingHeader", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      dropHeaders: ["vRPC-Pubkey"],
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-Pubkey");
    }
  });

  test("malformedSignatureHexThrowsMalformed", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      headerOverrides: { "vRPC-Signature": "0xnotcorrectlength" },
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Signature");
    }
  });

  test("malformedPubkeyHexThrowsMalformed", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      headerOverrides: { "vRPC-Pubkey": "deadbeef" },
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Pubkey");
    }
  });

  test("malformedTimestampNotNumericThrowsMalformed", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs, {
      headerOverrides: { "vRPC-Timestamp": "nope" },
    });

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedHeader);
    if (caught instanceof MalformedHeader) {
      expect(caught.headerName).toBe("vRPC-Timestamp");
    }
  });

  test("staleTimestampPastThrowsStaleTimestamp", async () => {
    const chainId = 1n;
    const staleMs = BigInt(Date.now()) - 120_000n;
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, staleMs);

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.allowedWindowMs).toBe(60_000);
      // Skew should be ≈ -120_000 (within ±1500ms of test execution slop).
      expect(Number(caught.skewMs)).toBeGreaterThan(-121_500);
      expect(Number(caught.skewMs)).toBeLessThan(-118_500);
    }
  });

  test("staleTimestampFutureThrowsStaleTimestamp", async () => {
    const chainId = 1n;
    const futureMs = BigInt(Date.now()) + 120_000n;
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, futureMs);

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.allowedWindowMs).toBe(60_000);
      expect(Number(caught.skewMs)).toBeGreaterThan(118_500);
      expect(Number(caught.skewMs)).toBeLessThan(121_500);
    }
  });

  test("replayWindowZeroRejectsAnythingButExactMatch", async () => {
    const chainId = 1n;
    const slightlyOldMs = BigInt(Date.now()) - 1n;
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, slightlyOldMs);

    const client = new VerifierClient(TEST_URL, {
      chainId,
      replayWindowMs: 0,
      fetch: mockFetch,
    });
    let caught: unknown;
    try {
      await client.call("m", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(StaleTimestamp);
    if (caught instanceof StaleTimestamp) {
      expect(caught.allowedWindowMs).toBe(0);
    }
  });

  test("jsonRpcIdAutoIncrements", async () => {
    const chainId = 1n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "ok");
    const { fetch: mockFetch, requestsSeen } = makeMockFetch(body, chainId, nowMs);

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    await client.call("a", []);
    await client.call("b", []);
    await client.call("c", []);

    expect(requestsSeen.length).toBe(3);
    const decoded = requestsSeen.map((bytes) => JSON.parse(new TextDecoder().decode(bytes)));
    const ids = decoded.map((d) => d.id);
    // All three are unique.
    expect(new Set(ids).size).toBe(3);
    // Envelope shape sanity.
    for (const d of decoded) {
      expect(d.jsonrpc).toBe("2.0");
      expect(typeof d.method).toBe("string");
      expect(Array.isArray(d.params)).toBe(true);
    }
  });

  test("verifierClientOptionsAcceptsChainIdBigint", async () => {
    // chainId 137n must flow through to the signed pre-image.
    const chainId = 137n;
    const nowMs = BigInt(Date.now());
    const body = makeSignedJsonRpcBody(1, "0xabc");
    const { fetch: mockFetch } = makeMockFetch(body, chainId, nowMs);

    const client = new VerifierClient(TEST_URL, { chainId, fetch: mockFetch });
    const verified = await client.call<string>("eth_chainId", []);
    expect(verified.result).toBe("0xabc");

    // Cross-check: if the mock signs with chainId 137n but the client expects 1n,
    // the signature verify must fail.
    const { fetch: wrongChainFetch } = makeMockFetch(body, 137n, nowMs, {
      signingChainIdOverride: 137n,
    });
    const wrongClient = new VerifierClient(TEST_URL, { chainId: 1n, fetch: wrongChainFetch });
    let caught: unknown;
    try {
      await wrongClient.call("eth_chainId", []);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BadSignature);
  });

  test("constructorRejectsNonHttpUrl", () => {
    expect(() => new VerifierClient("file:///etc/passwd", { chainId: 1n })).toThrow(TypeError);
    expect(() => new VerifierClient("ftp://example.com/", { chainId: 1n })).toThrow(TypeError);
    // http and https both accepted.
    expect(() => new VerifierClient("http://example.com/", { chainId: 1n })).not.toThrow();
    expect(() => new VerifierClient("https://example.com/", { chainId: 1n })).not.toThrow();
  });
});
