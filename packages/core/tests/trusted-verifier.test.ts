import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { AttestationError, EMPTY_ALLOWLIST } from "@ankr.com/dstack-verify";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";

import { buildPreImage } from "../src/preimage";
import {
  buildVerifyPolicy,
  DEFAULT_PUBKEY_CACHE_TTL_MS,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "../src/trusted-verifier";
import type { ResponseHeaders } from "../src/verify";

const SHARK_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const CHAIN_ID = 42161n;
const TEST_SEED = new Uint8Array(32).fill(0x42);
const NONCE = new Uint8Array(32).fill(0x07);
const NOW = 1_000_000;

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Build a real Ed25519-signed (requestBytes, responseBytes, headers) triple that
 * `verifyResponse` accepts. `verify()` consumes the triple directly — only the
 * attestation GET hits `fetch`, so the signed-POST leg of anchor.test.ts is
 * unnecessary here.
 */
async function signedPair(): Promise<{
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  headers: ResponseHeaders;
}> {
  const requestBytes = new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
  );
  const responseBytes = new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x12345" }),
  );
  // Sign with a wall-clock timestamp so verifyResponse's replay window (which
  // uses Date.now(), not the seam's injected cache clock) accepts it.
  const ts = BigInt(Date.now());
  const preImage = buildPreImage(CHAIN_ID, requestBytes, responseBytes, ts);
  const signature = await signAsync(preImage, TEST_SEED);
  const pubkey = await getPublicKeyAsync(TEST_SEED);
  const headers: Record<string, string> = {
    "vRPC-Signature": `0x${toHex(signature)}`,
    "vRPC-Timestamp": ts.toString(),
    "vRPC-Pubkey": `0x${toHex(pubkey)}`,
    "vRPC-NodeId": "node-abc",
  };
  return { requestBytes, responseBytes, headers };
}

/**
 * Like {@link signedPair} but WITHOUT the `vRPC-NodeId` header. Absent nodeId no
 * longer throws — the seam must fetch the attestation without a `node_id` query
 * param and still verify + cache (the endpoint decides; fail-closed propagates
 * only if the fetch itself errors).
 */
async function signedPairNoNodeId(): Promise<{
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  headers: ResponseHeaders;
}> {
  const { requestBytes, responseBytes, headers } = await signedPair();
  const { "vRPC-NodeId": _omit, ...rest } = headers as Record<string, string>;
  return { requestBytes, responseBytes, headers: rest };
}

interface AttMockState {
  fetch: typeof fetch;
  attGetCount: number;
  lastUrl: string | undefined;
}

/** Mock only the attestation GET leg; count how many times it is hit. */
function installAttestationMock(): AttMockState {
  const state: AttMockState = {
    fetch: (() => {}) as unknown as typeof fetch,
    attGetCount: 0,
    lastUrl: undefined,
  };
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
      state.lastUrl = url;
      const attPubkey = await getPublicKeyAsync(TEST_SEED);
      const body = {
        quote: { quote: "00", event_log: "00", report_data: "00", vm_config: "" },
        pubkey: `0x${toHex(attPubkey)}`,
        composeHash: "deadbeef",
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
  state.fetch = impl as typeof fetch;
  return state;
}

function baseOpts(overrides: Partial<TrustedVerifierOptions> = {}): TrustedVerifierOptions {
  return {
    chainId: CHAIN_ID,
    replayWindowMs: 60_000,
    attestationUrl: `${SHARK_BASE}/${CHAIN}_vrpc/attestation`,
    allowlist: EMPTY_ALLOWLIST,
    now: () => NOW,
    nonceSource: () => NONCE,
    ...overrides,
  };
}

describe("TrustedVerifier / trust seam", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("buildsPolicy", async () => {
    const pubkeyHex = `0x${toHex(await getPublicKeyAsync(TEST_SEED))}`;
    const policy = buildVerifyPolicy(baseOpts(), pubkeyHex, NONCE);
    expect(policy.allowInsecureMock).toBe(true);
    expect(policy.binding.expectedPubkey).toBe(pubkeyHex);
    expect(policy.binding.expectedNonce).toBe(toHex(NONCE));
    expect(policy.allowlist).toBe(EMPTY_ALLOWLIST);
  });

  test("failClosedNotCached", async () => {
    const mock = installAttestationMock();
    const pair = await signedPair();
    const tv = new TrustedVerifier(
      baseOpts({
        fetch: mock.fetch,
        verifyAttestation: async () => {
          throw new AttestationError("CHK-MOCK", "stub fail");
        },
      }),
    );

    let caught: unknown;
    try {
      await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestationError);

    // pubkey NOT cached → a second verify re-walks the attestation path.
    let caught2: unknown;
    try {
      await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    } catch (err) {
      caught2 = err;
    }
    expect(caught2).toBeInstanceOf(AttestationError);
    expect(mock.attGetCount).toBeGreaterThanOrEqual(2);
  });

  // ── Happy-path suite: real mock verifyDstackAttestation (allowInsecureMock
  // hard-set true by buildVerifyPolicy) → no verifyAttestation override. ──────

  test("cacheMissFetchesAndVerifies", async () => {
    // FLOW-03: unknown pubkey → attestation fetched + verified → VerifiedPair.
    const mock = installAttestationMock();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    const expectedPubkey = `0x${toHex(await getPublicKeyAsync(TEST_SEED))}`;
    expect(verified.verification.pubkeyHex).toBe(expectedPubkey);
    expect(mock.attGetCount).toBe(1);
  });

  test("absentNodeIdFetchesWithoutNodeIdAndVerifies", async () => {
    // Absent vRPC-NodeId no longer throws MissingHeader: the seam fetches the
    // attestation WITHOUT a node_id query param, verifies, and caches the pubkey.
    const mock = installAttestationMock();
    const pair = await signedPairNoNodeId();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    const expectedPubkey = `0x${toHex(await getPublicKeyAsync(TEST_SEED))}`;
    expect(verified.verification.pubkeyHex).toBe(expectedPubkey);
    expect(mock.attGetCount).toBe(1);
    // Fetched WITHOUT node_id.
    expect(mock.lastUrl).toContain("?nonce=");
    expect(mock.lastUrl).not.toContain("node_id=");

    // Pubkey cached → a second verify within TTL skips the attestation fetch.
    mock.attGetCount = 0;
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(0);
  });

  test("cacheHit", async () => {
    // FLOW-04: a fresh known pubkey skips the attestation fetch entirely.
    const mock = installAttestationMock();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);

    // Reset the counter; a second verify within TTL must NOT fetch.
    mock.attGetCount = 0;
    const second = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(second.verification.pubkeyHex).toBe(`0x${toHex(await getPublicKeyAsync(TEST_SEED))}`);
    expect(mock.attGetCount).toBe(0);
  });

  test("knownVsUnknown", async () => {
    // FLOW-01: first verify (unknown) attests (counter ++), second (known,
    // within TTL) routes through the cache (counter unchanged).
    const mock = installAttestationMock();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1); // miss path

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1); // hit path, no extra fetch
  });

  test("expiredReVerifies", async () => {
    // FLOW-02: advancing the injected clock past TTL forces a re-verify — a
    // cached pubkey is NOT trusted forever (no stale-trust). No real sleep.
    const mock = installAttestationMock();
    const pair = await signedPair();
    const ttlMs = 5_000;
    let fakeT = NOW;
    const tv = new TrustedVerifier(
      baseOpts({ fetch: mock.fetch, pubkeyCacheTtlMs: ttlMs, now: () => fakeT }),
    );

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1); // initial verify warms the cache

    // Still within TTL → cache hit, no fetch.
    fakeT += ttlMs - 1;
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);

    // Past TTL → entry expired → re-verify (counter increments again).
    fakeT += 2;
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(2);
  });

  test("ttlDefaultIsOneHour", async () => {
    // No pubkeyCacheTtlMs → DEFAULT_PUBKEY_CACHE_TTL_MS (1h): a < 1h shift is a
    // hit, a > 1h shift re-verifies.
    const mock = installAttestationMock();
    const pair = await signedPair();
    let fakeT = NOW;
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, now: () => fakeT }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);

    fakeT += DEFAULT_PUBKEY_CACHE_TTL_MS - 1; // < 1h → still fresh
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);

    fakeT += 2; // now > 1h since cache → expired
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(2);
  });
});
