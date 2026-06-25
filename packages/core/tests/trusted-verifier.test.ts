import { AttestationError, EMPTY_ALLOWLIST } from "@ankr.com/dstack-verify";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { buildPreImage } from "../src/preimage";
import {
  buildVerifyPolicy,
  DEFAULT_PUBKEY_CACHE_TTL_MS,
  TrustedVerifier,
  type TrustedVerifierOptions,
} from "../src/trusted-verifier";
import type { ResponseHeaders } from "../src/verify";
import { mockHardwareVerifier } from "./support/mock-hardware-verifier";

const RPC_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const CHAIN_ID = 42161n;
const TEST_SEED = new Uint8Array(32).fill(0x42);
const NONCE = new Uint8Array(32).fill(0x07);

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Real-clock sleep. The TTL tests use a small real ttl + a real wait rather than
 * vitest fake timers: lru-cache reads its TTL clock from `performance.now()` and
 * debounces it (ttlResolution), and vitest's faked `performance.now` does NOT
 * actually drive lru-cache's expiry (verified — a faked-advance entry stays
 * `has() === true`). A short real wait is the only deterministic way to expire it.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Build a real Ed25519-signed (requestBytes, responseBytes, headers) triple that
 * `verifyResponse` accepts. `verify()` consumes the triple directly — only the
 * attestation GET hits `fetch`, so the signed-POST leg of anchor.test.ts is
 * unnecessary here.
 */
async function signedPair(seed: Uint8Array = TEST_SEED): Promise<{
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
  // Sign with the current `Date.now()` so verifyResponse's replay window accepts
  // it. Under vitest fake timers `Date` is faked, so re-signing right before a
  // verify keeps the timestamp in-window even after the clock has been advanced
  // past the cache TTL.
  const ts = BigInt(Date.now());
  const preImage = buildPreImage(CHAIN_ID, requestBytes, responseBytes, ts);
  const signature = await signAsync(preImage, seed);
  const pubkey = await getPublicKeyAsync(seed);
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
  /** Seed whose pubkey the mock echoes — set per request so correlation passes. */
  activeSeed: Uint8Array;
}

/** Mock only the attestation GET leg; count how many times it is hit. */
function installAttestationMock(): AttMockState {
  const state: AttMockState = {
    fetch: (() => {}) as unknown as typeof fetch,
    attGetCount: 0,
    lastUrl: undefined,
    activeSeed: TEST_SEED,
  };
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
      state.lastUrl = url;
      const attPubkey = await getPublicKeyAsync(state.activeSeed);
      // report_data is the 64-byte CHK-A1 pre-image pubkey(bare) ‖ nonce(bare):
      // the seam binds report_data[0:32]==pubkey and [32:64]==the fetch nonce
      // (baseOpts hard-sets nonceSource -> NONCE = 0x07*32). A bare "00" stub
      // fails CHK-A1's 128-hex shape gate.
      const reportData = `${toHex(attPubkey)}${toHex(NONCE)}`;
      const body = {
        quote: { quote: "00", event_log: "00", report_data: reportData, vm_config: "" },
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
    attestationUrl: `${RPC_BASE}/${CHAIN}_vrpc/attestation`,
    nonceSource: () => NONCE,
    // Hardware verification is mandatory + defaults to a network cloud POST;
    // inject the no-network mock so the seam tests never touch the network.
    hardwareVerifier: mockHardwareVerifier(),
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
    const policy = buildVerifyPolicy(pubkeyHex, NONCE);
    expect(policy.hardwareVerifier).toBeDefined();
    expect(policy.allowInsecureMock).toBeUndefined();
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
    // Unknown pubkey → attestation fetched + verified → VerifiedPair.
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
    // A fresh known pubkey skips the attestation fetch entirely.
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
    // First verify (unknown) attests (counter ++), second (known,
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
    // A cached pubkey is NOT trusted forever (no stale-trust). Uses a
    // small REAL ttl + a real wait — vitest fake timers do not drive lru-cache's
    // TTL clock (see `sleep` note). Companion `expiryTestIsClockDependent` proves
    // that WITHOUT the wait the same 2nd verify is a hit (red without advancing).
    const mock = installAttestationMock();
    const ttlMs = 100;
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheTtlMs: ttlMs }));

    const initial = await signedPair();
    await tv.verify(initial.requestBytes, initial.responseBytes, initial.headers);
    expect(mock.attGetCount).toBe(1); // initial verify warms the cache

    // Wait past the TTL → entry expired → re-verify (counter increments again).
    await sleep(ttlMs * 3);
    const after = await signedPair();
    await tv.verify(after.requestBytes, after.responseBytes, after.headers);
    expect(mock.attGetCount).toBe(2);
  });

  test("expiryTestIsClockDependent", async () => {
    // Proves expiredReVerifies is meaningful: with the SAME small ttl but WITHOUT
    // waiting, the 2nd verify is a cache hit (no extra fetch). So the expiry test
    // genuinely depends on the elapsed clock — it would be red without the wait.
    const mock = installAttestationMock();
    const ttlMs = 100;
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheTtlMs: ttlMs }));

    const pair = await signedPair();
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);

    // No wait → still fresh → cache hit, NO second fetch.
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.attGetCount).toBe(1);
  });

  test("ttlDefaultIsOneHour", async () => {
    // Default TTL constant is 1h. With no override, a short real wait stays well
    // within it → cache hit (no re-attest). The 1h boundary itself is asserted on
    // the constant; we don't sleep an hour. The short-ttl `expiredReVerifies`
    // test above proves the expiry branch.
    expect(DEFAULT_PUBKEY_CACHE_TTL_MS).toBe(3_600_000);

    const mock = installAttestationMock();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const first = await signedPair();
    await tv.verify(first.requestBytes, first.responseBytes, first.headers);
    expect(mock.attGetCount).toBe(1);

    await sleep(40); // ≪ 1h → still fresh
    const within = await signedPair();
    await tv.verify(within.requestBytes, within.responseBytes, within.headers);
    expect(mock.attGetCount).toBe(1);
  });

  test("evictsOldestPastMax", async () => {
    // Bounded cache: with pubkeyCacheMax=2, verifying 3 distinct pubkeys evicts
    // the least-recently-used (the first) → re-accessing it re-attests.
    const mock = installAttestationMock();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheMax: 2 }));

    const seedA = new Uint8Array(32).fill(0x01);
    const seedB = new Uint8Array(32).fill(0x02);
    const seedC = new Uint8Array(32).fill(0x03);

    const verifyWith = async (seed: Uint8Array): Promise<void> => {
      mock.activeSeed = seed;
      const p = await signedPair(seed);
      await tv.verify(p.requestBytes, p.responseBytes, p.headers);
    };

    await verifyWith(seedA); // miss
    await verifyWith(seedB); // miss
    await verifyWith(seedC); // miss → evicts A (LRU, max=2)
    expect(mock.attGetCount).toBe(3);

    // A was evicted → re-attested; B and C are still resident → cache hits.
    await verifyWith(seedA);
    expect(mock.attGetCount).toBe(4);
    await verifyWith(seedC);
    await verifyWith(seedB);
    expect(mock.attGetCount).toBe(5); // B evicted when A re-entered; C still warm
  });

  test("nonPositiveTtlThrows", () => {
    // A non-positive TTL is a config error — the ctor fails fast.
    expect(() => new TrustedVerifier(baseOpts({ pubkeyCacheTtlMs: 0 }))).toThrow(RangeError);
  });
});
