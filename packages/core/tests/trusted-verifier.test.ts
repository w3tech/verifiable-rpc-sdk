import { AttestationError } from "@w3tech.io/dstack-verify";
import {
  attestationAnswer,
  attestationStub,
  CHAIN_ID,
  collectingLogger,
  mockHardwareVerifier,
  rejectionOf,
  signResponse,
  TEST_PUBKEY_HEX,
  TEST_SEED,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { ATTESTATION_TIMEOUT_MS } from "../src/attestation";
import {
  AttestationCorrelationError,
  AttestationFailed,
  AttestationUnavailable,
  InvalidOption,
  VerificationError,
} from "../src/errors";
import type { Logger } from "../src/logger";
import { DEFAULT_PUBKEY_CACHE_TTL_MS } from "../src/options";
import { TrustedVerifier, type TrustedVerifierOptions } from "../src/trusted-verifier";
import type { ResponseHeaders } from "../src/verify";

const RPC_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";

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
async function signedPair(
  seed: Uint8Array = TEST_SEED,
  nodeId = "node-abc",
): Promise<{
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
  // Default timestamp is `Date.now()` per call: under fake timers re-signing right
  // before a verify keeps it in the replay window past the cache TTL.
  const headers = signResponse(CHAIN_ID, requestBytes, responseBytes, { seed, nodeId });
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

function baseOpts(overrides: Partial<TrustedVerifierOptions> = {}): TrustedVerifierOptions {
  return {
    chainId: CHAIN_ID,
    replayWindowMs: 60_000,
    attestationUrl: `${RPC_BASE}/${CHAIN}_vrpc/attestation`,
    // Hardware verification is mandatory + defaults to a network cloud POST;
    // inject the no-network mock so the seam tests never touch the network.
    hardwareVerifier: mockHardwareVerifier(),
    ...overrides,
  };
}

describe("TrustedVerifier / trust seam", () => {
  test("constructor checks its options: a missing chain id is InvalidOption", () => {
    const err = thrownBy(() => new TrustedVerifier(baseOpts({ chainId: undefined as never })));
    expect(err).toBeInstanceOf(InvalidOption);
    expect(err).toMatchObject({ option: "chainId", executed: "no" });
  });

  test("constructor accepts the largest replay window and a 1 ms TTL", () => {
    expect(
      () =>
        new TrustedVerifier(
          baseOpts({ replayWindowMs: Number.MAX_SAFE_INTEGER, pubkeyCacheTtlMs: 1 }),
        ),
    ).not.toThrow();
  });

  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("failClosedNotCached", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    const tv = new TrustedVerifier(
      baseOpts({
        fetch: mock.fetch,
        hardwareVerifier: mockHardwareVerifier({
          fail: new AttestationError("CHK-P1", "stub fail"),
        }),
      }),
    );

    const caught = await rejectionOf(
      tv.verify(pair.requestBytes, pair.responseBytes, pair.headers),
    );
    // core re-wraps the leaf AttestationError into its VerificationError family;
    // the original leaf error is preserved as `cause`.
    expect(caught).toBeInstanceOf(AttestationFailed);
    expect(caught).toBeInstanceOf(VerificationError);
    expect((caught as AttestationFailed).kind).toBe("Attestation");
    expect((caught as { cause?: unknown }).cause).toBeInstanceOf(AttestationError);

    // pubkey NOT cached → a second verify re-walks the attestation path.
    const again = rejectionOf(tv.verify(pair.requestBytes, pair.responseBytes, pair.headers));
    expect(await again).toBeInstanceOf(AttestationFailed);
    expect(mock.urls.length).toBeGreaterThanOrEqual(2);
  });

  test("attestationStatus500IsUnavailableAndNotCached", async () => {
    const mock = attestationStub();
    mock.failNext = 500;
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const err = await rejectionOf(tv.verify(pair.requestBytes, pair.responseBytes, pair.headers));
    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toMatchObject({ reason: "status", status: 500 });
    expect(mock.urls.length).toBe(1);

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(verified.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
    expect(mock.urls.length).toBe(2);
  });

  test.each([
    [
      "a throwing fetch",
      async () => {
        throw new TypeError("fetch failed: https://k/SECRET");
      },
      { reason: "transport" },
    ],
    [
      "a redirect",
      async (_url: string, init?: RequestInit) =>
        new Response(null, { status: init?.redirect === "manual" ? 302 : 200 }),
      { reason: "status", status: 302 },
    ],
  ])("%s is AttestationUnavailable, not cached, global fetch untouched", async (_, send, fields) => {
    const global = vi.spyOn(globalThis, "fetch");
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: send as typeof fetch }));
    for (let i = 0; i < 2; i++) {
      const err = await rejectionOf(tv.verify(pair.requestBytes, pair.responseBytes, pair.headers));
      expect(err).toBeInstanceOf(AttestationUnavailable);
      expect(err).toMatchObject(fields);
      expect(`${String(err)} ${String((err as Error).cause)}`).not.toContain("SECRET");
    }
    expect(global).not.toHaveBeenCalled();
  });

  test("a quote for another key is rejected before the hardware verifier", async () => {
    const mock = attestationStub();
    mock.seed = new Uint8Array(32).fill(0x09);
    const hardwareVerifier = mockHardwareVerifier();
    const verifyHardware = vi.spyOn(hardwareVerifier, "verifyHardware");
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, hardwareVerifier }));

    const err = await rejectionOf(tv.verify(pair.requestBytes, pair.responseBytes, pair.headers));
    expect(err).toBeInstanceOf(AttestationCorrelationError);
    expect(verifyHardware).not.toHaveBeenCalled();
  });

  test("an uppercase attested pubkey equal to the signer is accepted", async () => {
    const upper = (async (url: string) => {
      const body = (await attestationAnswer(url).json()) as { pubkey: string };
      return Response.json({ ...body, pubkey: `0x${body.pubkey.slice(2).toUpperCase()}` });
    }) as typeof fetch;
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: upper }));

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(verified.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
  });

  test("cacheMissFetchesAndVerifies", async () => {
    // Unknown pubkey → attestation fetched + verified → VerifiedPair.
    const mock = attestationStub();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    expect(verified.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
    expect(mock.urls.length).toBe(1);
  });

  test("absentNodeIdFetchesWithoutNodeIdAndVerifies", async () => {
    // Absent vRPC-NodeId no longer throws MissingHeader: the seam fetches the
    // attestation WITHOUT a node_id query param, verifies, and caches the pubkey.
    const mock = attestationStub();
    const pair = await signedPairNoNodeId();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    expect(verified.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
    expect(mock.urls.length).toBe(1);
    // Fetched WITHOUT node_id.
    expect(mock.urls.at(-1)).toContain("?nonce=");
    expect(mock.urls.at(-1)).not.toContain("node_id=");

    // Pubkey cached → a second verify within TTL skips the attestation fetch.
    mock.urls.length = 0;
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(0);
  });

  test("cacheHit", async () => {
    // A fresh known pubkey skips the attestation fetch entirely.
    const mock = attestationStub();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(1);

    // Reset the counter; a second verify within TTL must NOT fetch.
    mock.urls.length = 0;
    const second = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(second.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
    expect(mock.urls.length).toBe(0);
  });

  test("knownVsUnknown", async () => {
    // First verify (unknown) attests (counter ++), second (known,
    // within TTL) routes through the cache (counter unchanged).
    const mock = attestationStub();
    const pair = await signedPair();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(1); // miss path

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(1); // hit path, no extra fetch
  });

  test("expiredReVerifies", async () => {
    // A cached pubkey is NOT trusted forever (no stale-trust). Uses a
    // small REAL ttl + a real wait — vitest fake timers do not drive lru-cache's
    // TTL clock (see `sleep` note). Companion `expiryTestIsClockDependent` proves
    // that WITHOUT the wait the same 2nd verify is a hit (red without advancing).
    const mock = attestationStub();
    const ttlMs = 100;
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheTtlMs: ttlMs }));

    const initial = await signedPair();
    await tv.verify(initial.requestBytes, initial.responseBytes, initial.headers);
    expect(mock.urls.length).toBe(1); // initial verify warms the cache

    // Wait past the TTL → entry expired → re-verify (counter increments again).
    await sleep(ttlMs * 3);
    const after = await signedPair();
    await tv.verify(after.requestBytes, after.responseBytes, after.headers);
    expect(mock.urls.length).toBe(2);
  });

  test("expiryTestIsClockDependent", async () => {
    // Proves expiredReVerifies is meaningful: with the SAME small ttl but WITHOUT
    // waiting, the 2nd verify is a cache hit (no extra fetch). So the expiry test
    // genuinely depends on the elapsed clock — it would be red without the wait.
    const mock = attestationStub();
    const ttlMs = 100;
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheTtlMs: ttlMs }));

    const pair = await signedPair();
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(1);

    // No wait → still fresh → cache hit, NO second fetch.
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(mock.urls.length).toBe(1);
  });

  test("ttlDefaultIsOneHour", async () => {
    // Default TTL constant is 1h. With no override, a short real wait stays well
    // within it → cache hit (no re-attest). The 1h boundary itself is asserted on
    // the constant; we don't sleep an hour. The short-ttl `expiredReVerifies`
    // test above proves the expiry branch.
    expect(DEFAULT_PUBKEY_CACHE_TTL_MS).toBe(3_600_000);

    const mock = attestationStub();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    const first = await signedPair();
    await tv.verify(first.requestBytes, first.responseBytes, first.headers);
    expect(mock.urls.length).toBe(1);

    await sleep(40); // ≪ 1h → still fresh
    const within = await signedPair();
    await tv.verify(within.requestBytes, within.responseBytes, within.headers);
    expect(mock.urls.length).toBe(1);
  });

  test("evictsOldestPastMax", async () => {
    // Bounded cache: with pubkeyCacheMax=2, verifying 3 distinct pubkeys evicts
    // the least-recently-used (the first) → re-accessing it re-attests.
    const mock = attestationStub();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, pubkeyCacheMax: 2 }));

    const seedA = new Uint8Array(32).fill(0x01);
    const seedB = new Uint8Array(32).fill(0x02);
    const seedC = new Uint8Array(32).fill(0x03);

    const verifyWith = async (seed: Uint8Array): Promise<void> => {
      mock.seed = seed;
      const p = await signedPair(seed);
      await tv.verify(p.requestBytes, p.responseBytes, p.headers);
    };

    await verifyWith(seedA); // miss
    await verifyWith(seedB); // miss
    await verifyWith(seedC); // miss → evicts A (LRU, max=2)
    expect(mock.urls.length).toBe(3);

    // A was evicted → re-attested; B and C are still resident → cache hits.
    await verifyWith(seedA);
    expect(mock.urls.length).toBe(4);
    await verifyWith(seedC);
    await verifyWith(seedB);
    expect(mock.urls.length).toBe(5); // B evicted when A re-entered; C still warm
  });
});

// ── Opt-in logger narration (Plan 02): all 11 events fire on a full MISS,
// redaction holds, the default path is silent, and a throwing logger never
// breaks verification. Uses the real verifyDstackAttestation (no override) +
// the no-network mockHardwareVerifier so the dstack field-check / hardware
// events fire offline. ───────────────────────────────────────────────────────
describe("TrustedVerifier / opt-in logger narration", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
    vi.restoreAllMocks();
  });

  /** All 11 dotted event names a full MISS verify is expected to emit. */
  const ALL_EVENTS = [
    "verify.start",
    "preimage.computed",
    "signature.checked",
    "timestamp.checked",
    "cache.lookup",
    "attestation.fetch",
    "attestation.received",
    "attestation.correlation",
    "attestation.fieldChecks",
    "hardware.verify",
    "cache.store",
  ];

  test("fullMissEmitsAllElevenEvents", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    const log = collectingLogger();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, logger: log }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    const names = log.calls.map((c) => c[0]);
    for (const event of ALL_EVENTS) {
      expect(names, `missing event: ${event}`).toContain(event);
    }
  });

  test("verifyStartLogsOnlyVrpcHeadersAndTruncatesReqRes", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    // Add credential + noise headers to the response so the vrpc-only filter is observable.
    const headers = {
      ...(pair.headers as Record<string, string>),
      authorization: "Bearer super-secret-token",
      "x-api-key": "key-abc123",
      "content-type": "application/json",
    };
    const log = collectingLogger();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, logger: log }));

    await tv.verify(pair.requestBytes, pair.responseBytes, headers);

    const start = log.calls.find((c) => c[0] === "verify.start")?.[1] as Record<string, unknown>;
    expect(start).toBeDefined();
    const loggedHeaders = start.headers as Record<string, string>;
    // Only vrpc-* headers are emitted; credential + non-vrpc headers are absent entirely.
    expect(loggedHeaders.authorization).toBeUndefined();
    expect(loggedHeaders["x-api-key"]).toBeUndefined();
    expect(loggedHeaders["content-type"]).toBeUndefined();
    expect(Object.keys(loggedHeaders).every((k) => k.toLowerCase().startsWith("vrpc-"))).toBe(true);
    expect(JSON.stringify(loggedHeaders)).not.toContain("super-secret-token");
    expect(JSON.stringify(loggedHeaders)).not.toContain("key-abc123");
    // req/res are truncated (truncateHex appends the ellipsis marker).
    expect(start.req as string).toContain("…");
    expect(start.res as string).toContain("…");
  });

  test("noSecretValueEverCollected", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    const headers = {
      ...(pair.headers as Record<string, string>),
      authorization: "Bearer super-secret-token",
      "x-api-key": "key-abc123",
    };
    const log = collectingLogger();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, logger: log }));

    await tv.verify(pair.requestBytes, pair.responseBytes, headers);

    // Scan EVERY collected event's data for the secret values.
    const dump = JSON.stringify(log.calls);
    expect(dump).not.toContain("super-secret-token");
    expect(dump).not.toContain("key-abc123");
  });

  test("hitPathEmitsCacheLookupHitAndSkipsAttestationFetch", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    const log = collectingLogger();
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, logger: log }));

    // First verify warms the cache (MISS).
    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    log.calls.length = 0; // reset; observe only the HIT verify

    const second = await signedPair();
    await tv.verify(second.requestBytes, second.responseBytes, second.headers);

    const lookup = log.calls.find((c) => c[0] === "cache.lookup")?.[1] as Record<string, unknown>;
    expect(lookup).toBeDefined();
    expect(lookup.hit).toBe(true);
    expect(lookup.note).toBe("cached → skip attestation");
    // No attestation fetch on a HIT.
    expect(log.calls.map((c) => c[0])).not.toContain("attestation.fetch");
  });

  test("silentPathNeverCallsConsoleDebug", async () => {
    const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
    const mock = attestationStub();
    const pair = await signedPair();
    // NO logger injected.
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch }));

    await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    expect(spy).not.toHaveBeenCalled();
  });

  test("throwingLoggerDoesNotBreakVerify", async () => {
    const mock = attestationStub();
    const pair = await signedPair();
    const throwing: Logger = {
      debug() {
        throw new Error("boom");
      },
    };
    const tv = new TrustedVerifier(baseOpts({ fetch: mock.fetch, logger: throwing }));

    // Verify must still resolve despite the throwing logger (safeLogger wrap).
    const verified = await tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);
    expect(verified.verification.pubkeyHex).toBe(TEST_PUBKEY_HEX);
  });
});

describe("TrustedVerifier / single attestation per pubkey", () => {
  const SEEDS: Record<string, Uint8Array> = {
    "node-abc": TEST_SEED,
    "node-b": new Uint8Array(32).fill(0x07),
  };

  afterEach(() => {
    vi.useRealTimers();
  });

  test.each([
    { name: "ten calls with one cold pubkey", nodes: Array(10).fill("node-abc"), gets: 1 },
    { name: "two cold pubkeys", nodes: ["node-abc", "node-b"], gets: 2 },
    {
      name: "ten calls with a failing attestation",
      nodes: Array(10).fill("node-abc"),
      gets: 1,
      failNext: 500,
    },
  ])("$name make $gets attestation GET(s); a failure is shared and not remembered", async ({
    nodes,
    gets,
    failNext,
  }) => {
    const stub = attestationStub();
    stub.failNext = failNext;
    const log = collectingLogger();
    const lookups = () => log.calls.filter(([event]) => event === "cache.lookup").length;
    // Answers once every call has missed the cache, with the quote of the requested node.
    const fetch = (async (url: string) => {
      while (lookups() < nodes.length) await sleep(1);
      stub.seed = SEEDS[new URL(url).searchParams.get("node_id") ?? ""] as Uint8Array;
      return stub.fetch(url);
    }) as typeof globalThis.fetch;
    const hardwareVerifier = mockHardwareVerifier();
    const verifyHardware = vi.spyOn(hardwareVerifier, "verifyHardware");
    const tv = new TrustedVerifier(baseOpts({ fetch, hardwareVerifier, logger: log }));
    const pairs = await Promise.all(nodes.map((node) => signedPair(SEEDS[node], node)));
    const verify = (pair: (typeof pairs)[number]) =>
      tv.verify(pair.requestBytes, pair.responseBytes, pair.headers);

    const results = await Promise.allSettled(pairs.map(verify));
    expect(stub.urls).toHaveLength(gets);
    if (failNext === undefined) {
      expect(results.every((r) => r.status === "fulfilled")).toBe(true);
      expect(verifyHardware).toHaveBeenCalledTimes(gets);
      return;
    }
    const reasons = new Set(results.map((r) => (r.status === "rejected" ? r.reason : r)));
    expect(reasons.size).toBe(1);
    expect([...reasons][0]).toBeInstanceOf(AttestationUnavailable);
    await verify(pairs[0] as (typeof pairs)[number]);
    await verify(pairs[0] as (typeof pairs)[number]);
    expect(stub.urls).toHaveLength(gets + 1);
  });

  const abortedBy = (signal: AbortSignal) =>
    new Promise<never>((_, reject) =>
      signal.addEventListener("abort", () => reject(signal.reason)),
    );

  test.each<[string, "fetch" | "hardware", (signal: AbortSignal) => Promise<unknown>]>([
    ["a fetch that never answers", "fetch", abortedBy],
    ["a hardware verifier that never settles", "hardware", () => new Promise(() => {})],
    [
      "a hardware verifier that succeeds after the deadline",
      "hardware",
      () => new Promise((resolve) => setTimeout(resolve, ATTESTATION_TIMEOUT_MS + 1_000)),
    ],
  ])("%s times out at the deadline and the next verify attests again", async (_, stage, stall) => {
    vi.useFakeTimers();
    const stub = attestationStub();
    const signals: AbortSignal[] = [];
    let stalled = () => {};
    const stalling = new Promise<void>((resolve) => {
      stalled = resolve;
    });
    const stallOnce = (signal: AbortSignal) => {
      stalled();
      return stall(signal);
    };
    const fetch = (async (url: string, init: RequestInit) => {
      signals.push(init.signal as AbortSignal);
      return stage === "fetch" && signals.length === 1
        ? stallOnce(init.signal as AbortSignal)
        : stub.fetch(url);
    }) as typeof globalThis.fetch;
    let hardwareCalls = 0;
    const hardwareVerifier = {
      async verifyHardware() {
        hardwareCalls += 1;
        if (stage === "hardware" && hardwareCalls === 1) await stallOnce(signals[0] as AbortSignal);
      },
    };
    const tv = new TrustedVerifier(baseOpts({ fetch, hardwareVerifier }));
    const first = await signedPair();

    const pending = rejectionOf(tv.verify(first.requestBytes, first.responseBytes, first.headers));
    await stalling;
    await vi.advanceTimersByTimeAsync(ATTESTATION_TIMEOUT_MS);
    const err = await pending;
    expect(err).toBeInstanceOf(AttestationUnavailable);
    expect(err).toMatchObject({ reason: "timeout" });
    expect(signals[0]?.aborted).toBe(true);

    await vi.advanceTimersByTimeAsync(1_000);
    const again = await signedPair();
    await tv.verify(again.requestBytes, again.responseBytes, again.headers);
    expect(signals).toHaveLength(2);
  });
});
