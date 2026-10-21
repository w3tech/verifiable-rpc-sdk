import { rejectionOf } from "@w3tech.io/vrpc-test-support";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { fetchAttestation } from "../src/attestation";
import { InvalidNonce } from "../src/errors";

const TEST_URL = "http://test.local:8545";
const TEST_ATTESTATION_URL = `${TEST_URL}/attestation`;
const MiB = 1_048_576;
const CHUNK = 65_536;

/**
 * Canonical hand-crafted golden fixture — mirrors the sidecar's Rust unit
 * test `attestation_response_nests_sdk_quote_and_renames_compose_hash`
 * byte-for-byte. The integration suite captures a real-simulator fixture
 * separately (`tests/fixtures/attestation-v0.1.0.json`).
 */
const GOLDEN_FIXTURE = {
  quote: {
    quote: "00010203",
    event_log: "04050607",
    report_data: "08090a0b",
    vm_config: "",
  },
  pubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
  composeHash: "deadbeef",
  app_compose: '{"manifest_version":2,"name":"demo"}',
};

interface MockState {
  urls: string[];
  headers: Array<Record<string, string> | undefined>;
}

function installMockFetch(body: unknown, extraHeaders: Record<string, string> = {}): MockState {
  const state: MockState = { urls: [], headers: [] };
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    state.urls.push(String(input));
    state.headers.push(init?.headers as Record<string, string> | undefined);
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json", ...extraHeaders },
    });
  }) as typeof fetch;
  return state;
}

describe("fetchAttestation", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("nonceMustBe32Bytes", async () => {
    // Install a fetch that throws synchronously — if validation isn't
    // synchronous, this sentinel will surface instead of InvalidNonce.
    globalThis.fetch = ((): Response => {
      throw new Error("fetch called — synchronous validation failed");
    }) as unknown as typeof fetch;

    for (const len of [0, 31, 33]) {
      const caught = await rejectionOf(
        fetchAttestation({
          attestationUrl: TEST_ATTESTATION_URL,
          nonce: new Uint8Array(len),
        }),
      );
      expect(caught).toBeInstanceOf(InvalidNonce);
      if (caught instanceof InvalidNonce) {
        expect(caught.reason).toContain("32 bytes");
        expect(caught.reason).toContain(String(len));
      }
    }
  });

  const NONCE = new Uint8Array(32);
  NONCE.set([0xde, 0xad, 0xbe, 0xef]);
  NONCE[31] = 0xff;
  const NONCE_HEX = `deadbeef${"00".repeat(27)}ff`;

  test.each([
    { nodeId: undefined, query: `?nonce=${NONCE_HEX}` },
    { nodeId: "node-1", query: `?nonce=${NONCE_HEX}&node_id=node-1` },
    { nodeId: "region/node 7", query: `?nonce=${NONCE_HEX}&node_id=region%2Fnode%207` },
  ])("GETs $query with the caller's headers", async ({ nodeId, query }) => {
    const state = installMockFetch(GOLDEN_FIXTURE);
    await fetchAttestation({
      attestationUrl: TEST_ATTESTATION_URL,
      nonce: NONCE,
      headers: { "x-api-key": "from-headers" },
      ...(nodeId === undefined ? {} : { nodeId }),
    });
    expect(state.urls).toEqual([`${TEST_ATTESTATION_URL}${query}`]);
    expect(state.headers[0]?.["x-api-key"]).toBe("from-headers");
  });

  test("goldenFixtureParsesToAttestation", async () => {
    installMockFetch(GOLDEN_FIXTURE);
    const result = await fetchAttestation({
      attestationUrl: TEST_ATTESTATION_URL,
      nonce: new Uint8Array(32),
    });
    expect(result).toEqual({
      quote: {
        quote: "00010203",
        event_log: "04050607",
        report_data: "08090a0b",
        vm_config: "",
      },
      pubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
      composeHash: "deadbeef",
      app_compose: '{"manifest_version":2,"name":"demo"}',
    });
  });

  test("appComposeDefaultsToEmptyWhenAbsent", async () => {
    // Older sidecars / the simulator omit app_compose; parsing stays lenient
    // (defaults to "") so CHK-A2 dormant-skips rather than failing the verify.
    const { app_compose: _omitted, ...withoutAppCompose } = GOLDEN_FIXTURE;
    installMockFetch(withoutAppCompose);
    const result = await fetchAttestation({
      attestationUrl: TEST_ATTESTATION_URL,
      nonce: new Uint8Array(32),
    });
    expect(result.app_compose).toBe("");
  });

  test("unsignedRouteIgnoresVrpcHeaders", async () => {
    // Sub-case 1: no vRPC-* headers at all — must succeed.
    installMockFetch(GOLDEN_FIXTURE);
    const a = await fetchAttestation({
      attestationUrl: TEST_ATTESTATION_URL,
      nonce: new Uint8Array(32),
    });
    expect(a.composeHash).toBe("deadbeef");

    // Sub-case 2: bogus vRPC-Signature header set — SDK must NOT verify,
    // result must still resolve. (If verifyAsync were called on this path,
    // it would either throw on the malformed signature or reject the
    // mismatched bytes.)
    installMockFetch(GOLDEN_FIXTURE, { "vRPC-Signature": `0x${"00".repeat(64)}` });
    const b = await fetchAttestation({
      attestationUrl: TEST_ATTESTATION_URL,
      nonce: new Uint8Array(32),
    });
    expect(b.composeHash).toBe("deadbeef");
  });

  test.each([
    {
      name: "a declared length over 1 MiB",
      headers: { "content-length": String(MiB + 1) },
      max: 0,
    },
    { name: "an endless body", headers: {}, max: MiB + CHUNK },
  ])("the 1 MiB cap stops reading $name", async ({ headers, max }) => {
    let read = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>(
      {
        pull: (controller) => {
          read += CHUNK;
          controller.enqueue(new Uint8Array(CHUNK));
        },
        cancel: () => {
          cancelled = true;
        },
      },
      { highWaterMark: 0 },
    );
    const fetch = (async () => new Response(body, { headers })) as typeof globalThis.fetch;
    const err = await rejectionOf(
      fetchAttestation({ attestationUrl: TEST_ATTESTATION_URL, nonce: new Uint8Array(32), fetch }),
    );
    expect(err).toMatchObject({ reason: "too-large" });
    expect(cancelled).toBe(true);
    expect(read).toBeLessThanOrEqual(max);
  });
});
