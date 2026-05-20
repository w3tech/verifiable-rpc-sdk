import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";

import { fetchAttestation } from "../src/attestation";
import { InvalidNonce, MalformedAttestationResponse } from "../src/errors";
import { VerifierClient } from "../src/verifier";

const TEST_URL = "http://test.local:8545";

/**
 * Canonical hand-crafted golden fixture — mirrors the sidecar's Rust unit
 * test `attestation_response_nests_sdk_quote_and_renames_compose_hash`
 * byte-for-byte. Phase 21 will REPLACE this with a real-simulator capture
 * if the shape differs.
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
};

interface MockState {
  capturedUrl: string | undefined;
}

function installMockFetch(body: unknown, extraHeaders: Record<string, string> = {}): MockState {
  const state: MockState = { capturedUrl: undefined };
  globalThis.fetch = (async (input: string | URL | Request) => {
    state.capturedUrl = typeof input === "string" ? input : input.toString();
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
      let caught: unknown;
      try {
        await fetchAttestation(TEST_URL, new Uint8Array(len));
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(InvalidNonce);
      if (caught instanceof InvalidNonce) {
        expect(caught.reason).toContain("32 bytes");
        expect(caught.reason).toContain(String(len));
      }
    }
  });

  test("nonceLength32Succeeds", async () => {
    const state = installMockFetch(GOLDEN_FIXTURE);
    const result = await fetchAttestation(TEST_URL, new Uint8Array(32));
    expect(state.capturedUrl).toBeDefined();
    expect(result.quote.quote).toBe("00010203");
  });

  test("urlIsAttestationWithBareHexNonce", async () => {
    const state = installMockFetch(GOLDEN_FIXTURE);
    const nonce = new Uint8Array(32);
    nonce[0] = 0xde;
    nonce[1] = 0xad;
    nonce[2] = 0xbe;
    nonce[3] = 0xef;
    await fetchAttestation(TEST_URL, nonce);
    const expectedHex = bytesToHex(nonce);
    expect(state.capturedUrl).toBe(`${TEST_URL}/attestation?nonce=${expectedHex}`);
    // No 0x prefix in the URL.
    expect(state.capturedUrl).not.toContain("nonce=0x");
    // Lowercase, 64 hex chars.
    expect(expectedHex).toMatch(/^[0-9a-f]{64}$/);
  });

  test("goldenFixtureParsesToAttestation", async () => {
    installMockFetch(GOLDEN_FIXTURE);
    const result = await fetchAttestation(TEST_URL, new Uint8Array(32));
    expect(result).toEqual({
      quote: {
        quote: "00010203",
        event_log: "04050607",
        report_data: "08090a0b",
        vm_config: "",
      },
      pubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
      composeHash: "deadbeef",
    });
  });

  test("malformedTopLevelQuoteThrows", async () => {
    installMockFetch({
      quote: "abcdef",
      pubkey: "0x00",
      composeHash: "feed",
    });
    let caught: unknown;
    try {
      await fetchAttestation(TEST_URL, new Uint8Array(32));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedAttestationResponse);
    if (caught instanceof MalformedAttestationResponse) {
      expect(caught.reason).toContain("quote");
    }
  });

  test("missingFieldsThrow", async () => {
    const cases: Array<{ body: unknown; fieldPath: string }> = [
      {
        body: {
          quote: GOLDEN_FIXTURE.quote,
          composeHash: "feed",
        },
        fieldPath: "pubkey",
      },
      {
        body: {
          quote: GOLDEN_FIXTURE.quote,
          pubkey: "0x00",
        },
        fieldPath: "composeHash",
      },
      {
        body: {
          quote: {
            quote: "00",
            // event_log missing
            report_data: "00",
            vm_config: "",
          },
          pubkey: "0x00",
          composeHash: "feed",
        },
        fieldPath: "event_log",
      },
    ];

    for (const { body, fieldPath } of cases) {
      installMockFetch(body);
      let caught: unknown;
      try {
        await fetchAttestation(TEST_URL, new Uint8Array(32));
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(MalformedAttestationResponse);
      if (caught instanceof MalformedAttestationResponse) {
        expect(caught.reason).toContain(fieldPath);
      }
    }
  });

  test("unsignedRouteIgnoresVrpcHeaders", async () => {
    // Sub-case 1: no vRPC-* headers at all — must succeed.
    installMockFetch(GOLDEN_FIXTURE);
    const a = await fetchAttestation(TEST_URL, new Uint8Array(32));
    expect(a.composeHash).toBe("deadbeef");

    // Sub-case 2: bogus vRPC-Signature header set — SDK must NOT verify,
    // result must still resolve. (If verifyAsync were called on this path,
    // it would either throw on the malformed signature or reject the
    // mismatched bytes.)
    installMockFetch(GOLDEN_FIXTURE, { "vRPC-Signature": `0x${"00".repeat(64)}` });
    const b = await fetchAttestation(TEST_URL, new Uint8Array(32));
    expect(b.composeHash).toBe("deadbeef");
  });

  test("clientDelegatesToStandaloneFn", async () => {
    const state = installMockFetch(GOLDEN_FIXTURE);
    const nonce = new Uint8Array(32).fill(0x11);
    const client = new VerifierClient(TEST_URL, { chainId: 1n });
    const result = await client.fetchAttestation(nonce);
    const expectedHex = bytesToHex(nonce);
    expect(state.capturedUrl).toBe(`${TEST_URL}/attestation?nonce=${expectedHex}`);
    expect(result).toEqual({
      quote: {
        quote: "00010203",
        event_log: "04050607",
        report_data: "08090a0b",
        vm_config: "",
      },
      pubkey: "0x0000000000000000000000000000000000000000000000000000000000000000",
      composeHash: "deadbeef",
    });
  });
});
