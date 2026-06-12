import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  fetchAttestation,
  fetchAttestationViaShark,
  verifyAttestationCorrelation,
} from "../src/attestation";
import {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  InvalidNonce,
  MalformedAttestationResponse,
} from "../src/errors";
import type { VerifiedResponse } from "../src/verifier";
import { VerifierClient } from "../src/verifier";

const TEST_URL = "http://test.local:8545";

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

const SHARK_BASE = "https://rpc.ankr.com";

interface SharkMockState {
  urls: string[];
  headers: Array<Record<string, string> | undefined>;
  calls: number;
}

function installSharkMockFetch(body: unknown, status = 200): SharkMockState {
  const state: SharkMockState = { urls: [], headers: [], calls: 0 };
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    state.calls += 1;
    state.urls.push(typeof input === "string" ? input : input.toString());
    state.headers.push(init?.headers as Record<string, string> | undefined);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return state;
}

describe("fetchAttestationViaShark", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("nonceMustBe32Bytes", async () => {
    globalThis.fetch = ((): Response => {
      throw new Error("fetch called — synchronous validation failed");
    }) as unknown as typeof fetch;
    let caught: unknown;
    try {
      await fetchAttestationViaShark({
        sharkBase: SHARK_BASE,
        chain: "eth",
        nodeId: "node-1",
        nonce: new Uint8Array(31),
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(InvalidNonce);
  });

  test("buildsExactContractUrl", async () => {
    const state = installSharkMockFetch(GOLDEN_FIXTURE);
    const nonce = new Uint8Array(32);
    await fetchAttestationViaShark({
      sharkBase: SHARK_BASE,
      chain: "eth",
      nodeId: "node-1",
      nonce,
    });
    const expectedHex = bytesToHex(nonce);
    expect(state.urls[0]).toBe(
      `${SHARK_BASE}/eth_vrpc/attestation?nonce=${expectedHex}&node_id=node-1`,
    );
    expect(state.urls[0]).not.toContain("nonce=0x");
  });

  test("nonceHexRoundTripsByteIntact", async () => {
    const state = installSharkMockFetch(GOLDEN_FIXTURE);
    const nonce = new Uint8Array(32);
    nonce[0] = 0xde;
    nonce[1] = 0xad;
    nonce[2] = 0xbe;
    nonce[3] = 0xef;
    nonce[31] = 0xff;
    await fetchAttestationViaShark({
      sharkBase: SHARK_BASE,
      chain: "eth",
      nodeId: "node-1",
      nonce,
    });
    const expectedHex = bytesToHex(nonce);
    expect(expectedHex).toMatch(/^[0-9a-f]{64}$/);
    expect(state.urls[0]).toContain(`nonce=${expectedHex}`);
  });

  test("nodeIdIsUrlEncoded", async () => {
    const state = installSharkMockFetch(GOLDEN_FIXTURE);
    await fetchAttestationViaShark({
      sharkBase: SHARK_BASE,
      chain: "eth",
      nodeId: "region/node 7",
      nonce: new Uint8Array(32),
    });
    expect(state.urls[0]).toContain("node_id=region%2Fnode%207");
    expect(state.urls[0]).not.toContain("node_id=region/node 7");
  });

  test("status404ThrowsNodeNotFoundWithNoRetry", async () => {
    const state = installSharkMockFetch({}, 404);
    let caught: unknown;
    try {
      await fetchAttestationViaShark({
        sharkBase: SHARK_BASE,
        chain: "eth",
        nodeId: "stale-node",
        nonce: new Uint8Array(32),
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestationNodeNotFoundError);
    if (caught instanceof AttestationNodeNotFoundError) {
      expect(caught.nodeId).toBe("stale-node");
    }
    // No fallback or retry.
    expect(state.calls).toBe(1);
  });

  test("apiKeySetsXApiKeyExplicitHeadersWin", async () => {
    const state = installSharkMockFetch(GOLDEN_FIXTURE);
    await fetchAttestationViaShark({
      sharkBase: SHARK_BASE,
      chain: "eth",
      nodeId: "node-1",
      nonce: new Uint8Array(32),
      apiKey: "from-option",
    });
    expect(state.headers[0]?.["x-api-key"]).toBe("from-option");

    const state2 = installSharkMockFetch(GOLDEN_FIXTURE);
    await fetchAttestationViaShark({
      sharkBase: SHARK_BASE,
      chain: "eth",
      nodeId: "node-1",
      nonce: new Uint8Array(32),
      apiKey: "from-option",
      headers: { "x-api-key": "from-headers" },
    });
    expect(state2.headers[0]?.["x-api-key"]).toBe("from-headers");
  });

  test("reusesNarrowAttestationOnMalformedBody", async () => {
    installSharkMockFetch({ quote: "abcdef", pubkey: "0x00", composeHash: "feed" });
    let caught: unknown;
    try {
      await fetchAttestationViaShark({
        sharkBase: SHARK_BASE,
        chain: "eth",
        nodeId: "node-1",
        nonce: new Uint8Array(32),
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(MalformedAttestationResponse);
  });
});

describe("verifyAttestationCorrelation", () => {
  const pubkey = "0x0000000000000000000000000000000000000000000000000000000000000000";

  function makeVerifiedResponse(pubkeyHex: string): VerifiedResponse {
    return {
      result: "0x1",
      raw: { request: new Uint8Array(0), response: new Uint8Array(0) },
      verification: {
        signatureHex: `0x${"00".repeat(64)}`,
        pubkeyHex,
        timestampMs: 0n,
        preImageSha256: new Uint8Array(32),
      },
    };
  }

  test("returnsOnPubkeyMatch", () => {
    const attestation = { ...GOLDEN_FIXTURE, pubkey };
    expect(() =>
      verifyAttestationCorrelation(attestation, makeVerifiedResponse(pubkey)),
    ).not.toThrow();
  });

  test("throwsCorrelationOnMismatch", () => {
    const attestationPubkey = `0x${"ab".repeat(32)}`;
    const responsePubkey = `0x${"cd".repeat(32)}`;
    const attestation = { ...GOLDEN_FIXTURE, pubkey: attestationPubkey };
    let caught: unknown;
    try {
      verifyAttestationCorrelation(attestation, makeVerifiedResponse(responsePubkey));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestationCorrelationError);
    if (caught instanceof AttestationCorrelationError) {
      expect(caught.expectedPubkey).toBe(responsePubkey);
      expect(caught.actualPubkey).toBe(attestationPubkey);
    }
  });
});
