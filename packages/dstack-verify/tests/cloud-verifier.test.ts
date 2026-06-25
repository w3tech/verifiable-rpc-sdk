// CloudVerifier behavior — happy path against the real Phala fixture + all
// negatives, ENTIRELY via an injected fetch (zero network).
//
// The expected pubkey / nonce / composeHash are DERIVED from the fixture (not
// hardcoded literals) so the suite stays correct if the fixture is re-captured:
//   - reportdata = pubkey(32B) ‖ nonce(32B)
//   - mr_config_id = 0x01 + composeHash(32B) + zero-pad
// Each negative asserts AttestationError with chkId === "CHK-P1".

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { AttestationError, createCloudVerifier, DEFAULT_PHALA_VERIFY_ENDPOINT } from "../src/index";
import type { AttestationBundle, VerifyPolicy } from "../src/types";

interface CloudFixture {
  quote: {
    verified: boolean;
    body: { reportdata: string; mr_config_id: string };
  };
}

function loadFixture(): CloudFixture {
  return JSON.parse(
    readFileSync(
      fileURLToPath(new URL("./fixtures/cloud-verify-response.json", import.meta.url)),
      "utf8",
    ),
  ) as CloudFixture;
}

// Derive expected values by slicing the fixture fields.
const fixture = loadFixture();
const reportDataHex = fixture.quote.body.reportdata.replace(/^0x/i, "").toLowerCase();
const mrConfigHex = fixture.quote.body.mr_config_id.replace(/^0x/i, "").toLowerCase();
const expectedPubkey = `0x${reportDataHex.slice(0, 64)}`;
const expectedNonce = reportDataHex.slice(64, 128);
// mr_config_id layout = 01 + composeHash(64 hex) + zero-pad → drop the leading
// "01" byte (2 hex), take the next 64 hex.
const composeHash = mrConfigHex.slice(2, 66);

// Sanity pins so a re-captured fixture that broke the layout would be caught.
expect(expectedPubkey.startsWith("0x27c6308b")).toBe(true);
expect(composeHash.startsWith("05b361b4")).toBe(true);

function makeBundle(composeHashOverride?: string): AttestationBundle {
  return {
    quote: { quote: "deadbeef" },
    tcbInfo: { compose_hash: composeHashOverride ?? composeHash },
  } as unknown as AttestationBundle;
}

function makePolicy(over?: { expectedPubkey?: string; expectedNonce?: string }): VerifyPolicy {
  return {
    binding: {
      expectedPubkey: over?.expectedPubkey ?? expectedPubkey,
      expectedNonce: over?.expectedNonce ?? expectedNonce,
    },
    allowInsecureMock: false,
  } as unknown as VerifyPolicy;
}

/** A 200 response whose body is the (possibly mutated) fixture. */
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

async function expectChkP1(promise: Promise<void>): Promise<void> {
  try {
    await promise;
    throw new Error("expected throw");
  } catch (e) {
    expect(e).toBeInstanceOf(AttestationError);
    expect((e as AttestationError).chkId).toBe("CHK-P1");
  }
}

describe("createCloudVerifier — happy path (real fixture)", () => {
  test("resolves when verified + reportdata + composeHash all bind; POSTs {hex} once", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const mockFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return okResponse(loadFixture());
    }) as unknown as typeof globalThis.fetch;

    const verifier = createCloudVerifier({ fetch: mockFetch });
    await expect(verifier.verifyHardware(makeBundle(), makePolicy())).resolves.toBeUndefined();

    expect(calls).toHaveLength(1);
    const call = calls[0];
    if (call === undefined) throw new Error("no fetch call recorded");
    expect(call.url).toBe(DEFAULT_PHALA_VERIFY_ENDPOINT);
    expect(call.init.method).toBe("POST");
    const body = JSON.parse(call.init.body as string) as { hex: string };
    expect(body).toEqual({ hex: "deadbeef" });
  });

  test("honors a custom endpoint", async () => {
    const calls: string[] = [];
    const mockFetch = (async (url: string | URL | Request) => {
      calls.push(String(url));
      return okResponse(loadFixture());
    }) as unknown as typeof globalThis.fetch;

    const verifier = createCloudVerifier({
      endpoint: "https://example.test/verify",
      fetch: mockFetch,
    });
    await expect(verifier.verifyHardware(makeBundle(), makePolicy())).resolves.toBeUndefined();
    expect(calls).toEqual(["https://example.test/verify"]);
  });
});

describe("createCloudVerifier — negatives (all fail closed with CHK-P1)", () => {
  test("verified:false → throws", async () => {
    const body = loadFixture();
    body.quote.verified = false;
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(body)) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("reportdata mismatch — wrong pubkey → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(loadFixture())) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(
      verifier.verifyHardware(makeBundle(), makePolicy({ expectedPubkey: `0x${"cc".repeat(32)}` })),
    );
  });

  test("reportdata mismatch — wrong nonce → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(loadFixture())) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(
      verifier.verifyHardware(makeBundle(), makePolicy({ expectedNonce: "dd".repeat(32) })),
    );
  });

  test("composeHash ∉ mr_config_id → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(loadFixture())) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle("00".repeat(32)), makePolicy()));
  });

  test("composeHash absent → throws (no silent skip)", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(loadFixture())) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(""), makePolicy()));
  });

  test("non-2xx (400) → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () =>
        ({
          ok: false,
          status: 400,
          json: async () => ({}),
        }) as unknown as Response) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("non-2xx (500) → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () =>
        ({
          ok: false,
          status: 500,
          json: async () => ({}),
        }) as unknown as Response) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("malformed body (no quote) → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse({})) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("timeout / abort → throws", async () => {
    const abortFetch = (async () => {
      throw new DOMException("aborted", "AbortError");
    }) as unknown as typeof globalThis.fetch;
    const verifier = createCloudVerifier({ fetch: abortFetch, timeoutMs: 5 });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });
});
