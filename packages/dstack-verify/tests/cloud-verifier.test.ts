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
import { mockHardwareVerifier, rejectionOf } from "@w3tech.io/vrpc-test-support";
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
    quote: "deadbeef",
    reportData: "",
    composeHash: composeHashOverride ?? composeHash,
    appCompose: "",
  };
}

function makePolicy(over?: { expectedPubkey?: string; expectedNonce?: string }): VerifyPolicy {
  return {
    binding: {
      expectedPubkey: over?.expectedPubkey ?? expectedPubkey,
      expectedNonce: over?.expectedNonce ?? expectedNonce,
    },
    hardwareVerifier: mockHardwareVerifier(),
  };
}

/** A 200 response whose body is the (possibly mutated) fixture. */
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

async function expectChkP1(promise: Promise<void>, unavailable?: true): Promise<void> {
  const err = await rejectionOf(promise);
  expect(err).toBeInstanceOf(AttestationError);
  expect((err as AttestationError).chkId).toBe("CHK-P1");
  expect((err as AttestationError).unavailable).toBe(unavailable);
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

  test("composeHash present at WRONG offset in mr_config_id → throws (positional bind, not substring)", async () => {
    // mr_config_id carries composeHash but shifted to offset 4 (layout offset is
    // 2: 0x01 prefix byte). A loose substring match would ACCEPT this; the
    // positional hex[2:66] bind MUST reject it. Guards against re-weakening the
    // composeHash check back to String.includes().
    const body = loadFixture();
    const shifted = `0000${composeHash}`.padEnd(96, "0");
    expect(shifted).toHaveLength(96);
    expect(shifted.includes(composeHash)).toBe(true); // a substring match WOULD pass
    body.quote.body.mr_config_id = `0x${shifted}`;
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(body)) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("malformed mr_config_id (wrong length) → throws", async () => {
    const body = loadFixture();
    body.quote.body.mr_config_id = `0x01${composeHash}`; // 66 hex, not 96
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(body)) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  test("composeHash absent → throws (no silent skip)", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse(loadFixture())) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(""), makePolicy()));
  });

  test("malformed body (no quote) → throws", async () => {
    const verifier = createCloudVerifier({
      fetch: (async () => okResponse({})) as unknown as typeof globalThis.fetch,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()));
  });

  const status = (code: number) => async () =>
    ({ ok: false, status: code, json: async () => ({}) }) as unknown as Response;
  const abortedBy = (signal: AbortSignal | null | undefined) =>
    new Promise<never>((_, reject) => {
      signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    });
  const body =
    (json: (signal: AbortSignal | null | undefined) => Promise<unknown>) =>
    async (_url: string, init: RequestInit) =>
      ({ ok: true, status: 200, json: () => json(init.signal) }) as unknown as Response;
  test.each([
    ["HTTP 500", status(500), true],
    ["HTTP 503", status(503), true],
    ["HTTP 429", status(429), true],
    ["HTTP 408", status(408), true],
    [
      "transport throw",
      async () => {
        throw new TypeError("fetch failed");
      },
      true,
    ],
    ["timeout", (_url: string, init: RequestInit) => abortedBy(init.signal), true],
    ["body read timeout", body(abortedBy), true],
    [
      "body read disconnect",
      body(async () => {
        throw new TypeError("terminated");
      }),
      true,
    ],
    [
      "non-JSON 200",
      body(async () => {
        throw new SyntaxError("Unexpected token '<'");
      }),
      true,
    ],
    ["HTTP 400", status(400), undefined],
    ["HTTP 422", status(422), undefined],
  ] as const)("%s → unavailable %s", { timeout: 1_000 }, async (_name, fetch, unavailable) => {
    const verifier = createCloudVerifier({
      fetch: fetch as unknown as typeof globalThis.fetch,
      timeoutMs: 5,
    });
    await expectChkP1(verifier.verifyHardware(makeBundle(), makePolicy()), unavailable);
  });
});
