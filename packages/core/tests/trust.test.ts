import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";

import { AttestationError } from "@ankr.com/dstack-verify";

import { buildPreImage } from "../src/preimage";
import { buildVerifyPolicy, TrustedVerifier, type TrustedVerifierOptions } from "../src/trust";
import type { ResponseHeaders } from "../src/verify";

const SHARK_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const CHAIN_ID = 42161n;
const TEST_SEED = new Uint8Array(32).fill(0x42);
const NONCE = new Uint8Array(32).fill(0x07);
const NOW = 1000;

/** Empty pinned allowlist — the v5.0 mock does not inspect it (A3). */
const EMPTY_ALLOWLIST = {
  composeHashes: [],
  mrtd: "",
  rtmr0: "",
  rtmr1: "",
  rtmr2: "",
  osImageHashes: [],
  kmsIdentities: [],
};

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
  const ts = BigInt(NOW);
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

interface AttMockState {
  fetch: typeof fetch;
  attGetCount: number;
}

/** Mock only the attestation GET leg; count how many times it is hit. */
function installAttestationMock(): AttMockState {
  const state: AttMockState = { fetch: (() => {}) as unknown as typeof fetch, attGetCount: 0 };
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
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
    replayWindowMs: 0,
    sharkBase: SHARK_BASE,
    chain: CHAIN,
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
});
