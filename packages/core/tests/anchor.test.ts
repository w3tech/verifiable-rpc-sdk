import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { anchorTrust } from "../src/anchor";
import {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  InvalidChainId,
  MissingHeader,
} from "../src/errors";
import { buildPreImage } from "../src/preimage";

const RPC_BASE = "https://rpc.ankr.com";
const CHAIN = "arbitrum";
const CHAIN_ID = "42161";
const TEST_SEED = new Uint8Array(32).fill(0x42);
// A second, unrelated key so the attestation route can return a NON-matching
// pubkey to exercise the correlation-failure (fail-closed) path.
const OTHER_SEED = new Uint8Array(32).fill(0x99);

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

interface GatewayScenario {
  /** Set the `vRPC-NodeId` header on the signed RPC POST response. */
  nodeIdHeader?: string;
  /** HTTP status for the attestation GET (404 → AttestationNodeNotFoundError). */
  attestationStatus?: number;
  /** Seed whose pubkey the attestation body reports (defaults to TEST_SEED). */
  attestationSeed?: Uint8Array;
}

interface GatewayMockState {
  fetch: typeof fetch;
  urls: string[];
}

/**
 * Mock the two legs anchorTrust drives, OFFLINE:
 *   1. POST <base>/<chain>_vrpc            → a real Ed25519-signed JSON-RPC body
 *      (mirrors verifier.test.ts makeMockFetch — the successful verify is the
 *      core crypto, NOT re-tested here; we only orchestrate it).
 *   2. GET  <base>/<chain>_vrpc/attestation → an attestation body whose `pubkey`
 *      either matches (correlation OK) or differs (correlation fails).
 */
function installGatewayMock(scenario: GatewayScenario = {}): GatewayMockState {
  const state: GatewayMockState = { fetch: (() => {}) as unknown as typeof fetch, urls: [] };
  const nowMs = BigInt(Date.now());

  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    state.urls.push(url);

    // ── Attestation GET leg ──────────────────────────────────────────────
    if (url.includes("/attestation")) {
      const status = scenario.attestationStatus ?? 200;
      if (status === 404) {
        return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
      }
      const attSeed = scenario.attestationSeed ?? TEST_SEED;
      const attPubkey = await getPublicKeyAsync(attSeed);
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

    // ── Signed RPC POST leg ──────────────────────────────────────────────
    let reqBytes: Uint8Array;
    const reqBody = init?.body;
    if (reqBody instanceof Uint8Array) {
      reqBytes = reqBody;
    } else if (typeof reqBody === "string") {
      reqBytes = new TextEncoder().encode(reqBody);
    } else {
      reqBytes = new Uint8Array(0);
    }

    const signedBody = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x12345" }),
    );
    const preImage = buildPreImage(CHAIN_ID, reqBytes, signedBody, nowMs);
    const signature = await signAsync(preImage, TEST_SEED);
    const pubkey = await getPublicKeyAsync(TEST_SEED);

    const headers: Record<string, string> = {
      "content-type": "application/json",
      "vRPC-Signature": `0x${toHex(signature)}`,
      "vRPC-Timestamp": nowMs.toString(),
      "vRPC-Pubkey": `0x${toHex(pubkey)}`,
    };
    if (scenario.nodeIdHeader !== undefined) {
      headers["vRPC-NodeId"] = scenario.nodeIdHeader;
    }
    return new Response(signedBody, { status: 200, headers });
  };

  state.fetch = impl as typeof fetch;
  return state;
}

describe("anchorTrust", () => {
  let savedFetch: typeof fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  test("resolvesOnPubkeyMatch", async () => {
    const mock = installGatewayMock({ nodeIdHeader: "node-abc" });
    const summary = await anchorTrust({
      rpcBaseUrl: RPC_BASE,
      chain: CHAIN,
      chainId: CHAIN_ID,
      fetch: mock.fetch,
      nonceSource: () => new Uint8Array(32).fill(0x07),
    });
    expect(summary.nodeId).toBe("node-abc");
    const expectedPubkey = `0x${toHex(await getPublicKeyAsync(TEST_SEED))}`;
    expect(summary.pubkey).toBe(expectedPubkey);
    // Both legs were driven: one signed POST + one attestation GET.
    expect(mock.urls.some((u) => u.endsWith(`/${CHAIN}_vrpc`))).toBe(true);
    expect(mock.urls.some((u) => u.includes(`/${CHAIN}_vrpc/attestation`))).toBe(true);
  });

  test("rejectsWithCorrelationErrorOnPubkeyMismatch", async () => {
    // Attestation reports OTHER_SEED's pubkey — must NOT equal the RPC signer's.
    const mock = installGatewayMock({ nodeIdHeader: "node-abc", attestationSeed: OTHER_SEED });
    let caught: unknown;
    try {
      await anchorTrust({
        rpcBaseUrl: RPC_BASE,
        chain: CHAIN,
        chainId: CHAIN_ID,
        fetch: mock.fetch,
        nonceSource: () => new Uint8Array(32).fill(0x07),
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestationCorrelationError);
  });

  test("rejectsWithNodeNotFoundOn404", async () => {
    const mock = installGatewayMock({ nodeIdHeader: "stale-node", attestationStatus: 404 });
    let caught: unknown;
    try {
      await anchorTrust({
        rpcBaseUrl: RPC_BASE,
        chain: CHAIN,
        chainId: CHAIN_ID,
        fetch: mock.fetch,
        nonceSource: () => new Uint8Array(32).fill(0x07),
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestationNodeNotFoundError);
    if (caught instanceof AttestationNodeNotFoundError) {
      expect(caught.nodeId).toBe("stale-node");
    }
  });

  test("rejectsWithTypedErrorWhenNodeIdAbsent", async () => {
    // Older proxy: no vRPC-NodeId header → boot-time anchor cannot target a node.
    const mock = installGatewayMock({});
    let caught: unknown;
    try {
      await anchorTrust({
        rpcBaseUrl: RPC_BASE,
        chain: CHAIN,
        chainId: CHAIN_ID,
        fetch: mock.fetch,
        nonceSource: () => new Uint8Array(32).fill(0x07),
      });
    } catch (err) {
      caught = err;
    }
    // Fail-closed: a VerificationError-family member, NOT a silent resolve.
    expect(caught).toBeInstanceOf(MissingHeader);
    if (caught instanceof MissingHeader) {
      expect(caught.headerName).toBe("vRPC-NodeId");
    }
  });

  test("usesFreshNonceFromInjectableSource", async () => {
    const mock = installGatewayMock({ nodeIdHeader: "node-abc" });
    let nonceCalls = 0;
    await anchorTrust({
      rpcBaseUrl: RPC_BASE,
      chain: CHAIN,
      chainId: CHAIN_ID,
      fetch: mock.fetch,
      nonceSource: () => {
        nonceCalls += 1;
        return new Uint8Array(32).fill(0x07);
      },
    });
    // The helper pulls exactly one fresh 32-byte nonce per call.
    expect(nonceCalls).toBe(1);
    // The attestation GET carries that nonce as bare lowercase hex (32 * "07").
    const attUrl = mock.urls.find((u) => u.includes("/attestation"));
    expect(attUrl).toBeDefined();
    expect(attUrl).toContain(`nonce=${"07".repeat(32)}`);
  });

  test("rejectsInvalidChainId", async () => {
    // The chain id string is passed through verbatim; VerifierClient's
    // constructor validates it and an invalid id rejects with InvalidChainId
    // before any network call.
    const mock = installGatewayMock({ nodeIdHeader: "node-abc" });
    await expect(
      anchorTrust({
        rpcBaseUrl: RPC_BASE,
        chain: CHAIN,
        chainId: "a b",
        fetch: mock.fetch,
        nonceSource: () => new Uint8Array(32).fill(0x07),
      }),
    ).rejects.toBeInstanceOf(InvalidChainId);
  });
});
