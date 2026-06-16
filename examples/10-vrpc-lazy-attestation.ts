// 10 — OFFLINE lazy-attestation flow through BOTH adapters (TEST-03 / FLOW-06 / DX-01).
//
// Demonstrates the v5.0 lazy-attestation seam end-to-end, fully OFFLINE (no env,
// no real network — injected mock fetch serves BOTH legs). When a VrpcProvider /
// vrpcHttp transport is constructed with the opt-in `sharkBase` + `chain` pair,
// the normal verify routes through vrpc-core's `TrustedVerifier`: on an UNKNOWN
// signing pubkey it fetches the node's `/attestation`, correlates it, runs the
// (v5.0 MOCK) attestation verifier, and CACHES the pubkey; a second ordinary read
// within TTL reuses the cache and skips the attestation fetch.
//
// >>> INSECURE MOCK — NO real attestation security until v6.0. <<<
// The v5.0 attestation verifier is a mock (`allowInsecureMock` is hard-set):
// "v5.0 provides NO real attestation security (real verification lands in v6.0)."
// This example proves the FLOW and the cache, NOT real TDX attestation.
//
// Run (no env required, exits 0):
//   bun run examples/10-vrpc-lazy-attestation.ts
//   (or `bun run example:10-vrpc-lazy-attestation`).

import { buildPreImage } from "@ankr.com/vrpc-core";
import { VrpcProvider } from "@ankr.com/vrpc-ethers";
import { vrpcHttp } from "@ankr.com/vrpc-viem";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { FetchRequest } from "ethers";
import { createPublicClient } from "viem";
import { assert, header, kv } from "./shared.ts";

header("10 — OFFLINE lazy-attestation flow through BOTH adapters (mock verifier)");

console.log(
  "\n  INSECURE MOCK — NO real attestation security until v6.0.\n" +
    "  v5.0 provides NO real attestation security (real verification lands in v6.0).\n" +
    "  This example demonstrates the lazy-attestation FLOW + pubkey cache against the\n" +
    "  v5.0 MOCK verifier — it does NOT perform real TDX attestation.\n",
);

// ── OFFLINE CONFIG ────────────────────────────────────────────────────────────
// A fixed in-script signing seed (NOT a secret — a test fixture, never a
// production key). The attestation GET returns the SAME pubkey so correlation
// passes. A wide replay window neutralizes wall-clock skew on the signed fixture.
const CHAIN_ID = 42161n;
const VRPC_URL = "http://offline.local/arbitrum_vrpc";
const SHARK_BASE = "http://offline.local";
const CHAIN = "arbitrum";
const TEST_SEED = new Uint8Array(32).fill(0x42);
const WIDE_REPLAY_MS = 365 * 24 * 60 * 60 * 1000; // 1y — fixture staleness guard

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Sign `responseBytes` over the EXACT request bytes (matches the sidecar pre-image). */
async function signRpc(
  requestBytes: Uint8Array,
  responseBytes: Uint8Array,
): Promise<Record<string, string>> {
  const ts = BigInt(Date.now());
  const preImage = buildPreImage(CHAIN_ID, requestBytes, responseBytes, ts);
  const signature = await signAsync(preImage, TEST_SEED);
  const pubkey = await getPublicKeyAsync(TEST_SEED);
  return {
    "content-type": "application/json",
    "vRPC-Signature": `0x${toHex(signature)}`,
    "vRPC-Timestamp": ts.toString(),
    "vRPC-Pubkey": `0x${toHex(pubkey)}`,
    "vRPC-NodeId": "node-offline",
  };
}

/** Attestation body whose `pubkey` correlates to TEST_SEED (so the seam passes). */
async function attestationResponse(): Promise<Response> {
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

// ── SECTION 1: ethers VrpcProvider ────────────────────────────────────────────
// The ethers RPC leg rides a FetchRequest (getUrlFunc serves the signed POST);
// the seam's attestation GET rides the injected `fetch` option. Both are offline.
{
  header("Section 1 — ethers VrpcProvider lazy attestation (offline)");
  let attGetCount = 0;
  const RESULT = "0x100000";

  const req = new FetchRequest(VRPC_URL);
  // RPC POST leg: sign over the exact bytes ethers serialized (sentReq.body).
  req.getUrlFunc = async (sentReq) => {
    const requestBytes = sentReq.body ?? new Uint8Array();
    const responseBytes = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: RESULT }),
    );
    const headers = await signRpc(requestBytes, responseBytes);
    return { statusCode: 200, statusMessage: "OK", headers, body: responseBytes };
  };
  // Attestation GET leg: injected seam fetch, offline, counted for the cache proof.
  const attFetch = (async (input: string | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      attGetCount += 1;
      return attestationResponse();
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as unknown as typeof fetch;

  const provider = new VrpcProvider(req, CHAIN_ID, {
    sharkBase: SHARK_BASE,
    chain: CHAIN,
    fetch: attFetch,
    replayWindowMs: WIDE_REPLAY_MS,
  });

  const block1 = await provider.getBlockNumber();
  kv("ethers getBlockNumber #1", block1);
  assert(Number.isInteger(block1) && block1 > 0, "ethers read #1 must return a verified value");
  assert(attGetCount === 1, "ethers: attestation GET must be hit exactly once (cache miss)");

  const block2 = await provider.getBlockNumber();
  kv("ethers getBlockNumber #2", block2);
  assert(Number.isInteger(block2) && block2 > 0, "ethers read #2 must return a verified value");
  assert(attGetCount === 1, "ethers: 2nd read within TTL must reuse the cache (no extra GET)");
  kv("ethers attestation GET count", attGetCount);
}

// ── SECTION 2: viem vrpcHttp ──────────────────────────────────────────────────
// `fetchFn` feeds BOTH legs for viem: the signed RPC POST and the attestation GET.
{
  header("Section 2 — viem vrpcHttp lazy attestation (offline)");
  let attGetCount = 0;
  const RESULT = "0x200000";

  const fetchFn = async (input: string, init: RequestInit): Promise<Response> => {
    if (input.includes("/attestation")) {
      attGetCount += 1;
      return attestationResponse();
    }
    const requestBytes = new TextEncoder().encode(String(init.body ?? ""));
    const responseBytes = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: RESULT }),
    );
    const headers = await signRpc(requestBytes, responseBytes);
    return new Response(responseBytes, { status: 200, headers });
  };

  const client = createPublicClient({
    transport: vrpcHttp(VRPC_URL, {
      chainId: CHAIN_ID,
      sharkBase: SHARK_BASE,
      chain: CHAIN,
      fetchFn,
      replayWindowMs: WIDE_REPLAY_MS,
    }),
  });

  const block1 = await client.getBlockNumber();
  kv("viem getBlockNumber #1", block1.toString());
  assert(block1 > 0n, "viem read #1 must return a verified value");
  assert(attGetCount === 1, "viem: attestation GET must be hit exactly once (cache miss)");

  const block2 = await client.getBlockNumber();
  kv("viem getBlockNumber #2", block2.toString());
  assert(block2 > 0n, "viem read #2 must return a verified value");
  assert(attGetCount === 1, "viem: 2nd read within TTL must reuse the cache (no extra GET)");
  kv("viem attestation GET count", attGetCount);
}

console.log(
  "\nPASS — both adapters demonstrated the lazy-attestation flow (mock verifier, cached)",
);
