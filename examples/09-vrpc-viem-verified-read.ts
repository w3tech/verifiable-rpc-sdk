// 09 — drop-in viem vrpcHttp transport verified read + boot-time trust anchor (DX-02 / TRUST-01).
//
// The viem half of the v4.0 onboarding pair (symmetric with example 08). Build a
// `createPublicClient({ transport: vrpcHttp(url, { chainId, headers }) })` (the
// verifiable drop-in for `http(url)`), do a REAL verified read through a stage
// shark `arbitrum_vrpc` route — every viem action funnels through the verifying
// transport `request`, so a returned value IS the proof the response was
// Ed25519-verified over its raw bytes — then call the SAME adapter-neutral
// `anchorTrust(...)` once for boot-time attestation correlation. `anchorTrust`
// is OPT-IN, does NOT alter the transport, and throws a VerificationError-family
// member on correlation failure (fail-closed).
//
// SECRETS: SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY are read from env BY NAME
// only (via requireEnv). Their VALUES are never hardcoded, printed, or logged —
// only "set" is shown.
//
// LIVE RUN IS AN OPERATOR STEP. This script needs the staging URL + x-api-key
// supplied via env at runtime; offline/CI does NOT execute it live. Run with:
//   SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… pnpm example:09-vrpc-viem-verified-read
// (or `tsx examples/09-vrpc-viem-verified-read.ts`).

import { anchorTrust } from "@ankr.com/vrpc-core";
import { vrpcHttp } from "@ankr.com/vrpc-viem";
import { createPublicClient } from "viem";
import {
  assert,
  CHAIN_ID,
  header,
  kv,
  requireEnv,
  SHARK_STAGE_TDX_TEST_KEY,
  SHARK_STAGE_URL,
} from "./shared.ts";

header("09 — viem vrpcHttp + createPublicClient verified read + anchorTrust via stage shark");

const sharkUrl = requireEnv("SHARK_STAGE_URL", SHARK_STAGE_URL);
const apiKey = requireEnv("SHARK_STAGE_TDX_TEST_KEY", SHARK_STAGE_TDX_TEST_KEY);
const chain = "arbitrum";
// Pass the PLAIN route — the SDK appends `_vrpc` itself (single-URL convention).
const url = `${sharkUrl}/${chain}`;

// Never print the secret URL / key — only confirm they are set.
kv("SHARK_STAGE_URL", "set");
kv("SHARK_STAGE_TDX_TEST_KEY", "set");
kv("route (SDK appends _vrpc)", `/${chain}`);

// ── DROP-IN CONSTRUCTION ──────────────────────────────────────────────────────
// One-line swap: `http(url)` → `vrpcHttp(url, { chainId })`. Pass the plain URL;
// the SDK appends the `_vrpc` route suffix (and derives the `/attestation`
// sub-route) itself — no manual concatenation, no attestationBaseUrl/chainSlug.
// Attestation is always-on, derived from the URL. The x-api-key auth header
// rides on the transport's per-request `headers`.
const client = createPublicClient({
  transport: vrpcHttp(url, {
    chainId: CHAIN_ID,
    headers: { "x-api-key": apiKey },
  }),
});

// ── REAL VERIFIED READ ────────────────────────────────────────────────────────
// getBalance funnels through the verifying transport; a returned value IS the
// proof the response was Ed25519-verified. The zero address is a stable,
// side-effect-free read target.
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
const balance = await client.getBalance({ address: ZERO_ADDR });
kv("getBalance(0x0) (wei)", balance.toString());
assert(typeof balance === "bigint", "getBalance must return a bigint (verified read)");

const blockNumber = await client.getBlockNumber();
kv("getBlockNumber", blockNumber.toString());
assert(blockNumber > 0n, "blockNumber must be a positive bigint");

// ── BOOT-TIME TRUST ANCHOR (TRUST-01) ─────────────────────────────────────────
// The SAME adapter-neutral helper example 08 calls — identical behaviour across
// ethers + viem. Throws a VerificationError-family member on correlation failure.
const anchor = await anchorTrust({
  sharkBase: sharkUrl,
  chain,
  chainId: CHAIN_ID,
  apiKey,
});
kv("anchorTrust nodeId", anchor.nodeId);
kv("anchorTrust pubkey", anchor.pubkey);
assert(
  anchor.pubkey.startsWith("0x") && anchor.pubkey.length === 66,
  "anchored pubkey must be 0x + 64 hex chars",
);

console.log(
  "\nPASS — viem vrpcHttp client returned a verified read through shark and anchorTrust correlated the attestation pubkey",
);
