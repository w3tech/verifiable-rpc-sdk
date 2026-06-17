// 08 — drop-in ethers VrpcProvider verified read + boot-time trust anchor (DX-02 / TRUST-01).
//
// The ethers half of the v4.0 onboarding pair. Construct the verifiable drop-in
// `new VrpcProvider(url, chainId, opts)` (substitutes for `new
// JsonRpcProvider(url)`), do a REAL verified read through a stage shark
// `arbitrum_vrpc` route — the value only reaches the caller AFTER the in-`_send`
// Ed25519 verification — then call the adapter-neutral `anchorTrust(...)` ONCE
// to confirm boot-time attestation correlation (the serving node's attestation
// pubkey == the response signer's pubkey). `anchorTrust` is OPT-IN and does NOT
// alter the (sync) constructor; on correlation failure it throws a
// VerificationError-family member (fail-closed).
//
// SECRETS: SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY are read from env BY NAME
// only (via requireEnv). Their VALUES are never hardcoded, printed, or logged —
// only "set" is shown.
//
// LIVE RUN IS AN OPERATOR STEP. This script needs the staging URL + x-api-key
// supplied via env at runtime; offline/CI does NOT execute it live. Run with:
//   SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… bun run examples/08-vrpc-ethers-verified-read.ts
// (or `bun run example:08-vrpc-ethers-verified-read`).

import { anchorTrust } from "@ankr.com/vrpc-core";
import { VrpcProvider } from "@ankr.com/vrpc-ethers";
import { FetchRequest } from "ethers";
import {
  assert,
  CHAIN_ID,
  header,
  kv,
  requireEnv,
  SHARK_STAGE_TDX_TEST_KEY,
  SHARK_STAGE_URL,
} from "./shared.ts";

header("08 — ethers VrpcProvider verified read + anchorTrust via stage shark");

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
// One-line swap: `new JsonRpcProvider(url)` → `new VrpcProvider(url, chainId)`.
// Pass the plain URL; the SDK appends the `_vrpc` route suffix (and derives the
// `/attestation` sub-route) itself — no manual concatenation, no
// attestationBaseUrl/chainSlug. Attestation is always-on, derived from the URL.
// The x-api-key auth header is supplied via a FetchRequest, the same mechanism
// ethers uses for header injection; VrpcOptions extends JsonRpcApiProviderOptions
// so the FetchRequest passes straight through to the underlying connection.
const req = new FetchRequest(url);
req.setHeader("x-api-key", apiKey);
const provider = new VrpcProvider(req, CHAIN_ID);

// ── REAL VERIFIED READ ────────────────────────────────────────────────────────
// getBalance funnels through the verifying `_send` override; a returned value IS
// the proof the response was Ed25519-verified over its raw bytes. The zero
// address is a stable, side-effect-free read target.
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
const balance = await provider.getBalance(ZERO_ADDR);
kv("getBalance(0x0) (wei)", balance.toString());
assert(typeof balance === "bigint", "getBalance must return a bigint (verified read)");

const blockNumber = await provider.getBlockNumber();
kv("getBlockNumber", blockNumber);
assert(Number.isInteger(blockNumber) && blockNumber > 0, "blockNumber must be a positive integer");

// ── BOOT-TIME TRUST ANCHOR (TRUST-01) ─────────────────────────────────────────
// Opt-in correlation: confirm the serving node's attestation pubkey == the
// response signer's pubkey. Throws a VerificationError-family member on failure.
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
  "\nPASS — ethers VrpcProvider returned a verified read through shark and anchorTrust correlated the attestation pubkey",
);
