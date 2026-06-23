// 03 — vrpc-core walkthrough: verify a JSON-RPC response, step by step.
//
// `@ankr.com/vrpc-core` is the verification engine the ethers/viem adapters are
// built on. This example uses it DIRECTLY against the live TDX node so you can
// see every step of the trust chain — no ethers, no viem, no secrets required:
//
//   pnpm example:03-vrpc-core-walkthrough
//
// What you will see:
//   1. A normal JSON-RPC request, and the `vRPC-*` signature headers the node
//      attaches to every response (signed INSIDE the TEE).
//   2. `verifyResponse(...)` — Ed25519 verification of those bytes.
//   3. The fail-closed property: tamper one byte → `BadSignature`.
//   4. `fetchAttestation(...)` + correlation — anchoring the signing key to the
//      TEE quote (so you know the key lives in an attested enclave).
//   5. `VerifierClient` — the one-liner that wraps steps 1-2 for everyday use.

import crypto from "node:crypto";

import {
  BadSignature,
  fetchAttestation,
  type VerifiedPair,
  VerifierClient,
  verifyAttestationCorrelation,
  verifyResponse,
} from "@ankr.com/vrpc-core";

// Verifiable node config via env — no node address hardcoded. Set VRPC_NODE_URL
// (+ optional VRPC_NODE_CHAIN_ID, VRPC_NODE_COMPOSE_HASH) to run; otherwise skip.
const NODE_URL = process.env.VRPC_NODE_URL ?? "http://127.0.0.1:1234";
const NODE_CONFIGURED = (process.env.VRPC_NODE_URL ?? "").length > 0;
const CHAIN_ID = BigInt(process.env.VRPC_NODE_CHAIN_ID ?? "42161");
const PINNED_COMPOSE_HASH = process.env.VRPC_NODE_COMPOSE_HASH ?? "";

// Tiny console helpers (kept local so this file is self-contained).
const header = (t: string): void => console.log(`\n${"=".repeat(64)}\n  ${t}\n${"=".repeat(64)}`);
const kv = (label: string, value: unknown): void =>
  console.log(`  ${label.padEnd(38)} ${String(value)}`);
function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) {
    console.error(`\nFAIL — ${msg}`);
    process.exit(1);
  }
}

const enc = new TextEncoder();
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

async function main(): Promise<void> {
  header("vrpc-core walkthrough");
  if (!NODE_CONFIGURED) {
    kv("Skipped", "set VRPC_NODE_URL (+ optional VRPC_NODE_CHAIN_ID, VRPC_NODE_COMPOSE_HASH)");
    kv("Example", "VRPC_NODE_URL=http://<host>:<port> pnpm example:03-vrpc-core-walkthrough");
    return;
  }
  kv("Node", NODE_URL);
  kv("Chain id (signed into pre-image)", CHAIN_ID);

  // ── Step 1 — Make a request and read the signed wire ───────────────────────
  // A vRPC response is an ordinary JSON-RPC body PLUS three headers the sidecar
  // adds inside the TEE: vRPC-Signature, vRPC-Timestamp, vRPC-Pubkey. We send
  // `accept-encoding: identity` so the bytes we hash are byte-for-byte the wire
  // bytes (defense-in-depth; v0.2.0 signs the content-decoded body either way).
  header("Step 1 — request + signed response headers");
  const requestBody = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBlockByNumber",
    params: ["latest", false],
  });
  const requestBytes = enc.encode(requestBody);

  const res = await fetch(NODE_URL, {
    method: "POST",
    headers: { "content-type": "application/json", "accept-encoding": "identity" },
    body: requestBody,
  });
  const responseBytes = new Uint8Array(await res.arrayBuffer());

  kv("HTTP status", res.status);
  kv("vRPC-Pubkey", res.headers.get("vRPC-Pubkey"));
  kv("vRPC-Timestamp", res.headers.get("vRPC-Timestamp"));
  kv("vRPC-Signature", `${res.headers.get("vRPC-Signature")?.slice(0, 26)}…`);

  // ── Step 2 — Verify the signature ──────────────────────────────────────────
  // verifyResponse reconstructs the canonical 80-byte pre-image
  // (chainId ‖ sha256(request) ‖ sha256(response) ‖ timestamp) and checks the
  // Ed25519 signature over it. Success = these exact bytes were produced by the
  // holder of vRPC-Pubkey, for THIS request, on THIS chain, at THAT time.
  header("Step 2 — verifyResponse()");
  const verified: VerifiedPair = await verifyResponse(requestBytes, responseBytes, res.headers, {
    chainId: CHAIN_ID,
  });
  kv("Verified ✓ signer pubkey", verified.verification.pubkeyHex);
  kv("Signed timestamp (ms)", verified.verification.timestampMs);
  kv("pre-image sha256", hex(verified.verification.preImageSha256));
  const block = JSON.parse(Buffer.from(verified.responseBytes).toString("utf8")) as {
    result?: { number?: string };
  };
  kv("Verified result — block number", block.result?.number);

  // ── Step 3 — Tamper detection (fail-closed) ────────────────────────────────
  // Flip a single byte of the verified body and re-verify. The signature no
  // longer matches the pre-image → BadSignature. The SDK never returns data it
  // could not prove: verification failure is an exception, not a flag.
  header("Step 3 — tamper one byte → BadSignature");
  const tampered = Uint8Array.from(responseBytes);
  const i = Math.floor(tampered.length / 2);
  tampered[i] = (tampered[i] ?? 0) ^ 0xff;
  try {
    await verifyResponse(requestBytes, tampered, res.headers, { chainId: CHAIN_ID });
    assert(false, "tampered response unexpectedly verified");
  } catch (err) {
    assert(err instanceof BadSignature, `expected BadSignature, got ${(err as Error).name}`);
    kv("Rejected ✓ (as expected)", "BadSignature");
  }

  // ── Step 4 — Anchor trust in the TEE (attestation) ─────────────────────────
  // Step 2 proves a KEY signed the bytes. Attestation proves that key lives
  // inside an attested TDX enclave running the approved image. We fetch a fresh
  // quote bound to a random nonce, then correlate: the attestation's pubkey MUST
  // equal the key that signed our response.
  header("Step 4 — fetchAttestation() + correlation");
  const nonce = crypto.randomBytes(32);
  const attestation = await fetchAttestation({
    attestationUrl: `${NODE_URL}/attestation`,
    nonce,
  });
  kv("Attestation pubkey", attestation.pubkey);
  kv("Attestation composeHash", attestation.composeHash);
  kv(
    "Matches pinned composeHash?",
    PINNED_COMPOSE_HASH === ""
      ? "(no pin — set VRPC_NODE_COMPOSE_HASH)"
      : attestation.composeHash === PINNED_COMPOSE_HASH
        ? "yes ✓"
        : "NO ✗",
  );
  verifyAttestationCorrelation(attestation, verified);
  kv("Correlation ✓", "attestation pubkey == response signer");
  console.log(
    "\n  NOTE: in v6.0 the TDX quote's own cryptographic verification is a mock\n" +
      "  (frozen contract). Real DCAP quote verification lands in v7.0.",
  );

  // ── Step 5 — The everyday one-liner ────────────────────────────────────────
  // VerifierClient wraps steps 1-2: it POSTs, verifies, and hands back a typed
  // result. This is exactly what the ethers/viem adapters use under the hood.
  header("Step 5 — VerifierClient (steps 1-2 in one call)");
  const client = new VerifierClient(NODE_URL, { chainId: CHAIN_ID });
  const r = await client.call<string>("eth_blockNumber", []);
  kv("eth_blockNumber (verified)", r.result);
  kv("Signer pubkey", r.verification.pubkeyHex);

  header("Done — response verified, key attested, tamper rejected");
}

main().catch((err) => {
  console.error("\nFAIL —", err);
  process.exit(1);
});
