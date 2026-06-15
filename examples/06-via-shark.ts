// 06 — verifier SDK through stage shark-proxy (vrpc passthrough).
//
// Proves the SDK verifies a signed call routed THROUGH stage shark-proxy. Shark
// was updated to pass request/response bytes through unmodified for vrpc
// routes; a passing signed `.call()` through shark IS the cryptographic proof
// of byte-exact passthrough — the 80-byte pre-image binds request_hash +
// response_hash, so any mutation in either direction surfaces as BadSignature.
//
// The vrpc route is `<shark-url>/arbitrum_vrpc` with auth header
// `x-api-key: <key>`. Both SHARK_STAGE_URL and SHARK_STAGE_TDX_TEST_KEY are
// SECRETS: read via env, never printed/logged/committed (only "set" is shown).
//
// Shark does NOT serve /attestation yet, so the pubkey cross-check fetches
// attestation DIRECT from the node (URL from shared.ts), NOT through shark.

import { fetchAttestation, VerifierClient } from "@ankr.com/vrpc-core";
import {
  assert,
  CHAIN_ID,
  header,
  kv,
  requireEnv,
  SHARK_STAGE_TDX_TEST_KEY,
  SHARK_STAGE_URL,
  URL,
} from "./shared.ts";

const VRPC_HEADERS = ["vRPC-Signature", "vRPC-Pubkey", "vRPC-Timestamp"] as const;

/** The eth_blockNumber envelope, serialized ONCE so request bytes are stable. */
function blockNumberEnvelope(id: number): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id, method: "eth_blockNumber", params: [] }),
  );
}

header("06 — verifier SDK through stage shark (vrpc passthrough)");

const sharkUrl = requireEnv("SHARK_STAGE_URL", SHARK_STAGE_URL);
const apiKey = requireEnv("SHARK_STAGE_TDX_TEST_KEY", SHARK_STAGE_TDX_TEST_KEY);
const vrpcUrl = `${sharkUrl}/arbitrum_vrpc`;

// Never print the secret URL / key — only confirm they are set.
kv("SHARK_STAGE_URL", "set");
kv("SHARK_STAGE_TDX_TEST_KEY", "set");
kv("vrpc route suffix", "/arbitrum_vrpc");

// ── PRIMARY PROOF: signed .call() through shark ───────────────────────────────
// A successful return proves the vrpc headers arrived through shark AND the
// request+response bytes passed through unmodified (else BadSignature).
let viaSharkPubkey: string | undefined;
try {
  const client = new VerifierClient(vrpcUrl, {
    chainId: CHAIN_ID,
    headers: { "x-api-key": apiKey },
  });
  const r = await client.call<string>("eth_blockNumber", []);

  kv("result.blockNumber (hex)", r.result);
  kv("result.blockNumber (dec)", BigInt(r.result).toString());
  kv("verification.signatureHex", r.verification.signatureHex);
  kv("verification.pubkeyHex", r.verification.pubkeyHex);
  kv("verification.timestampMs", r.verification.timestampMs.toString());

  assert(
    r.verification.signatureHex.startsWith("0x") && r.verification.signatureHex.length === 130,
    "signatureHex must be 0x + 128 hex chars",
  );
  assert(
    r.verification.pubkeyHex.startsWith("0x") && r.verification.pubkeyHex.length === 66,
    "pubkeyHex must be 0x + 64 hex chars",
  );
  assert(r.verification.preImageSha256.length === 32, "preImageSha256 must be 32 bytes");
  assert(
    typeof r.result === "string" && r.result.startsWith("0x"),
    "blockNumber must be 0x-prefixed hex",
  );

  viaSharkPubkey = r.verification.pubkeyHex.toLowerCase();
  kv("signed .call() through shark", "VERIFIED (byte-exact passthrough)");
} catch (err) {
  // ── FAILURE LOCALIZATION ────────────────────────────────────────────────
  // Localize the broken leg with raw fetches: headers stripped? body mutated?
  console.error(
    `\nverify through shark FAILED: ${(err as Error)?.name}: ${(err as Error)?.message}`,
  );
  header("DIAGNOSTIC — localizing the broken leg");

  const reqBytes = blockNumberEnvelope(1);

  // (a) via-shark raw fetch — which vrpc headers survived?
  const viaShark = await fetch(vrpcUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept-encoding": "identity",
      "x-api-key": apiKey,
    },
    body: reqBytes,
  });
  kv("via-shark HTTP status", viaShark.status);
  for (const h of VRPC_HEADERS) {
    kv(`via-shark ${h}`, viaShark.headers.get(h) === null ? "MISSING" : "present");
  }
  const viaSharkBytes = new Uint8Array(await viaShark.arrayBuffer());
  kv("via-shark response length", viaSharkBytes.length);

  // (b) direct-node raw fetch (no x-api-key) — byte-compare same request.
  const direct = await fetch(URL, {
    method: "POST",
    headers: { "content-type": "application/json", "accept-encoding": "identity" },
    body: reqBytes,
  });
  const directBytes = new Uint8Array(await direct.arrayBuffer());
  kv("direct-node response length", directBytes.length);

  const bytesEqual = Buffer.compare(Buffer.from(viaSharkBytes), Buffer.from(directBytes)) === 0;
  kv("response bytes via-shark == direct", bytesEqual ? "true" : "false (BODY MUTATED)");

  const anyHeaderMissing = VRPC_HEADERS.some((h) => viaShark.headers.get(h) === null);
  if (anyHeaderMissing) {
    console.error("\nFAIL — broken leg: shark STRIPPED one or more vRPC-* headers.");
  } else if (!bytesEqual) {
    console.error("\nFAIL — broken leg: shark MUTATED the response body bytes.");
  } else {
    console.error(
      "\nFAIL — headers present and body bytes match direct; broken leg is the REQUEST bytes (shark mutated the request before the node signed it).",
    );
  }
  process.exit(1);
}

// ── PUBKEY CROSS-CHECK: attestation fetched DIRECT from the node ──────────────
// Shark does not serve /attestation; anchor trust against the node directly.
const nonce = crypto.getRandomValues(new Uint8Array(32));
const attestation = await fetchAttestation(URL, nonce);
const directPubkey = attestation.pubkey.toLowerCase();

kv("via-shark pubkey", viaSharkPubkey);
kv("direct-node /attestation pubkey", directPubkey);
assert(
  directPubkey === viaSharkPubkey,
  "via-shark pubkey must equal the direct node /attestation pubkey",
);

// One-line supporting summary on the happy path: confirm headers present too.
const supp = await fetch(vrpcUrl, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "accept-encoding": "identity",
    "x-api-key": apiKey,
  },
  body: blockNumberEnvelope(99),
});
await supp.arrayBuffer();
const headersPresent = VRPC_HEADERS.every((h) => supp.headers.get(h) !== null);
kv("vRPC-* headers survive shark", headersPresent ? "true (all present)" : "false");
assert(headersPresent, "all three vRPC-* headers must survive shark");

console.log(
  "\nPASS — SDK verifies through stage shark; bytes pass through unmodified; pubkey matches direct node /attestation",
);
