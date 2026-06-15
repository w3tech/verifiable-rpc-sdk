// 07 — full trustless attestation-correlation loop, entirely through stage shark.
//
// Closes the loop example 06 could not: signed `.call()` through shark →
// capture the serving node's id (`vRPC-NodeId`) and pubkey (`vRPC-Pubkey`) →
// fetch THAT node's attestation THROUGH shark by node_id with a fresh random
// nonce → assert the attestation pubkey equals the RPC pubkey. The node_id hop
// needs no trust: correlation enforces attestation.pubkey === vRPC-Pubkey, so a
// wrong node can only fail the check, never spoof it. A negative path proves a
// bogus node_id surfaces the typed AttestationNodeNotFoundError (404) with no
// retry and no fallback node.
//
// The vrpc route is `<shark-url>/arbitrum_vrpc`; auth is `x-api-key` passed via
// the SDK's first-class `apiKey` option. Both SHARK_STAGE_URL and
// SHARK_STAGE_TDX_TEST_KEY are SECRETS: read via env by NAME, never
// printed/logged/committed (only "set" is shown).

import {
	AttestationNodeNotFoundError,
	VerifierClient,
	fetchAttestationViaShark,
	verifyAttestationCorrelation,
} from "../src/index.ts";
import {
	CHAIN_ID,
	SHARK_STAGE_TDX_TEST_KEY,
	SHARK_STAGE_URL,
	assert,
	header,
	kv,
	requireEnv,
} from "./shared.ts";

header("07 — full trustless correlation loop via stage shark");

const sharkUrl = requireEnv("SHARK_STAGE_URL", SHARK_STAGE_URL);
const apiKey = requireEnv("SHARK_STAGE_TDX_TEST_KEY", SHARK_STAGE_TDX_TEST_KEY);
const vrpcUrl = `${sharkUrl}/arbitrum_vrpc`;

// Never print the secret URL / key — only confirm they are set.
kv("SHARK_STAGE_URL", "set");
kv("SHARK_STAGE_TDX_TEST_KEY", "set");
kv("vrpc route suffix", "/arbitrum_vrpc");

// ── HAPPY PATH ────────────────────────────────────────────────────────────────

// 1. Signed call through shark. apiKey sets `x-api-key` on the RPC POST. A
//    successful return IS the Ed25519 verification of the response (the client
//    throws BadSignature otherwise), so no separate verify step is needed.
const client = new VerifierClient(vrpcUrl, { chainId: CHAIN_ID, apiKey });
const r = await client.call<string>("eth_blockNumber", []);

kv("result.blockNumber (hex)", r.result);
kv("result.blockNumber (dec)", BigInt(r.result).toString());
kv("verification.signatureHex", r.verification.signatureHex);
kv("verification.pubkeyHex", r.verification.pubkeyHex);

assert(
	typeof r.result === "string" && r.result.startsWith("0x"),
	"blockNumber must be 0x-prefixed hex",
);
assert(
	r.verification.signatureHex.startsWith("0x") && r.verification.signatureHex.length === 130,
	"signatureHex must be 0x + 128 hex chars",
);
assert(
	r.verification.pubkeyHex.startsWith("0x") && r.verification.pubkeyHex.length === 66,
	"pubkeyHex must be 0x + 64 hex chars",
);

// 2. Capture the serving node id + the pubkey we will correlate against.
const nodeId = r.nodeId;
const expectedPubkey = r.verification.pubkeyHex;
assert(
	nodeId !== undefined,
	"stage shark must send vRPC-NodeId — is it running v0.26.21-rc.vrpc.1?",
);
kv("vRPC-NodeId", nodeId);
kv("expected pubkey (vRPC-Pubkey)", expectedPubkey);

// 3. Fresh random 32-byte attestation nonce.
const nonce = crypto.getRandomValues(new Uint8Array(32));

// 4. Fetch THIS node's attestation THROUGH shark:
//    GET <sharkUrl>/arbitrum_vrpc/attestation?nonce=<hex>&node_id=<id>
const attestation = await fetchAttestationViaShark({
	sharkBase: sharkUrl,
	chain: "arbitrum",
	nodeId,
	nonce,
	apiKey,
});
kv("attestation fetched via shark", "OK (by node_id)");
kv("attestation pubkey", attestation.pubkey);

// 5. Correlation: throws AttestationCorrelationError on pubkey mismatch; a clean
//    return proves attestation.pubkey === vRPC-Pubkey.
verifyAttestationCorrelation(attestation, r);
kv("pubkey correlation", "OK (attestation pubkey == vRPC-Pubkey)");

// 6. Nonce-in-REPORTDATA binding is validated by the attestation parse path;
//    surface report_data presence here. The report_data == pubkey ‖ nonce hash
//    check itself is pinned by example 03 — not re-implemented here.
assert(attestation.quote.report_data.length > 0, "attestation report_data must be present");
kv("report_data present", `${attestation.quote.report_data.length} hex chars`);

// ── NEGATIVE PATH: bogus node_id → typed 404, no fallback ─────────────────────

const bogusNodeId = "vrpc-node-does-not-exist-0000";
const negNonce = crypto.getRandomValues(new Uint8Array(32));
let caught: unknown;
try {
	await fetchAttestationViaShark({
		sharkBase: sharkUrl,
		chain: "arbitrum",
		nodeId: bogusNodeId,
		nonce: negNonce,
		apiKey,
	});
	// Must not resolve — the SDK never retries another node.
	assert(false, "bogus node_id must throw AttestationNodeNotFoundError, not resolve");
} catch (err) {
	caught = err;
}
assert(
	caught instanceof AttestationNodeNotFoundError,
	`bogus node_id must surface AttestationNodeNotFoundError, got ${(caught as Error)?.name}`,
);
kv("bogus node_id → typed 404", "AttestationNodeNotFoundError");

console.log(
	"\nPASS — trustless loop closes through shark: signed call verified, attestation fetched via shark by node_id, pubkey correlation OK, bogus node_id surfaces typed 404",
);
