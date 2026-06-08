// 04 — End-to-end: attest → trust pubkey → signed call → assert continuity.
//
// The shape an integrator would actually write: at boot, fetch a fresh
// attestation and anchor trust in its pubkey (with the caveat that compose-hash
// provenance is the user's responsibility for now — see README). Then make
// signed RPC calls and require that the signature pubkey matches the one
// that came back inside the attestation.
//
// This is what makes the "you talked to an unmodified, approved nitro client
// inside a TDX CVM" claim cash out at the application layer.

import { VerifierClient, fetchAttestation } from "../src/index.ts";
import {
	CHAIN_ID,
	PINNED_COMPOSE_HASH,
	URL,
	assert,
	header,
	kv,
} from "./shared.ts";

header(
	"04 — end-to-end: attest → trust pubkey → signed call → verify pubkey match",
);

// Step 1: fetch attestation, anchor trust in the returned pubkey.
const nonce = crypto.getRandomValues(new Uint8Array(32));
const att = await fetchAttestation(URL, nonce);

assert(
	att.composeHash === PINNED_COMPOSE_HASH,
	`composeHash mismatch — sidecar redeployed?\n  got:    ${att.composeHash}\n  pinned: ${PINNED_COMPOSE_HASH}`,
);
kv("step 1 — attested pubkey", att.pubkey);
kv("step 1 — composeHash matches pinned", "YES");

// Step 2: make a signed RPC call.
const client = new VerifierClient(URL, { chainId: CHAIN_ID });
const r = await client.call<string>("eth_blockNumber", []);
kv("step 2 — blockNumber (dec)", BigInt(r.result).toString());
kv("step 2 — call pubkey       ", r.verification.pubkeyHex);

// Step 3: the SDK-verified signer must be the same key the attestation
// proved is bound to the TDX-measured compose-hash.
assert(
	r.verification.pubkeyHex.toLowerCase() === att.pubkey.toLowerCase(),
	`pubkey mismatch between attestation and signed call:\n  attestation: ${att.pubkey}\n  call:        ${r.verification.pubkeyHex}`,
);
kv("step 3 — pubkey match", "OK — same signer across attestation + call");

console.log(
	"\nPASS — end-to-end pipeline verified: fetched attestation → trusted pubkey → signed call → pubkey continuity.",
);
