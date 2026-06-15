// 01 — signed eth_blockNumber via VerifierClient.
//
// Smallest possible "the SDK works against a live TDX-hosted node" smoke test.
// VerifierClient does the JSON-RPC envelope, the pre-image reconstruction,
// and the Ed25519 verify; this script just asserts the returned shape is
// well-formed and prints the verification metadata for human inspection.

import { VerifierClient } from "../src/index.ts";
import { CHAIN_ID, URL, assert, header, kv } from "./shared.ts";

header("01 — signed eth_blockNumber via VerifierClient");

const client = new VerifierClient(URL, { chainId: CHAIN_ID });
const r = await client.call<string>("eth_blockNumber", []);

kv("result.blockNumber (hex)", r.result);
kv("result.blockNumber (dec)", BigInt(r.result).toString());
kv("verification.signatureHex", r.verification.signatureHex);
kv("verification.pubkeyHex", r.verification.pubkeyHex);
kv("verification.timestampMs", r.verification.timestampMs.toString());
kv(
	"verification.preImageSha256 (hex)",
	Buffer.from(r.verification.preImageSha256).toString("hex"),
);

assert(
	r.verification.signatureHex.startsWith("0x") &&
		r.verification.signatureHex.length === 130,
	"signatureHex must be 0x + 128 hex chars",
);
assert(
	r.verification.pubkeyHex.startsWith("0x") &&
		r.verification.pubkeyHex.length === 66,
	"pubkeyHex must be 0x + 64 hex chars",
);
assert(
	r.verification.preImageSha256.length === 32,
	"preImageSha256 must be 32 bytes",
);
assert(
	typeof r.result === "string" && r.result.startsWith("0x"),
	"blockNumber must be 0x-prefixed hex",
);

console.log(
	"\nPASS — signature verified by SDK, all verification fields well-formed.",
);
