// 05 — gzip-transport crypto evidence (ENC-04).
//
// Proves the deployed sidecar (v0.2.0-rc.1) signs the content-DECODED body,
// not the compressed wire bytes. This is THE cryptographic evidence for
// ENC-04: a real signed gzip response is decoded and its Ed25519 signature
// verifies over the decoded plaintext — and the negative control (verifying
// over the compressed bytes) FAILS, proving the signature covers decoded bytes.
//
// Unlike 01-04 this script does NOT use VerifierClient (which pins
// accept-encoding: identity). It drives raw fetch with Accept-Encoding: gzip
// and the SDK's verify primitives (buildPreImage + @noble/ed25519 verifyAsync)
// directly, so we exercise the gzip transport path end to end.

import { verifyAsync } from "@noble/ed25519";

import { buildPreImage } from "../src/index.ts";
import { CHAIN_ID, URL, assert, header, kv } from "./shared.ts";

const EXPECTED_PUBKEY =
	"0x27c6308b5bdb7d8ad6d727c9e749947059e59fc2b3b9a47d443ba34838d393ac";

/** Convert `0x...` lowercase hex to a Uint8Array. Mirrors src/verifier.ts. */
function hexToBytes(hex0x: string): Uint8Array {
	const stripped = hex0x.startsWith("0x") ? hex0x.slice(2) : hex0x;
	const out = new Uint8Array(stripped.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

header("05 — gzip-transport: signature over content-decoded body (ENC-04)");

// Serialize the JSON-RPC envelope ONCE so the bytes we POST are byte-identical
// to the bytes we hash for the request_hash leg of the pre-image.
const requestBytes = new TextEncoder().encode(
	JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
);

// Fetch with decompression disabled (Bun extension) so we can inspect the RAW
// wire bytes the proxy put on the socket. Accept-Encoding: gzip asks the
// sidecar's CompressionLayer to re-encode for this client.
const resp = await fetch(URL, {
	method: "POST",
	headers: { "content-type": "application/json", "accept-encoding": "gzip" },
	body: requestBytes,
	// @ts-expect-error Bun-specific: keep raw compressed bytes for the negative control
	decompress: false,
});

assert(resp.status === 200, `HTTP 200 expected, got ${resp.status}`);

const contentEncoding = (resp.headers.get("content-encoding") ?? "identity").toLowerCase();
const isGzip = contentEncoding === "gzip";
kv("content-encoding (wire)", contentEncoding);
kv("transport path exercised", isGzip ? "gzip" : "identity");

// Raw wire bytes (compressed when isGzip, plaintext otherwise).
const wireBytes = new Uint8Array(await resp.arrayBuffer());
kv("wire body length (bytes)", wireBytes.length);

if (isGzip) {
	assert(
		wireBytes[0] === 0x1f && wireBytes[1] === 0x8b,
		"content-encoding: gzip but wire bytes lack the gzip magic (1f 8b)",
	);
}

// The DECODED plaintext bytes are what the sidecar signed.
const decodedBytes = isGzip ? new Uint8Array(Bun.gunzipSync(wireBytes)) : wireBytes;
kv("decoded body length (bytes)", decodedBytes.length);
kv("decoded body (json)", new TextDecoder().decode(decodedBytes));

// Header parse (case-insensitive on fetch Headers.get).
const sigHex = resp.headers.get("vRPC-Signature");
const pubkeyHex = resp.headers.get("vRPC-Pubkey");
const tsRaw = resp.headers.get("vRPC-Timestamp");
assert(sigHex !== null, "vRPC-Signature header present");
assert(pubkeyHex !== null, "vRPC-Pubkey header present");
assert(tsRaw !== null, "vRPC-Timestamp header present");
assert(/^0x[0-9a-f]{128}$/.test(sigHex), "vRPC-Signature is 0x + 128 hex");
assert(/^0x[0-9a-f]{64}$/.test(pubkeyHex), "vRPC-Pubkey is 0x + 64 hex");
assert(/^\d+$/.test(tsRaw), "vRPC-Timestamp is a decimal u64");

kv("vRPC-Pubkey", pubkeyHex);
kv("vRPC-Signature", sigHex);
kv("vRPC-Timestamp", tsRaw);

assert(
	pubkeyHex.toLowerCase() === EXPECTED_PUBKEY,
	`pubkey must equal the attested sidecar key ${EXPECTED_PUBKEY}`,
);

const sigBytes = hexToBytes(sigHex);
const pubkeyBytes = hexToBytes(pubkeyHex);
const timestampMs = BigInt(tsRaw);

// POSITIVE: pre-image over the DECODED body must verify.
const preImageDecoded = buildPreImage(CHAIN_ID, requestBytes, decodedBytes, timestampMs);
const okDecoded = await verifyAsync(sigBytes, preImageDecoded, pubkeyBytes);
kv("verify over DECODED body", okDecoded ? "true (PASS)" : "false");
assert(okDecoded, "Ed25519 signature MUST verify over the content-decoded body");

// NEGATIVE control: when the gzip path is active, pre-image over the COMPRESSED
// wire bytes MUST fail — proving the signature covers decoded, not compressed,
// bytes. On the identity path wire == decoded, so the control is not applicable.
if (isGzip) {
	const preImageCompressed = buildPreImage(CHAIN_ID, requestBytes, wireBytes, timestampMs);
	const okCompressed = await verifyAsync(sigBytes, preImageCompressed, pubkeyBytes);
	kv("verify over COMPRESSED bytes", okCompressed ? "true" : "false (expected fail)");
	assert(
		!okCompressed,
		"negative control failed: signature verified over COMPRESSED bytes — sidecar is not signing the decoded body",
	);
} else {
	kv("negative control", "skipped — identity path (wire == decoded)");
}

console.log(
	`\nPASS — signature verifies over content-decoded body (${isGzip ? "gzip" : "identity"} path)`,
);
