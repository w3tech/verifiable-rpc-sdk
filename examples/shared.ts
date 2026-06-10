// Shared helpers for the live examples — keeps each script self-explanatory
// while not repeating the pinned config in four places.
//
// The scripts target the live TDX node. The node was redeployed
// 2026-06-10 (sidecar v0.2.0 release, compression-aware signing — the signature
// now covers the content-DECODED body); `PINNED_COMPOSE_HASH` re-pinned to
// match the /info.compose_hash of the v0.2.0 app-compose.
// Until a ComposeSource/registry lands this must be re-pinned by hand (DEC-03).

export const URL = "http://40.160.13.104:15269";
// chain_id baked into the canonical pre-image by the sidecar — NOT the
// upstream node's reported eth_chainId. Set at sidecar startup; if mismatched
// against the SDK's `chainId` opt, every `.call()` throws BadSignature.
// 42161n = Arbitrum, matching the live node's SIDECAR_CHAIN_ID="42161".
export const CHAIN_ID = 42161n;
export const PINNED_COMPOSE_HASH =
	"287a19287bb1d6c798e8cc80aacf0e33d7f1c6982ba28c6135bf4aa3e4b1024e";

// Stage shark-proxy config for the via-shark example (06). Read by NAME only —
// the VALUES are secrets and must never be printed, logged, or committed.
export const SHARK_STAGE_URL: string | undefined = Bun.env.SHARK_STAGE_URL;
export const SHARK_STAGE_TDX_TEST_KEY: string | undefined = Bun.env.SHARK_STAGE_TDX_TEST_KEY;

/**
 * Return `value` if set, else fail loudly WITHOUT printing the value. `name` is
 * the env var name (safe to print); the value is a secret.
 */
export function requireEnv(name: string, value: string | undefined): string {
	assert(
		typeof value === "string" && value.length > 0,
		`${name} env var must be set (not printing its value)`,
	);
	return value;
}

export function header(title: string): void {
	const bar = "=".repeat(64);
	console.log(`\n${bar}\n  ${title}\n${bar}`);
}

export function kv(label: string, value: unknown): void {
	console.log(`  ${label.padEnd(38)} ${String(value)}`);
}

export function assert(cond: unknown, msg: string): asserts cond {
	if (!cond) {
		console.error(`\nFAIL — ${msg}`);
		process.exit(1);
	}
}
