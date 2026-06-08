// Shared helpers for the live examples — keeps each script self-explanatory
// while not repeating the pinned config in four places.
//
// All four scripts target the live TDX node. The node was redeployed
// 2026-06-08 (sidecar v0.1.1-rc.3); `PINNED_COMPOSE_HASH` re-pinned to match.
// Until a ComposeSource/registry lands this must be re-pinned by hand (DEC-03).

export const URL = "http://40.160.13.104:15269";
// chain_id baked into the canonical pre-image by the sidecar — NOT the
// upstream node's reported eth_chainId. Set at sidecar startup; if mismatched
// against the SDK's `chainId` opt, every `.call()` throws BadSignature.
// 42161n = Arbitrum, matching the live node's SIDECAR_CHAIN_ID="42161".
export const CHAIN_ID = 42161n;
export const PINNED_COMPOSE_HASH =
	"ed22ab89412e6df756fe428f06bbe2fd4d5e769e4891b64db0737ebcb7380c52";

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
