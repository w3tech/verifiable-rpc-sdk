// Shared helpers for the examples — keeps each script self-explanatory while
// not repeating the pinned config.
//
// `URL` is the live direct TDX node used by the vrpc-core walkthrough (03).
// `PINNED_COMPOSE_HASH` was last re-pinned 2026-06-23 to the node's current
// /attestation composeHash (sidecar v0.2.0, compression-aware signing — the
// signature covers the content-DECODED body). Until a ComposeSource/registry
// lands this must be re-pinned by hand whenever the node is redeployed (DEC-03).

export const URL = "http://40.160.13.104:15269";
// chain_id baked into the canonical pre-image by the sidecar — NOT the
// upstream node's reported eth_chainId. Set at sidecar startup; if mismatched
// against the SDK's `chainId` opt, every `.call()` throws BadSignature.
// 42161n = Arbitrum, matching the live node's SIDECAR_CHAIN_ID="42161".
export const CHAIN_ID = 42161n;
export const PINNED_COMPOSE_HASH =
  "e8f728881fa14582f08465431b67c4ee80aa460b592f82ddcddda21b37d02ce3";

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
