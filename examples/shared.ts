// Shared helpers for the examples. The verifiable node the vrpc-core walkthrough
// (03) talks to is supplied via env — NO node address is hardcoded in the repo.
// When `VRPC_NODE_URL` is unset, `NODE_CONFIGURED` is false and the walkthrough
// skips with a hint (like the ethers/viem examples).
//
//   VRPC_NODE_URL          verifiable node base URL, e.g. http://<host>:<port>
//   VRPC_NODE_CHAIN_ID     chain_id baked into the signed pre-image (default 42161 = Arbitrum).
//                          MUST match the sidecar's SIDECAR_CHAIN_ID, else every call → BadSignature.
//   VRPC_NODE_COMPOSE_HASH (optional) expected /attestation composeHash to compare against.

export const URL = process.env.VRPC_NODE_URL ?? "http://127.0.0.1:1234";
export const NODE_CONFIGURED = (process.env.VRPC_NODE_URL ?? "").length > 0;
export const CHAIN_ID = BigInt(process.env.VRPC_NODE_CHAIN_ID ?? "42161");
export const PINNED_COMPOSE_HASH = process.env.VRPC_NODE_COMPOSE_HASH ?? "";

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
