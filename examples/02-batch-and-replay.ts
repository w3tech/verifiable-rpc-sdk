// 02 — Sequential signed calls + replay-window skew check + pubkey stability.
//
// Runs N JSON-RPC methods through the same VerifierClient instance, each
// independently signed by the sidecar. Asserts:
//   - every call returns a VerifiedResponse (SDK would have thrown otherwise)
//   - the pubkey is stable across calls within a single sidecar lifetime
//   - |timestampMs - now| stays inside the configured replay window
//
// The SDK already enforces the replay window inside `.call`; we additionally
// print the skew so a human can see how tight the clocks are.

import { VerifierClient } from "@ankr.com/vrpc-core";
import { assert, CHAIN_ID, header, kv, URL } from "./shared.ts";

header("02 — N sequential signed calls + replay-window check");

const REPLAY_MS = 60_000;
const client = new VerifierClient(URL, {
  chainId: CHAIN_ID,
  replayWindowMs: REPLAY_MS,
});

const calls: Array<{ method: string; params: unknown[] }> = [
  { method: "eth_blockNumber", params: [] },
  { method: "eth_chainId", params: [] },
  { method: "net_version", params: [] },
  { method: "web3_clientVersion", params: [] },
];

let pubkeySeen: string | null = null;

for (const c of calls) {
  const before = Date.now();
  const r = await client.call<string>(c.method, c.params);
  const skew = Math.abs(Number(r.verification.timestampMs) - before);

  kv(`${c.method} → result`, r.result);
  kv(`${c.method} → timestamp skew ms`, skew);

  if (pubkeySeen === null) pubkeySeen = r.verification.pubkeyHex;
  assert(r.verification.pubkeyHex === pubkeySeen, "pubkey changed mid-session — unexpected");
  assert(skew <= REPLAY_MS, `timestamp skew ${skew}ms exceeds ${REPLAY_MS}ms replay window`);
}

console.log(`\nPASS — ${calls.length} calls verified, replay window respected, pubkey stable.`);
