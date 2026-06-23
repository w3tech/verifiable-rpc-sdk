// 02 — viem client: a drop-in verified transport.
//
// `vrpcHttp` is a viem Transport you pass to `createPublicClient`. You then use
// the client like any viem public client (getBlock, getTransaction, getBalance);
// every response is cryptographically verified (Ed25519 + TDX attestation)
// inside the transport before viem decodes it. Symmetric with example 01.
//
// Set these env vars, then run `pnpm example:02-viem-client`:
//
//   VRPC_RPC_URL=https://rpc.ankr.com/arbitrum   # your vRPC endpoint
//   VRPC_API_KEY=<your Ankr API key>
//   VRPC_CHAIN_ID=42161                           # optional, defaults to 42161

import { vrpcHttp } from "@ankr.com/vrpc-viem";
import { createPublicClient } from "viem";

import { header, kv } from "./shared.js";

const RPC_URL = process.env.VRPC_RPC_URL;
const API_KEY = process.env.VRPC_API_KEY;
const CHAIN_ID = BigInt(process.env.VRPC_CHAIN_ID ?? "42161");
const ZERO = "0x0000000000000000000000000000000000000000";

async function main(): Promise<void> {
  header("viem client — verified reads via vrpcHttp transport");

  if (!RPC_URL || !API_KEY) {
    kv("Skipped", "set VRPC_RPC_URL and VRPC_API_KEY to run this example");
    kv(
      "Example",
      "VRPC_RPC_URL=https://rpc.ankr.com/arbitrum VRPC_API_KEY=… pnpm example:02-viem-client",
    );
    return;
  }

  // Wire the verified transport into a normal viem public client. `headers`
  // authenticates the RPC leg; `apiKey` authenticates the attestation leg.
  const client = createPublicClient({
    transport: vrpcHttp(RPC_URL, {
      chainId: CHAIN_ID,
      headers: { "x-api-key": API_KEY },
      apiKey: API_KEY,
    }),
  });
  kv("Endpoint", RPC_URL);
  kv("Chain id", CHAIN_ID);

  // get block (with its transactions)
  const blockNumber = await client.getBlockNumber();
  const block = await client.getBlock({ blockNumber, includeTransactions: true });
  kv("Latest block", blockNumber);
  kv("  tx count", block.transactions.length);

  // get a transaction from that block
  const first = block.transactions[0];
  if (first) {
    const tx = await client.getTransaction({ hash: first.hash });
    kv("First tx", first.hash);
    kv("  from", tx.from);
    kv("  value (wei)", tx.value.toString());
  }

  // get a balance
  const balanceTarget = first ? first.from : ZERO;
  const balance = await client.getBalance({ address: balanceTarget });
  kv("Balance of", balanceTarget);
  kv("  wei", balance.toString());

  header("Done — every response above was verified before viem returned it");
}

main().catch((err) => {
  console.error("\nFAIL —", err);
  process.exit(1);
});
