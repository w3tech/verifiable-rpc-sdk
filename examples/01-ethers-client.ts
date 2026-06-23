// 01 — ethers client: a drop-in verified provider.
//
// `VrpcProvider` is a normal ethers v6 provider — you create it and call the
// usual methods (getBlock, getTransaction, getBalance). The difference is that
// every JSON-RPC response is cryptographically verified (Ed25519 + TDX
// attestation) before ethers ever sees it; a tampered response throws instead
// of returning bad data.
//
// Point it at a shark-routed vRPC endpoint (the SDK owns the `_vrpc` suffix and
// the attestation sub-route). Set these env vars, then run
// `pnpm example:01-ethers-client`:
//
//   VRPC_RPC_URL=https://rpc.ankr.com/arbitrum   # your vRPC endpoint
//   VRPC_API_KEY=<your Ankr API key>
//   VRPC_CHAIN_ID=42161                           # optional, defaults to 42161

import { VrpcProvider } from "@ankr.com/vrpc-ethers";
import { FetchRequest } from "ethers";

import { header, kv } from "./shared.js";

const RPC_URL = process.env.VRPC_RPC_URL;
const API_KEY = process.env.VRPC_API_KEY;
const CHAIN_ID = BigInt(process.env.VRPC_CHAIN_ID ?? "42161");
const ZERO = "0x0000000000000000000000000000000000000000";

async function main(): Promise<void> {
  header("ethers client — verified reads via VrpcProvider");

  if (!RPC_URL || !API_KEY) {
    kv("Skipped", "set VRPC_RPC_URL and VRPC_API_KEY to run this example");
    kv(
      "Example",
      "VRPC_RPC_URL=https://rpc.ankr.com/arbitrum VRPC_API_KEY=… pnpm example:01-ethers-client",
    );
    return;
  }

  // Create the client exactly like a normal ethers provider. Set auth the
  // idiomatic ethers way — on the FetchRequest. The SDK reuses these headers for
  // BOTH the RPC POST and the internal attestation fetch, so there is no
  // separate apiKey option.
  const req = new FetchRequest(RPC_URL);
  req.setHeader("x-api-key", API_KEY);
  const provider = new VrpcProvider(req, CHAIN_ID);
  kv("Endpoint", RPC_URL);
  kv("Chain id", CHAIN_ID);

  // get block (with its transactions)
  const blockNumber = await provider.getBlockNumber();
  const block = await provider.getBlock(blockNumber, true);
  kv("Latest block", blockNumber);
  kv("  tx count", block?.transactions.length ?? 0);

  // get a transaction from that block
  const txHash = block?.transactions[0];
  if (txHash) {
    const tx = await provider.getTransaction(txHash);
    kv("First tx", txHash);
    kv("  from", tx?.from);
    kv("  value (wei)", tx?.value.toString());
  }

  // get a balance
  const balanceTarget = block?.transactions[0]
    ? ((await provider.getTransaction(block.transactions[0]))?.from ?? ZERO)
    : ZERO;
  const balance = await provider.getBalance(balanceTarget);
  kv("Balance of", balanceTarget);
  kv("  wei", balance.toString());

  header("Done — every response above was verified before ethers returned it");
}

main().catch((err) => {
  console.error("\nFAIL —", err);
  process.exit(1);
});
