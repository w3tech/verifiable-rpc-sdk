// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode with ethers and viem. Every call is encrypted to the
// attested node, so the gateway sees only ciphertext, and only answers signed by
// that node are opened. The client attests and pins the node on `ready` (or on
// the first call).
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";

const RPC_URL = "https://rpc.ankr.com/arbitrum_vrpc/123456";
const HOLDER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

async function main() {
  // The chain id is required in this mode.
  const provider = new VrpcProvider(RPC_URL, "42161", { confidential: true });
  await provider.confidentialReady();
  console.log("ethers pinned", provider.getConfidentialInfo());
  console.log({
    block: await provider.getBlockNumber(),
    balance: await provider.getBalance(HOLDER),
  });
  provider.destroy();

  // The chain id comes from the client's `chain`.
  const client = createPublicClient({
    chain: arbitrum,
    transport: vrpcHttp(RPC_URL, { confidential: true }),
  });
  await client.transport.ready();
  console.log("viem pinned", client.transport.getConfidentialInfo());
  console.log({
    block: await client.getBlockNumber(),
    balance: await client.getBalance({ address: HOLDER }),
  });
}

main();
