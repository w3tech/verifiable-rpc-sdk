// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC mode with ethers and viem. Every call is encrypted to the
// attested node, so the gateway sees only ciphertext, and only answers signed by
// that node are opened. The client attests and pins the node on `ready` (or on
// the first call).
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { FetchRequest } from "ethers";
import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";

// Set ANKR_API_KEY to send it as `x-api-key`; VRPC_URL to use another vRPC route.
const API_KEY = process.env.ANKR_API_KEY;
const RPC_URL = process.env.VRPC_URL ?? "https://rpc.ankr.com/arbitrum_vrpc";
const HOLDER = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

async function main() {
  const request = new FetchRequest(RPC_URL);
  if (API_KEY) request.setHeader("x-api-key", API_KEY);
  // The chain id is required in this mode.
  const provider = new VrpcProvider(request, "42161", { confidential: true });
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
    transport: vrpcHttp(RPC_URL, {
      confidential: true,
      headers: API_KEY ? { "x-api-key": API_KEY } : {},
    }),
  });
  await client.transport.ready();
  console.log("viem pinned", client.transport.getConfidentialInfo());
  console.log({
    block: await client.getBlockNumber(),
    balance: await client.getBalance({ address: HOLDER }),
  });
}

main();
