// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Drop-in verified ethers provider. Use it exactly like a normal ethers v6
// provider — every JSON-RPC response is cryptographically verified (Ed25519 +
// TDX attestation) before ethers returns it; a tampered response throws.
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
import { FetchRequest } from "ethers";

// Set ANKR_API_KEY to send it as `x-api-key` (to the RPC and attestation legs).
const API_KEY = process.env.ANKR_API_KEY;

async function main() {
  const request = new FetchRequest("https://rpc.ankr.com/arbitrum_vrpc");
  if (API_KEY) request.setHeader("x-api-key", API_KEY);
  const provider = new VrpcProvider(request, "42161");

  const block = await provider.getBlock("latest");
  const balance = await provider.getBalance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

  console.log({ block: block?.number, balance });
}

main();
