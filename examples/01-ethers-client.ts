// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Drop-in verified ethers provider. Use it exactly like a normal ethers v6
// provider — every JSON-RPC response is cryptographically verified (Ed25519 +
// TDX attestation) before ethers returns it; a tampered response throws.
import { VrpcProvider } from "@ankr.com/vrpc-ethers";

async function main() {
  const provider = new VrpcProvider("https://rpc.ankr.com/arbitrum/123456", 42161n);

  const block = await provider.getBlock("latest");
  const balance = await provider.getBalance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

  console.log({ block: block?.number, balance });
}

main();
