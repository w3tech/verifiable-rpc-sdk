// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Drop-in verified viem transport. Pass `vrpcHttp` to `createPublicClient` and
// use the client like any viem public client — every response is verified
// (Ed25519 + TDX attestation) inside the transport before viem decodes it.
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";

// Set ANKR_API_KEY to send it as `x-api-key` (to the RPC and attestation legs).
const API_KEY = process.env.ANKR_API_KEY;

async function main() {
  // chain id is taken from the client's `chain` (mirrors ethers' ctor arg).
  const client = createPublicClient({
    chain: arbitrum,
    transport: vrpcHttp("https://rpc.ankr.com/arbitrum_vrpc", {
      headers: API_KEY ? { "x-api-key": API_KEY } : {},
    }),
  });

  const block = await client.getBlockNumber();
  const balance = await client.getBalance({
    address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  });

  console.log({ block, balance });
}

main();
