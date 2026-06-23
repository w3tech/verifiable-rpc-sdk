// Drop-in verified viem transport. Pass `vrpcHttp` to `createPublicClient` and
// use the client like any viem public client — every response is verified
// (Ed25519 + TDX attestation) inside the transport before viem decodes it.
import { vrpcHttp } from "@ankr.com/vrpc-viem";
import { createPublicClient } from "viem";

const client = createPublicClient({
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum/123456", { chainId: 42161n }),
});

const block = await client.getBlockNumber();
const balance = await client.getBalance({ address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" });

console.log({ block, balance });
