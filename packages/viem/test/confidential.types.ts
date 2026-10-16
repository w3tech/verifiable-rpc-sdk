// Type-level check of the Ankr Confidential RPC overload of vrpcHttp; compiled by tsc, not run.

import type { ConfidentialInfo } from "@w3tech.io/vrpc-core/confidential";
import { createPublicClient, defineChain } from "viem";
import {
  type AttestationUnavailableReason,
  type InvalidInnerRequestReason,
  type MalformedConfidentialResponseReason,
  type TransportFailedReason,
  vrpcHttp,
} from "../src/index";

const chain = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

export async function confidentialMembers(): Promise<void> {
  const client = createPublicClient({
    chain,
    transport: vrpcHttp("http://127.0.0.1/eth_vrpc", { confidential: true }),
  });
  const info: ConfidentialInfo = await client.transport.ready();
  const withSignal: ConfidentialInfo = await client.transport.ready({
    signal: new AbortController().signal,
  });
  const pinned: ConfidentialInfo | undefined = client.transport.getConfidentialInfo();
  // @ts-expect-error ready() takes an options object, not a number.
  await client.transport.ready(42);
  // @ts-expect-error getConfidentialInfo() may be undefined.
  const required: ConfidentialInfo = client.transport.getConfidentialInfo();
  void [info, withSignal, pinned, required];
}

export const reasons: [
  AttestationUnavailableReason,
  TransportFailedReason,
  InvalidInnerRequestReason,
  MalformedConfidentialResponseReason,
][] = [];
