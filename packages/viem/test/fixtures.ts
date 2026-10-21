// Fixtures and helpers shared by the vrpc-viem adapter tests.

import { KEY, mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { BaseError, defineChain } from "viem";

// Served verbatim in /attestation with its composeHash, so CHK-A2 activates and passes.
export const APP_COMPOSE = '{"manifest_version":2,"name":"demo"}';

export const arbitrum = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1"] } },
});

// vrpcHttp in Ankr Confidential RPC mode sending the key header; a server is called at /eth_vrpc.
export function confidential(
  target: string | { url: string },
  options: Parameters<typeof vrpcHttp>[1] = {},
) {
  return vrpcHttp(typeof target === "string" ? target : `${target.url}/eth_vrpc`, {
    headers: { "x-api-key": KEY },
    hardwareVerifier: mockHardwareVerifier(),
    ...options,
    confidential: true,
  });
}

export function walkFind<T>(
  err: unknown,
  type: abstract new (...args: never[]) => T,
): T | undefined {
  if (err instanceof type) return err;
  if (!(err instanceof BaseError)) return undefined;
  return (err.walk((e) => e instanceof type) as T | null) ?? undefined;
}
