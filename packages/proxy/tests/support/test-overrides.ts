// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared unit-test constants and no-network injection helpers.
//
// Replicates the fixture recipe from core's trusted-verifier.test.ts
// (constants, attestation-fetch mock, options factory); helpers shared across
// packages live in @w3tech.io/vrpc-test-support. Every proxy test
// MUST pass `testOverrides()` into `createProxyServer`; without it the
// TrustedVerifier hits the network through the proxy's Agent (attestation GET
// and the Phala CloudVerifier) on a pubkey-cache miss.

import { getPublicKeyAsync } from "@noble/ed25519";
import { mockHardwareVerifier, TEST_SEED, toHex } from "@w3tech.io/vrpc-test-support";
import type { ProxyConfig } from "../../src/config";
import type { ProxyTestOverrides } from "../../src/server";

export const TEST_CHAIN_ID = "proxy-test-chain";
const NONCE = new Uint8Array(32).fill(0x07);

/**
 * The sidecar attestation JSON for `TEST_SEED` (core's installAttestationMock
 * recipe). `report_data` is the 64-byte CHK-A1 pre-image pubkey(bare) ‖ nonce(bare).
 */
export async function attestationBody(nonceHex: string): Promise<string> {
  const pubkey = toHex(await getPublicKeyAsync(TEST_SEED));
  return JSON.stringify({
    quote: { quote: "00", event_log: "00", report_data: `${pubkey}${nonceHex}`, vm_config: "" },
    pubkey: `0x${pubkey}`,
    composeHash: "deadbeef",
  });
}

/**
 * A `fetch`-compatible mock answering any URL containing `/attestation` with
 * `attestationBody`; the nonce is pinned via `nonceSource: () => NONCE`.
 */
function attestationFetchMock(): typeof fetch {
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      return new Response(await attestationBody(toHex(NONCE)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
  return impl as typeof fetch;
}

/**
 * The no-network TrustedVerifier injection set for `createProxyServer`:
 * attestation fetch mock + hardware-verifier mock + pinned nonce. Zero network
 * in unit tests.
 */
export function testOverrides(): ProxyTestOverrides {
  return {
    fetch: attestationFetchMock(),
    hardwareVerifier: mockHardwareVerifier(),
    nonceSource: () => NONCE,
  };
}

/**
 * Build a valid ProxyConfig pointing at a mock upstream. The attestation URL
 * is arbitrary — the injected fetch mock intercepts it. Tests call
 * `server.listen(0)` themselves, so the listen fields are placeholders.
 */
export function testConfig(upstreamUrl: string, overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    upstreamUrl,
    chainId: TEST_CHAIN_ID,
    attestationUrl: "http://sidecar.test/attestation",
    attestationHeaders: {},
    listenHost: "127.0.0.1",
    listenPort: 0,
    upstreamTimeoutMs: 2000,
    maxBodyBytes: 33_554_432,
    logLevel: "silent",
    ...overrides,
  };
}
