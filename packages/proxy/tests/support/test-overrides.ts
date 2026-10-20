// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared unit-test constants and no-network injection helpers.
//
// Every proxy test MUST pass `testOverrides()` into `createProxyServer`; without it the
// TrustedVerifier hits the network through the proxy's Agent (attestation GET
// and the Phala CloudVerifier) on a pubkey-cache miss.

import { attestationStub, mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import type { ProxyConfig } from "../../src/config";
import type { ProxyTestOverrides } from "../../src/server";

export const TEST_CHAIN_ID = "proxy-test-chain";
const NONCE = new Uint8Array(32).fill(0x07);

/**
 * The no-network TrustedVerifier injection set for `createProxyServer`:
 * attestation stub + hardware-verifier mock + pinned nonce. Zero network
 * in unit tests.
 */
export function testOverrides(): ProxyTestOverrides {
  return {
    fetch: attestationStub().fetch,
    hardwareVerifier: mockHardwareVerifier(),
    nonceSource: () => NONCE,
  };
}

/**
 * Build a valid ProxyConfig pointing at a mock upstream. The attestation URL
 * is arbitrary — the injected attestation stub intercepts it. Tests call
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
