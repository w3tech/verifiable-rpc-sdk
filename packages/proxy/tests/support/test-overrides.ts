// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared unit-test constants and no-network injection helpers.
//
// Replicates the fixture recipe from core's trusted-verifier.test.ts
// (constants, attestation-fetch mock, options factory) — repo convention is a
// local copy per package, never a cross-package test import. Every proxy test
// MUST pass `testOverrides()` into `createProxyServer`; without it the
// TrustedVerifier hits `globalThis.fetch` and the Phala CloudVerifier on a
// pubkey-cache miss.

import { getPublicKeyAsync } from "@noble/ed25519";

import type { ProxyConfig } from "../../src/config";
import type { ProxyTestOverrides } from "../../src/server";
import { mockHardwareVerifier } from "./mock-hardware-verifier";

export const TEST_CHAIN_ID = "proxy-test-chain";
export const TEST_SEED = new Uint8Array(32).fill(0x42);
export const NONCE = new Uint8Array(32).fill(0x07);

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * A `fetch`-compatible mock answering any URL containing `/attestation` with
 * the sidecar attestation JSON shape (core's installAttestationMock recipe).
 * `report_data` is the 64-byte CHK-A1 pre-image pubkey(bare) ‖ nonce(bare) —
 * the nonce is pinned via `nonceSource: () => NONCE`. The signing pubkey is
 * derived lazily from `seed` inside the async impl, keeping this factory
 * synchronous.
 */
export function attestationFetchMock(seed: Uint8Array = TEST_SEED): typeof fetch {
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      const attPubkey = await getPublicKeyAsync(seed);
      const reportData = `${toHex(attPubkey)}${toHex(NONCE)}`;
      const body = {
        quote: { quote: "00", event_log: "00", report_data: reportData, vm_config: "" },
        pubkey: `0x${toHex(attPubkey)}`,
        composeHash: "deadbeef",
      };
      return new Response(JSON.stringify(body), {
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
