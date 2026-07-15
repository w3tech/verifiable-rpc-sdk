// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// parseConfig matrix: required flags, URL/chain/numeric/listen validation,
// defaults, env fallbacks with CLI precedence, attestation headers, and
// attestation-URL derivation. Pure — no server, no network.

import { deriveVrpcUrls, InvalidChainId } from "@w3tech.io/vrpc-core";
import { describe, expect, test } from "vitest";

import { parseConfig } from "../src/config";
import { ConfigError } from "../src/errors";

const UPSTREAM = "https://rpc.example.com/arbitrum_vrpc/KEY";
const BASE = ["--upstream", UPSTREAM, "--chain", "test-chain"];

describe("parseConfig", () => {
  test("missingUpstreamNamesFlagAndEnvVar", () => {
    expect(() => parseConfig(["--chain", "test-chain"], {})).toThrow(ConfigError);
    expect(() => parseConfig(["--chain", "test-chain"], {})).toThrow(/--upstream/);
    expect(() => parseConfig(["--chain", "test-chain"], {})).toThrow(/VRPC_PROXY_UPSTREAM/);
  });

  test("missingChainThrowsConfigError", () => {
    expect(() => parseConfig(["--upstream", UPSTREAM], {})).toThrow(ConfigError);
    expect(() => parseConfig(["--upstream", UPSTREAM], {})).toThrow(/--chain/);
  });

  test("invalidUpstreamUrlThrowsConfigError", () => {
    expect(() => parseConfig(["--upstream", "not a url", "--chain", "test-chain"], {})).toThrow(
      ConfigError,
    );
  });

  test("invalidChainIdPropagatesCoreInvalidChainId", () => {
    const args = (chain: string) => ["--upstream", UPSTREAM, "--chain", chain];
    // Whitespace-only trims to empty.
    expect(() => parseConfig(args("   "), {})).toThrow(InvalidChainId);
    // Oversized: > 64 UTF-8 bytes.
    expect(() => parseConfig(args("a".repeat(65)), {})).toThrow(InvalidChainId);
    // Non-printable-ASCII.
    expect(() => parseConfig(args("café"), {})).toThrow(InvalidChainId);
  });

  test("unknownFlagThrowsConfigError", () => {
    expect(() => parseConfig([...BASE, "--bogus", "x"], {})).toThrow(ConfigError);
  });

  test("invalidNumericFlagsThrowConfigError", () => {
    expect(() => parseConfig([...BASE, "--timeout", "0"], {})).toThrow(ConfigError);
    expect(() => parseConfig([...BASE, "--timeout=-5"], {})).toThrow(ConfigError);
    expect(() => parseConfig([...BASE, "--timeout", "abc"], {})).toThrow(ConfigError);
  });

  test("invalidListenThrowsConfigError", () => {
    expect(() => parseConfig([...BASE, "--listen", "127.0.0.1:99999"], {})).toThrow(ConfigError);
    expect(() => parseConfig([...BASE, "--listen", "nohostport"], {})).toThrow(ConfigError);
    expect(() => parseConfig([...BASE, "--listen", "127.0.0.1:abc"], {})).toThrow(ConfigError);
  });

  test("defaultsAppliedWhenFlagsAbsent", () => {
    const config = parseConfig(BASE, {});
    expect(config.listenHost).toBe("127.0.0.1");
    expect(config.listenPort).toBe(8969);
    expect(config.upstreamTimeoutMs).toBe(30_000);
    expect(config.maxBodyBytes).toBe(33_554_432);
    expect(config.logLevel).toBe("silent");
    expect(config.replayWindowMs).toBeUndefined();
  });

  test("envFallbackUsedWhenFlagAbsent", () => {
    const config = parseConfig(["--chain", "test-chain"], { VRPC_PROXY_UPSTREAM: UPSTREAM });
    expect(config.upstreamUrl).toBe(UPSTREAM);
  });

  test("cliFlagWinsOverEnvVar", () => {
    const config = parseConfig([...BASE, "--timeout", "5000"], { VRPC_PROXY_TIMEOUT: "9000" });
    expect(config.upstreamTimeoutMs).toBe(5000);
  });

  test("repeatableAttestationHeaderFlagsCollected", () => {
    const config = parseConfig(
      [...BASE, "--attestation-header", "X-Api-Key: k1", "--attestation-header", "X-Other: v"],
      {},
    );
    expect(config.attestationHeaders).toEqual({ "X-Api-Key": "k1", "X-Other": "v" });
  });

  test("newlineSeparatedEnvAttestationHeadersParsed", () => {
    const config = parseConfig(BASE, {
      VRPC_PROXY_ATTESTATION_HEADER: "X-Api-Key: k1\nX-Other: v",
    });
    expect(config.attestationHeaders).toEqual({ "X-Api-Key": "k1", "X-Other": "v" });
  });

  test("attestationHeaderWithoutColonThrowsConfigError", () => {
    expect(() => parseConfig([...BASE, "--attestation-header", "no-colon-here"], {})).toThrow(
      ConfigError,
    );
  });

  test("attestationUrlDerivedFromUpstream", () => {
    const config = parseConfig(BASE, {});
    expect(config.attestationUrl).toBe(deriveVrpcUrls(UPSTREAM).attestationUrl);
  });

  test("explicitAttestationUrlOverrideWins", () => {
    const override = "https://sidecar.internal:8080/attestation";
    const config = parseConfig([...BASE, "--attestation-url", override], {});
    expect(config.attestationUrl).toBe(override);
  });

  test("upstreamQueryWithoutOverrideProducesWarning", () => {
    const config = parseConfig(
      ["--upstream", "https://rpc.example.com/chain?key=abc", "--chain", "test-chain"],
      {},
    );
    expect(config.warnings).toBeDefined();
    expect(config.warnings?.length).toBeGreaterThan(0);
  });

  test("apiKeyFlagSetsConfigAndAttestationHeader", () => {
    const config = parseConfig([...BASE, "--api-key", "sekret"], {});
    expect(config.apiKey).toBe("sekret");
    expect(config.attestationHeaders["x-api-key"]).toBe("sekret");
  });

  test("apiKeyEnvFallback", () => {
    const config = parseConfig(BASE, { VRPC_PROXY_API_KEY: "envkey" });
    expect(config.apiKey).toBe("envkey");
    expect(config.attestationHeaders["x-api-key"]).toBe("envkey");
  });

  test("explicitAttestationHeaderWinsOverApiKey", () => {
    const config = parseConfig(
      [...BASE, "--api-key", "sekret", "--attestation-header", "x-api-key: explicit"],
      {},
    );
    expect(config.attestationHeaders["x-api-key"]).toBe("explicit");
    expect(config.apiKey).toBe("sekret");
  });

  test("absentApiKeyLeavesConfigUnset", () => {
    const config = parseConfig(BASE, {});
    expect(config.apiKey).toBeUndefined();
    expect(config.attestationHeaders["x-api-key"]).toBeUndefined();
  });
});
