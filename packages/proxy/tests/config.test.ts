// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// parseConfig matrix: required flags, URL/chain/numeric/listen validation,
// defaults, env fallbacks with CLI precedence, attestation headers, and
// attestation-URL derivation. Pure — no server, no network.

import { deriveVrpcUrls } from "@w3tech.io/vrpc-core";
import { describe, expect, test } from "vitest";

import { parseConfig } from "../src/config";
import { ConfigError } from "../src/errors";

const UPSTREAM = "https://rpc.example.com/arbitrum_vrpc/KEY";
const BASE = ["--upstream", UPSTREAM, "--chain-id", "test-chain"];

describe("parseConfig", () => {
  test("missingUpstreamNamesFlagAndEnvVar", () => {
    expect(() => parseConfig(["--chain-id", "test-chain"], {})).toThrow(ConfigError);
    expect(() => parseConfig(["--chain-id", "test-chain"], {})).toThrow(/--upstream/);
    expect(() => parseConfig(["--chain-id", "test-chain"], {})).toThrow(/VRPC_PROXY_UPSTREAM/);
  });

  test("missingChainThrowsConfigError", () => {
    expect(() => parseConfig(["--upstream", UPSTREAM], {})).toThrow(ConfigError);
    expect(() => parseConfig(["--upstream", UPSTREAM], {})).toThrow(/--chain-id/);
  });

  test("invalidUpstreamUrlThrowsConfigError", () => {
    expect(() => parseConfig(["--upstream", "not a url", "--chain-id", "test-chain"], {})).toThrow(
      ConfigError,
    );
  });

  test.each(["   ", "a".repeat(65), "café"])("chain id %j is InvalidOption", (chain) => {
    expect(() => parseConfig(["--upstream", UPSTREAM, "--chain-id", chain], {})).toThrow(
      expect.objectContaining({ name: "InvalidOption", option: "chainId" }),
    );
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

  test("bracketedIpv6ListenUnwrapsToBareAddress", () => {
    const config = parseConfig([...BASE, "--listen", "[::1]:8969"], {});
    expect(config.listenHost).toBe("::1");
    expect(config.listenPort).toBe(8969);
  });

  test("defaultsAppliedWhenFlagsAbsent", () => {
    const config = parseConfig(BASE, {});
    expect(config.listenHost).toBe("127.0.0.1");
    expect(config.listenPort).toBe(8969);
    expect(config.upstreamTimeoutMs).toBe(30_000);
    expect(config.maxBodyBytes).toBe(33_554_432);
    expect(config.logLevel).toBe("error");
    expect(config.replayWindowMs).toBeUndefined();
  });

  test("logLevelFlagAcceptsErrorAndDebugRejectsOther", () => {
    expect(parseConfig([...BASE, "--log-level", "error"], {}).logLevel).toBe("error");
    expect(parseConfig([...BASE, "--log-level", "debug"], {}).logLevel).toBe("debug");
    expect(parseConfig([...BASE, "--log-level", "silent"], {}).logLevel).toBe("silent");
    expect(() => parseConfig([...BASE, "--log-level", "verbose"], {})).toThrow(ConfigError);
  });

  test("attestationCacheTtlFlagAndEnvParsed", () => {
    expect(parseConfig([...BASE, "--attestation-cache-ttl", "600000"], {}).pubkeyCacheTtlMs).toBe(
      600_000,
    );
    expect(parseConfig(BASE, { VRPC_PROXY_ATTESTATION_CACHE_TTL: "300000" }).pubkeyCacheTtlMs).toBe(
      300_000,
    );
    expect(parseConfig(BASE, {}).pubkeyCacheTtlMs).toBeUndefined();
    expect(() => parseConfig([...BASE, "--attestation-cache-ttl", "0"], {})).toThrow(ConfigError);
  });

  test("envFallbackUsedWhenFlagAbsent", () => {
    const config = parseConfig(["--chain-id", "test-chain"], { VRPC_PROXY_UPSTREAM: UPSTREAM });
    expect(config.upstreamUrl).toBe(UPSTREAM);
  });

  test("cliFlagWinsOverEnvVar", () => {
    const config = parseConfig([...BASE, "--timeout", "5000"], { VRPC_PROXY_TIMEOUT: "9000" });
    expect(config.upstreamTimeoutMs).toBe(5000);
  });

  test("attestationUrlDerivedFromUpstream", () => {
    const config = parseConfig(BASE, {});
    expect(config.attestationUrl).toBe(deriveVrpcUrls(UPSTREAM).attestationUrl);
  });

  test("upstreamUrlUsedVerbatimOnRpcLeg", () => {
    const config = parseConfig(
      ["--upstream", "https://rpc.ankr.com/arbitrum_vrpc", "--chain-id", "42161"],
      {},
    );
    expect(config.upstreamUrl).toBe("https://rpc.ankr.com/arbitrum_vrpc");
    expect(config.attestationUrl).toBe("https://rpc.ankr.com/arbitrum_vrpc/attestation");
  });

  test("upstreamQueryStaysOnTheRpcLegAndWarnsAboutTheAttestationLeg", () => {
    const config = parseConfig(
      ["--upstream", "https://rpc.example.com/chain/?key=abc", "--chain-id", "test-chain"],
      {},
    );
    expect(config.upstreamUrl).toBe("https://rpc.example.com/chain?key=abc");
    expect(config.warnings?.[0]).toContain("the derived attestation URL drops");
  });

  test("upstreamQueryWarningInConfidentialModeSaysNoKeyIsSent", () => {
    const config = parseConfig(
      [
        "--upstream",
        "https://rpc.example.com/chain?key=abc",
        "--chain-id",
        "test-chain",
        "--confidential",
      ],
      {},
    );
    expect(config.warnings).toHaveLength(1);
    expect(config.warnings?.[0]).toContain("no API key is sent unless --api-key");
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

  test("absentApiKeyLeavesConfigUnset", () => {
    const config = parseConfig(BASE, {});
    expect(config.apiKey).toBeUndefined();
    expect(config.attestationHeaders["x-api-key"]).toBeUndefined();
  });

  test("confidentialFlagTurnsModeOn", () => {
    expect(parseConfig([...BASE, "--confidential"], {}).confidential).toBe(true);
  });

  test("confidentialEnvAcceptsOneAndTrueInAnyCase", () => {
    for (const value of ["1", "true", "TRUE", "True"]) {
      expect(parseConfig(BASE, { VRPC_PROXY_CONFIDENTIAL: value }).confidential).toBe(true);
    }
  });

  test("confidentialEnvZeroFalseEmptyOrUnsetLeavesModeOff", () => {
    for (const value of ["0", "false", "FALSE", ""]) {
      expect(parseConfig(BASE, { VRPC_PROXY_CONFIDENTIAL: value }).confidential).not.toBe(true);
    }
    expect(parseConfig(BASE, {}).confidential).not.toBe(true);
  });

  test("confidentialEnvUnrecognisedValueThrowsConfigError", () => {
    for (const value of ["yes", "on", "2", " 1"]) {
      const parse = () => parseConfig(BASE, { VRPC_PROXY_CONFIDENTIAL: value });
      expect(parse).toThrow(ConfigError);
      expect(parse).toThrow(/--confidential/);
      expect(parse).toThrow(/VRPC_PROXY_CONFIDENTIAL/);
    }
  });

  test("confidentialFlagRejectsAValue", () => {
    expect(() => parseConfig(["--confidential=true", ...BASE], {})).toThrow(ConfigError);
  });

  test("confidentialFlagWinsOverEnvOff", () => {
    const config = parseConfig([...BASE, "--confidential"], { VRPC_PROXY_CONFIDENTIAL: "0" });
    expect(config.confidential).toBe(true);
  });

  test("confidentialModeKeepsListenDefaultAndAddsNoWarning", () => {
    const config = parseConfig([...BASE, "--confidential"], {});
    expect(config.listenHost).toBe("127.0.0.1");
    expect(config.listenPort).toBe(8969);
    expect(config.warnings).toBeUndefined();
  });

  test("confidentialModeStillRequiresChainId", () => {
    expect(() => parseConfig(["--upstream", UPSTREAM, "--confidential"], {})).toThrow(ConfigError);
    expect(() => parseConfig(["--upstream", UPSTREAM, "--confidential"], {})).toThrow(/--chain-id/);
  });
});
