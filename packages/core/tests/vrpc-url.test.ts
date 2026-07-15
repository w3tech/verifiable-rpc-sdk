import { describe, expect, test } from "vitest";

import { deriveVrpcUrls } from "../src/vrpc-url";

// Fake key literal — never a real key.
const KEY = "DEADBEEF";

describe("deriveVrpcUrls", () => {
  test("ankr keyed form: _vrpc on the chain segment, key preserved", () => {
    expect(deriveVrpcUrls(`https://rpc.ankr.com/arbitrum/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}/attestation`,
    });
  });

  test("onerpc form (no key): chain suffixed (unchanged behavior)", () => {
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum_vrpc",
      attestationUrl: "https://rpc.example.com/arbitrum_vrpc/attestation",
    });
  });

  test("trailing slash is ignored", () => {
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum/")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum_vrpc",
      attestationUrl: "https://rpc.example.com/arbitrum_vrpc/attestation",
    });
  });

  test("dup-guard: chain already ends with _vrpc (no key) is unchanged", () => {
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum_vrpc")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum_vrpc",
      attestationUrl: "https://rpc.example.com/arbitrum_vrpc/attestation",
    });
  });

  test("dup-guard: chain already _vrpc, with a key segment, is unchanged", () => {
    expect(deriveVrpcUrls(`https://rpc.ankr.com/arbitrum_vrpc/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}/attestation`,
    });
  });

  test("direct node, no path: derives /_vrpc", () => {
    expect(deriveVrpcUrls("http://node.example:8545")).toEqual({
      rpcUrl: "http://node.example:8545/_vrpc",
      attestationUrl: "http://node.example:8545/_vrpc/attestation",
    });
  });

  test("direct node already /_vrpc is unchanged", () => {
    expect(deriveVrpcUrls("http://node.example:8545/_vrpc")).toEqual({
      rpcUrl: "http://node.example:8545/_vrpc",
      attestationUrl: "http://node.example:8545/_vrpc/attestation",
    });
  });

  test("restPrefixKeptOnRpcLegStrippedFromAttestation", () => {
    // Public non-EVM HTTP-API form (e.g. TON): rpc.ankr.com/premium-http/<chain>/<key>.
    expect(deriveVrpcUrls(`https://rpc.ankr.com/premium-http/ton_api_v2/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/ton_api_v2_vrpc/${KEY}/attestation`,
    });
  });

  test("restPrefixDupGuardOnVrpcChain", () => {
    expect(deriveVrpcUrls(`https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/ton_api_v2_vrpc/${KEY}/attestation`,
    });
  });

  test("sharkDirectRestPrefixHandledLikePremiumHttp", () => {
    expect(deriveVrpcUrls("https://shark.example.com/rest/ton_api_v2")).toEqual({
      rpcUrl: "https://shark.example.com/rest/ton_api_v2_vrpc",
      attestationUrl: "https://shark.example.com/ton_api_v2_vrpc/attestation",
    });
  });

  test("bareRestPrefixWithoutChainFallsThroughToChainRule", () => {
    // A single "rest" segment is treated as the chain itself, not a prefix.
    expect(deriveVrpcUrls("https://host.example.com/rest")).toEqual({
      rpcUrl: "https://host.example.com/rest_vrpc",
      attestationUrl: "https://host.example.com/rest_vrpc/attestation",
    });
  });
});
