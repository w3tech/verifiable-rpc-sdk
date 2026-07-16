import { describe, expect, test } from "vitest";

import { deriveVrpcUrls } from "../src/vrpc-url";

// Fake key literal — never a real key.
const KEY = "DEADBEEF";

describe("deriveVrpcUrls", () => {
  test("ankr keyed form: URL used as-is, key preserved", () => {
    expect(deriveVrpcUrls(`https://rpc.ankr.com/arbitrum_vrpc/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/arbitrum_vrpc/${KEY}/attestation`,
    });
  });

  test("onerpc form (no key): URL used as-is", () => {
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum_vrpc")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum_vrpc",
      attestationUrl: "https://rpc.example.com/arbitrum_vrpc/attestation",
    });
  });

  test("trailing slash is ignored", () => {
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum_vrpc/")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum_vrpc",
      attestationUrl: "https://rpc.example.com/arbitrum_vrpc/attestation",
    });
  });

  test("no auto-suffix: bare chain slug passes through unmodified", () => {
    // The SDK does NOT append `_vrpc` — the user owns the route.
    expect(deriveVrpcUrls("https://rpc.example.com/arbitrum")).toEqual({
      rpcUrl: "https://rpc.example.com/arbitrum",
      attestationUrl: "https://rpc.example.com/arbitrum/attestation",
    });
  });

  test("direct node /_vrpc route used as-is", () => {
    expect(deriveVrpcUrls("http://node.example:8545/_vrpc")).toEqual({
      rpcUrl: "http://node.example:8545/_vrpc",
      attestationUrl: "http://node.example:8545/_vrpc/attestation",
    });
  });

  test("no path: origin used as-is (no /_vrpc auto-derivation)", () => {
    expect(deriveVrpcUrls("http://node.example:8545")).toEqual({
      rpcUrl: "http://node.example:8545",
      attestationUrl: "http://node.example:8545/attestation",
    });
  });

  test("restPrefixKeptOnBothLegs", () => {
    // Public non-EVM HTTP-API form (e.g. TON): rpc.ankr.com/premium-http/<chain>/<key>.
    // The prefixed attestation spelling is served by its own ingress rule.
    expect(deriveVrpcUrls(`https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}`)).toEqual({
      rpcUrl: `https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}`,
      attestationUrl: `https://rpc.ankr.com/premium-http/ton_api_v2_vrpc/${KEY}/attestation`,
    });
  });
});
