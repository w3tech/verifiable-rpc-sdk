import { describe, expect, test } from "vitest";

import { deriveVrpcUrls } from "../src/vrpc-url";

// Fake key literal — never a real key.
const KEY = "DEADBEEF";

describe("deriveVrpcUrls", () => {
  test("ankr keyed form: _vrpc on the chain segment, key preserved (SHARK-3283)", () => {
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
    expect(deriveVrpcUrls("http://40.160.13.104:15269")).toEqual({
      rpcUrl: "http://40.160.13.104:15269/_vrpc",
      attestationUrl: "http://40.160.13.104:15269/_vrpc/attestation",
    });
  });

  test("direct node already /_vrpc is unchanged", () => {
    expect(deriveVrpcUrls("http://40.160.13.104:15269/_vrpc")).toEqual({
      rpcUrl: "http://40.160.13.104:15269/_vrpc",
      attestationUrl: "http://40.160.13.104:15269/_vrpc/attestation",
    });
  });
});
