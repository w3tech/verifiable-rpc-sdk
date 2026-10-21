// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// redactUrl keeps key-in-path segments and query values out of the startup banner.

import { describe, expect, test } from "vitest";

import { redactUrl } from "../src/redact";

// Fake key literals — never real keys.
const KEY32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
const KEY64 = "deadbeef".repeat(8);

describe("redactUrl", () => {
  test.each([
    [`https://h.example/arbitrum_vrpc/${KEY32}`, "https://h.example/arbitrum_vrpc/***"],
    [`https://h.example/arbitrum_vrpc/${KEY64}`, "https://h.example/arbitrum_vrpc/***"],
    ["https://h.example/eth_vrpc?apikey=SECRET&x=1", "https://h.example/eth_vrpc?apikey=***&x=***"],
    [
      `https://h.example/eth_vrpc/${KEY32}?token=SECRET`,
      "https://h.example/eth_vrpc/***?token=***",
    ],
    [
      "https://h.example/premium-http/ton_api_v2_vrpc",
      "https://h.example/premium-http/ton_api_v2_vrpc",
    ],
    ["http://127.0.0.1:8969/eth_vrpc", "http://127.0.0.1:8969/eth_vrpc"],
  ])("%s is shown as %s", (url, shown) => {
    expect(redactUrl(url)).toBe(shown);
  });
});
