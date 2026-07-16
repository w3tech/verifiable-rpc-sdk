// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// redactUrl guards the startup banner against key-in-path (#20) and
// key-in-query secrets — pinned here so neither leak class regresses.

import { describe, expect, test } from "vitest";

import { redactUrl } from "../src/redact";

// Fake key literals — never real keys.
const KEY32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
const KEY64 = "deadbeef".repeat(8);

describe("redactUrl", () => {
  test("masks a 32-alphanumeric key-in-path segment", () => {
    expect(redactUrl(`https://rpc.ankr.com/arbitrum_vrpc/${KEY32}`)).toBe(
      "https://rpc.ankr.com/arbitrum_vrpc/***",
    );
  });

  test("masks a 64-hex key-in-path segment", () => {
    expect(redactUrl(`https://rpc.ankr.com/arbitrum_vrpc/${KEY64}`)).toBe(
      "https://rpc.ankr.com/arbitrum_vrpc/***",
    );
  });

  test("masks every query-string value, keeps param names", () => {
    expect(redactUrl("https://host.example/eth_vrpc?apikey=SECRET&x=1")).toBe(
      "https://host.example/eth_vrpc?apikey=***&x=***",
    );
  });

  test("masks path key and query values together", () => {
    expect(redactUrl(`https://host.example/eth_vrpc/${KEY32}?token=SECRET`)).toBe(
      "https://host.example/eth_vrpc/***?token=***",
    );
  });

  test("leaves non-key path segments untouched", () => {
    expect(redactUrl("https://rpc.ankr.com/premium-http/ton_api_v2_vrpc")).toBe(
      "https://rpc.ankr.com/premium-http/ton_api_v2_vrpc",
    );
  });

  test("keyless URL with no query passes through unchanged", () => {
    expect(redactUrl("http://127.0.0.1:8969/")).toBe("http://127.0.0.1:8969/");
  });
});
