// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Parse the chainId from a raw `eth_chainId` response body — the conversion the
// auto-derive bootstrap (both the ethers and viem adapters) runs before the
// self-consistent verify. A malformed body (invalid JSON, or a missing / non-0x-hex
// `result`) throws MalformedHeader so it reads as a verify failure, consistent with
// the fail-fast bootstrap contract — never an opaque SyntaxError / TypeError.

import { MalformedHeader } from "./errors";

/**
 * Decode + parse a chainId (as `bigint`) from the raw bytes of a signed
 * `eth_chainId` response. `BigInt()` is taken directly off the 0x-hex string — no
 * number round-trip — since a chain id may exceed `Number.MAX_SAFE_INTEGER` and
 * must bind the full u64 into the canonical pre-image.
 */
export function parseChainId(rawResponseBytes: Uint8Array): bigint {
  const rawText = new TextDecoder().decode(rawResponseBytes);
  let parsed: { result?: string };
  try {
    parsed = JSON.parse(rawText) as { result?: string };
  } catch {
    throw new MalformedHeader(
      "eth_chainId.result",
      rawText,
      "auto-derived chainId could not be parsed: bootstrap body is not valid JSON",
    );
  }
  if (typeof parsed.result !== "string" || !/^0x[0-9a-fA-F]+$/.test(parsed.result)) {
    throw new MalformedHeader(
      "eth_chainId.result",
      String(parsed.result),
      "auto-derived chainId could not be parsed: expected 0x-hex chain id",
    );
  }
  return BigInt(parsed.result);
}
