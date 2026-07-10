// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Parse the chainId from a raw `eth_chainId` response body — the conversion the
// auto-derive bootstrap (both the ethers and viem adapters) runs before the
// self-consistent verify. A malformed body (invalid JSON, or a missing / non-0x-hex
// `result`) throws MalformedHeader so it reads as a verify failure, consistent with
// the fail-fast bootstrap contract — never an opaque SyntaxError / TypeError.

import { MalformedHeader } from "./errors";

/**
 * Decode + parse a chainId (as a DECIMAL STRING, e.g. `"42161"` for `0xa4b1`)
 * from the raw bytes of a signed `eth_chainId` response. The 0x-hex result is
 * converted via `BigInt()` then base-10 `toString()` — no `Number` round-trip,
 * since a chain id may exceed `Number.MAX_SAFE_INTEGER`.
 *
 * The decimal string is what EVM nodes are configured with (the arbitrum GA
 * node uses `"42161"`), so EVM auto-detect binds the exact string the sidecar
 * signs under. Non-EVM chains have no `eth_chainId` auto-detect and must
 * configure their chain id explicitly.
 */
export function parseChainId(rawResponseBytes: Uint8Array): string {
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
  return BigInt(parsed.result).toString(10);
}
