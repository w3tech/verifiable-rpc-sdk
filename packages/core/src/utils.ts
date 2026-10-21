// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Parse the chainId from a raw `eth_chainId` response body — the conversion the
// auto-derive bootstrap runs before the self-consistent verify. A malformed body
// (not UTF-8 JSON, or a missing / non-0x-hex `result`) throws MalformedHeader so it
// reads as a verify failure — never an opaque SyntaxError / TypeError. The body is
// unverified at this point, so no error echoes it.
// A derived id the sidecar would reject is InvalidChainId: the request was already sent.

import { MalformedHeader } from "./errors";
import { validateChainId } from "./preimage";

/** Strict UTF-8 decoder: bytes that are not UTF-8 throw instead of becoming U+FFFD. */
export const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Decode + parse a chainId (as a DECIMAL STRING, e.g. `"42161"` for `0xa4b1`)
 * from the raw bytes of a signed `eth_chainId` response. The 0x-hex result (at
 * most 256 bits, an EVM QUANTITY) is converted via `BigInt()` then base-10
 * `toString()` — no `Number` round-trip, since a chain id may exceed
 * `Number.MAX_SAFE_INTEGER`.
 *
 * The decimal string is what EVM nodes are configured with (the arbitrum GA
 * node uses `"42161"`), so EVM auto-detect binds the exact string the sidecar
 * signs under. Non-EVM chains have no `eth_chainId` auto-detect and must
 * configure their chain id explicitly.
 */
export function parseChainId(rawResponseBytes: Uint8Array): string {
  let result: unknown;
  try {
    result = (JSON.parse(strictUtf8.decode(rawResponseBytes)) as { result?: unknown } | null)
      ?.result;
  } catch {
    throw new MalformedHeader("eth_chainId.result", "<unverified>", "body is not UTF-8 JSON");
  }
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(result)) {
    throw new MalformedHeader("eth_chainId.result", "<unverified>", "expected a 0x-hex chain id");
  }
  return validateChainId(BigInt(result).toString(10));
}
