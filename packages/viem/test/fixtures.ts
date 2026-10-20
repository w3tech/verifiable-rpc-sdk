// Signed-response fixtures for the vrpc-viem adapter tests.

/**
 * Known decoded balance a signed `eth_getBalance` fixture carries —
 * `0x1bc16d674ec80000` = 2 ETH (wei).
 */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";

// Replay window wide enough for responses signed at FIXTURE_TIMESTAMP_MS.
export const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;

// Served verbatim in /attestation with its composeHash, so CHK-A2 activates and passes.
export const APP_COMPOSE = '{"manifest_version":2,"name":"demo"}';

export function jsonResult(result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, result });
}
