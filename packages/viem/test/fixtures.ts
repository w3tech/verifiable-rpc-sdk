// Signed-response fixtures for the vrpc-viem adapter tests.

/**
 * Chain id bound into every fixture's pre-image (arbitrum — matches
 * `examples/shared.ts` conventions). Exported so tests pass it to
 * `verifyResponse({ chainId: CHAIN_ID })`. Decimal string — the exact value the
 * sidecar is configured with and hashes into the pre-image.
 */
export const CHAIN_ID = "42161";

/**
 * Known decoded balance a signed `eth_getBalance` fixture carries —
 * `0x1bc16d674ec80000` = 2 ETH (wei).
 */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";
