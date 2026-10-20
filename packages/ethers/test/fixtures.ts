// Signed-response fixtures for the vrpc-ethers adapter tests.

import { CHAIN_ID, FIXTURE_TIMESTAMP_MS, signedJsonHeaders } from "@w3tech.io/vrpc-test-support";

export interface Fixture {
  /** Request body bytes, exactly as signed (= `buildPreImage` request input). */
  requestBytes: Uint8Array;
  /** Response body bytes, exactly as signed. */
  responseBytes: Uint8Array;
  /** Signed `vRPC-*` triple plus `content-type`. */
  headers: Record<string, string>;
  /** The exact `timestampMs` the triple was signed over. */
  timestampMs: bigint;
}

// ---------------------------------------------------------------------------
// The static fixture. Signed with the fixed TEST_SEED, so the matching pubkey is
// deterministic. Synthesized eagerly at module load.
// ---------------------------------------------------------------------------

/** Known decoded balance carried by SINGLE_RESULT. `0x1bc16d674ec80000` = 2 ETH (wei). */
export const SINGLE_RESULT_BALANCE_HEX = "0x1bc16d674ec80000";

const singleRequestBytes = new TextEncoder().encode(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBalance",
    params: ["0x1111111111111111111111111111111111111111", "latest"],
  }),
);
const singleResponseBytes = new TextEncoder().encode(
  JSON.stringify({ jsonrpc: "2.0", id: 1, result: SINGLE_RESULT_BALANCE_HEX }),
);

/** Single signed `eth_getBalance` result. */
export const SINGLE_RESULT: Fixture = {
  requestBytes: singleRequestBytes,
  responseBytes: singleResponseBytes,
  headers: signedJsonHeaders(CHAIN_ID, singleRequestBytes, singleResponseBytes),
  timestampMs: FIXTURE_TIMESTAMP_MS,
};
