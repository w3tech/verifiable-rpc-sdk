// TEST-02 — VrpcProvider adapter-WIRING suite (Phase 30, Wave 2).
//
// These tests assert ADAPTER WIRING ONLY: that `VrpcProvider._send` routes every
// JSON-RPC call through `vrpc-core` `verifyResponse` over the raw response bytes
// before parse, maps results/errors/null back to callers, preserves native
// batching with id-correlation, and applies the strict (fail-closed) /
// permissive policy + the re-exported VerificationError family.
//
// They do NOT re-test Ed25519 / pre-image / replay-window correctness — that is
// core's `packages/core/tests/verify.test.ts` (TEST-01). The request-aware
// `signingRequest` helper signs over the EXACT bytes ethers POSTs, so a real
// getBalance / Contract / batch payload verifies without the test predicting
// ethers' internal payload encoding.

import { describe, expect, test } from "bun:test";
import {
  BadSignature,
  MissingHeader,
  VerificationError,
  VrpcProvider,
} from "@ankr.com/vrpc-ethers";
import { Contract, FetchRequest, Interface, toBeHex } from "ethers";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";
import { signingRequest } from "./helpers";

const CHAIN_ID_NUMBER = Number(CHAIN_ID); // 42161 (arbitrum)
const ADDR = "0x1111111111111111111111111111111111111111";
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness; production
// keeps the vrpc-core default (60s).
const WIDE_WINDOW = { replayWindowMs: Number.MAX_SAFE_INTEGER } as const;

function jsonResult(id: number, result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

describe("VrpcProvider._send wiring (TEST-02)", () => {
  test("verified value routes through _send: getBalance returns the decoded balance", async () => {
    // The id ethers assigns to the first call is 1; the request-aware signer
    // signs whatever ethers actually POSTs, so we only need the response shape.
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX)),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // 2 ETH in wei
  });

  test("verified Contract view read returns the decoded value", async () => {
    // A uint256 view; ethers eth_call → ABI-encoded 32-byte return.
    const iface = new Interface(["function totalSupply() view returns (uint256)"]);
    const value = 123_456_789n;
    const encoded = iface.encodeFunctionResult("totalSupply", [value]);
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, encoded)),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    const contract = new Contract("0x2222222222222222222222222222222222222222", iface, provider);
    expect(await contract.totalSupply()).toBe(value);
  });

  test("tampered response → BadSignature, fail-closed (strict default)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { tamper: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.getBalance(ADDR)).rejects.toBeInstanceOf(BadSignature);
  });

  test("wrong chainId → BadSignature (signed for one chain, verified against another)", async () => {
    // Sign the response bound to chain 1 (mainnet) but construct the provider
    // for arbitrum (42161): the signature is valid yet the pre-image chainId
    // differs → BadSignature.
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { signingChainId: 1n }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.getBalance(ADDR)).rejects.toBeInstanceOf(BadSignature);
  });

  test("unsigned response → MissingHeader, fail-closed (strict default)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { unsigned: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.getBalance(ADDR)).rejects.toBeInstanceOf(MissingHeader);
  });

  test("permissive mode passes tampered data through with exactly one warning", async () => {
    let calls = 0;
    const logger = () => {
      calls++;
    };
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { tamper: true }),
      CHAIN_ID_NUMBER,
      { verification: "permissive", logger, ...WIDE_WINDOW },
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(calls).toBe(1);
  });

  test("signed JSON-RPC {error} → ordinary ethers RPC error, NOT a VerificationError", async () => {
    const provider = new VrpcProvider(
      signingRequest(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
      ),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    // The signature is valid (verified first); ethers then surfaces the RPC
    // error. It must NOT be downgraded into / confused with a VerificationError.
    const err = await provider.getBalance(ADDR).then(
      () => {
        throw new Error("expected rejection");
      },
      (e) => e,
    );
    expect(err).not.toBeInstanceOf(VerificationError);
  });

  test("signed {result:null} returns null (getBlock of a missing block)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, null)),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    expect(await provider.getBlock(99_999_999)).toBeNull();
  });

  // ETHERS-03 — raw-transaction broadcast funnels through the verified `_send`.
  // `eth_sendRawTransaction` is the broadcast method; driving it via `_send`
  // (provider.send) proves it is NOT special-cased around verification: the
  // signed tx-hash result is verified, and a tampered response on the SAME
  // method path fails closed exactly like a read.
  const RAW_SIGNED_TX =
    "0x02f8730182012c8459682f008502540be40082520894aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa880de0b6b3a764000080c001a0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2a04f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";
  const TX_HASH = "0x88df020a2f000000000000000000000000000000000000000000000000000088";

  test("ETHERS-03: verified broadcast — eth_sendRawTransaction returns the verified tx hash", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, TX_HASH)),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    const hash = await provider.send("eth_sendRawTransaction", [RAW_SIGNED_TX]);
    expect(hash).toBe(TX_HASH);
  });

  test("ETHERS-03: unsigned broadcast response → MissingHeader (broadcast is NOT exempt from verification)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, TX_HASH), { unsigned: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.send("eth_sendRawTransaction", [RAW_SIGNED_TX])).rejects.toBeInstanceOf(
      MissingHeader,
    );
  });

  test("ETHERS-03: tampered broadcast response → BadSignature, fail-closed", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, TX_HASH), { tamper: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.send("eth_sendRawTransaction", [RAW_SIGNED_TX])).rejects.toBeInstanceOf(
      BadSignature,
    );
  });

  // ETHERS-04 — HTTP event-polling RPC calls funnel through the verified `_send`.
  // ethers' poll loop issues `eth_getLogs` (event filters) and
  // `eth_getFilterChanges` (filter subscriptions) via the same `_send`
  // chokepoint. Proving the underlying RPC verifies (and rejects unsigned) is
  // exactly what ETHERS-04 requires — no need to spin the polling timer.
  const LOG_ENTRY = {
    address: "0x3333333333333333333333333333333333333333",
    topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
    data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
    blockNumber: "0x10d4f",
    transactionHash: TX_HASH,
    transactionIndex: "0x0",
    blockHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
    logIndex: "0x0",
    removed: false,
  };

  test("ETHERS-04: verified eth_getLogs — polling/event funnels through verified _send", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY])),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    const logs = await provider.getLogs({ address: LOG_ENTRY.address, fromBlock: 0x10d4f });
    expect(logs).toHaveLength(1);
    expect(logs[0].transactionHash).toBe(TX_HASH);
  });

  test("ETHERS-04: unsigned eth_getLogs response → MissingHeader (poll path is NOT exempt)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY]), { unsigned: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(
      provider.getLogs({ address: LOG_ENTRY.address, fromBlock: 0x10d4f }),
    ).rejects.toBeInstanceOf(MissingHeader);
  });

  test("ETHERS-04: verified eth_getFilterChanges — filter-subscription poll funnels through verified _send", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY])),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    // The filter-poll RPC ethers fires on each tick. Driving it via `_send`
    // proves the poll-loop's RPC is verified before the parsed changes surface.
    const changes = await provider.send("eth_getFilterChanges", ["0x1"]);
    expect(changes).toHaveLength(1);
    expect((changes as Array<{ transactionHash: string }>)[0].transactionHash).toBe(TX_HASH);
  });

  test("ETHERS-04: tampered eth_getFilterChanges response → BadSignature, fail-closed", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY]), { tamper: true }),
      CHAIN_ID_NUMBER,
      WIDE_WINDOW,
    );
    await expect(provider.send("eth_getFilterChanges", ["0x1"])).rejects.toBeInstanceOf(
      BadSignature,
    );
  });

  // MD-01 — chain ids beyond Number.MAX_SAFE_INTEGER (2^53−1) must survive the
  // constructor without precision loss. The pre-image binds the full u64 chain
  // id, so a `number`-widened chainId would diverge from what the sidecar signed
  // and reject an intact response (false BadSignature). Passing a bigint through
  // the constructor → #chainId → verify({ chainId }) chain must round-trip the
  // exact value: sign-and-verify succeeds for the large id, and a one-off
  // mismatch still throws BadSignature (verification is NOT weakened).
  const LARGE_CHAIN_ID = (1n << 53n) + 12_345n; // 9_007_199_254_753_337n > 2^53−1

  test("MD-01: large chainId > 2^53−1 round-trips exactly (bigint, no precision loss)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { chainId: LARGE_CHAIN_ID }),
      LARGE_CHAIN_ID,
      WIDE_WINDOW,
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });

  test("MD-01: large chainId mismatch still fails closed (BadSignature, verification not weakened)", async () => {
    // Signed for LARGE_CHAIN_ID+1, verified against LARGE_CHAIN_ID → mismatch.
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), {
        signingChainId: LARGE_CHAIN_ID + 1n,
      }),
      LARGE_CHAIN_ID,
      WIDE_WINDOW,
    );
    await expect(provider.getBalance(ADDR)).rejects.toBeInstanceOf(BadSignature);
  });

  test("batch: verified once over the array body, results correlate by id", async () => {
    // Disable static-network round-trips and force batching by issuing two
    // concurrent calls. The request-aware responder reads the actual array
    // payload ethers POSTs, echoes each id with a matching result, and signs
    // the whole array body once — exactly the production batch path.
    const req = new FetchRequest("http://test.invalid");
    req.getUrlFunc = async (sentReq) => {
      const requestBytes = sentReq.body ?? new Uint8Array();
      const payload = JSON.parse(new TextDecoder().decode(requestBytes));
      // payload is an array when ethers batches; build an aligned result array.
      const results = (payload as Array<{ id: number; method: string }>).map((p) => {
        if (p.method === "eth_blockNumber") {
          return { jsonrpc: "2.0", id: p.id, result: toBeHex(0x10d4f) };
        }
        return { jsonrpc: "2.0", id: p.id, result: SINGLE_RESULT_BALANCE_HEX };
      });
      const responseBytes = new TextEncoder().encode(JSON.stringify(results));
      const headers = await signResponseBytes(requestBytes, responseBytes, {});
      return { statusCode: 200, statusMessage: "OK", headers, body: responseBytes };
    };

    const provider = new VrpcProvider(req, CHAIN_ID_NUMBER, {
      ...WIDE_WINDOW,
      batchMaxCount: 10,
      batchStallTime: 10,
    });

    const [blockNumber, balance] = await Promise.all([
      provider.getBlockNumber(),
      provider.getBalance(ADDR),
    ]);
    expect(blockNumber).toBe(0x10d4f);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });
});
