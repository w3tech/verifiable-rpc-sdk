// TEST-03 — vrpcHttp transport WIRING suite (Phase 31, Wave 2).
//
// Asserts ADAPTER WIRING ONLY: that vrpcHttp's `request` routes every viem
// action through vrpc-core `verifyResponse` over the raw response bytes before
// parse, maps result/error/null back to callers, forces retryCount:0, defaults
// to per-request (non-batched) verification, and is fail-closed (always strict)
// + the re-exported VerificationError family.
//
// It does NOT re-test Ed25519 / pre-image / replay-window correctness — that is
// core's verify.test.ts (TEST-04). The request-aware fetch seam signs over the
// EXACT bytes the transport POSTs (via signResponseBytes), so a real
// getBalance / readContract / getBlock payload verifies without the test
// predicting viem's internal body encoding. No `ethers` import (manifest
// isolation) — cross-adapter parity is proved against the vrpc-core class
// identity that BOTH adapters re-export.

import { describe, expect, test } from "bun:test";
// Same family identity the ethers adapter re-exports — proves a caller cannot
// tell the two adapters apart by error shape (cross-adapter parity).
import { VerificationError as CoreVerificationError } from "@ankr.com/vrpc-core";
import {
  BadSignature,
  MalformedHeader,
  MissingHeader,
  VerificationError,
  vrpcHttp,
} from "@ankr.com/vrpc-viem";
import { createPublicClient, encodeFunctionResult, HttpRequestError, parseAbi } from "viem";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";

const URL = "http://test.invalid";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness; production
// keeps the vrpc-core default (60s).
const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;

interface SeamOptions {
  /** Strip the vRPC-* headers entirely (downgrade attack) → MissingHeader. */
  unsigned?: boolean;
  /** Flip one ASCII digit of the response body AFTER signing → BadSignature. */
  tamper?: boolean;
  /** Chain id used ONLY for signing (forge a chain-id-mismatch fixture). */
  signingChainId?: bigint;
  /** Chain id bound into the pre-image AND signed (large-id round-trip). */
  chainId?: bigint;
  /** Increment on every call — proves retryCount:0 (no retry of a failure). */
  counter?: { n: number };
  /** Capture the raw POST body of each call (batch-default assertion). */
  bodies?: string[];
  /** Override the HTTP status code (e.g. 502) for the MD-01 status check. */
  status?: number;
  /** Capture each call's RequestInit (e.g. to assert the timeout signal). */
  inits?: RequestInit[];
}

/**
 * Build an injected `fetchFn` that returns `responseBody` signed over the EXACT
 * request bytes the transport POSTed. Mirrors the ethers `signingRequest` helper
 * at the fetch layer.
 */
function signingFetch(
  responseBody: string,
  seam: SeamOptions = {},
): (url: string, init: RequestInit) => Promise<Response> {
  return async (_url, init) => {
    if (seam.counter) {
      seam.counter.n += 1;
    }
    if (seam.inits) {
      seam.inits.push(init);
    }
    const bodyStr = init.body as string;
    if (seam.bodies) {
      seam.bodies.push(bodyStr);
    }
    const requestBytes = new TextEncoder().encode(bodyStr);
    const responseBytes = new TextEncoder().encode(responseBody);

    if (seam.unsigned) {
      return new Response(responseBody, {
        status: seam.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }

    const headers = await signResponseBytes(requestBytes, responseBytes, {
      ...(seam.chainId !== undefined ? { chainId: seam.chainId } : {}),
      ...(seam.signingChainId !== undefined ? { signingChainId: seam.signingChainId } : {}),
    });

    // Tamper AFTER signing: flip one ASCII digit in the body so it stays valid
    // UTF-8 / JSON but the signed bytes no longer match → BadSignature.
    let outBody = responseBody;
    if (seam.tamper) {
      const idx = responseBody.search(/[0-9]/);
      const ch = responseBody[idx];
      const flipped = ch === "9" ? "8" : String(Number(ch) + 1);
      outBody = responseBody.slice(0, idx) + flipped + responseBody.slice(idx + 1);
    }
    return new Response(outBody, { status: seam.status ?? 200, headers });
  };
}

function jsonResult(result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, result });
}

/**
 * Build a `fetchFn` that answers a SIGNED `eth_chainId` bootstrap whose
 * `{result}` carries `bootstrapChainId` (default CHAIN_ID), signed over the
 * exact request bytes bound to `bootstrapSigningChainId` (default
 * `bootstrapChainId`, i.e. self-consistent), then optionally tampered/unsigned;
 * and answers every OTHER method with `responseBody`, SIGNED over the exact
 * bytes POSTed, bound to `signingChainId` (default CHAIN_ID). `bootstrapHits`
 * counts the bootstrap fetches. Mirrors the ethers `autoDeriveRequest` seam.
 *
 * The bootstrap is now VERIFIED self-consistently: a bootstrap whose claimed
 * `result` differs from the chain it was signed for, a tampered bootstrap, or
 * an unsigned bootstrap all fail FAST at `resolveChainId`.
 */
function autoDeriveFetch(
  responseBody: string,
  seam: {
    bootstrapChainId?: bigint;
    bootstrapSigningChainId?: bigint;
    bootstrapUnsigned?: boolean;
    bootstrapTamper?: boolean;
    // Override the bootstrap body with a raw (possibly malformed) string —
    // bad JSON, missing `result`, or non-hex `result`. Returned UNSIGNED since
    // the parse/shape guard must reject it BEFORE verifyResponse runs. (LOW-01/02)
    bootstrapRawBody?: string;
    signingChainId?: bigint;
    bootstrapHits?: { n: number };
  } = {},
): (url: string, init: RequestInit) => Promise<Response> {
  const bootstrapChainId = seam.bootstrapChainId ?? CHAIN_ID;
  return async (_url, init) => {
    const bodyStr = init.body as string;
    const payload = JSON.parse(bodyStr) as { method?: string };
    if (payload.method === "eth_chainId") {
      if (seam.bootstrapHits) {
        seam.bootstrapHits.n += 1;
      }
      if (seam.bootstrapRawBody !== undefined) {
        // Malformed bootstrap body: must be rejected at parse/shape time with a
        // typed MalformedHeader BEFORE verifyResponse — no signature needed.
        return new Response(seam.bootstrapRawBody, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      const bootstrapBody = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: `0x${bootstrapChainId.toString(16)}`,
      });
      if (seam.bootstrapUnsigned) {
        // UNSIGNED bootstrap → MissingHeader fail-fast at bootstrap.
        return new Response(bootstrapBody, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      const requestBytes = new TextEncoder().encode(bodyStr);
      const responseBytes = new TextEncoder().encode(bootstrapBody);
      // SIGNED bootstrap: by default signed over the SAME chain it claims
      // (self-consistent → verifies). `bootstrapSigningChainId` forges a
      // mismatch (signed for a chain != claimed result) → BadSignature.
      const headers = await signResponseBytes(requestBytes, responseBytes, {
        signingChainId: seam.bootstrapSigningChainId ?? bootstrapChainId,
      });
      let outBody = bootstrapBody;
      if (seam.bootstrapTamper) {
        // Flip the first ASCII digit AFTER signing → BadSignature (body stays
        // valid JSON so the parse before verify still succeeds).
        const idx = bootstrapBody.search(/[0-9]/);
        const ch = bootstrapBody[idx];
        const flipped = ch === "9" ? "8" : String(Number(ch) + 1);
        outBody = bootstrapBody.slice(0, idx) + flipped + bootstrapBody.slice(idx + 1);
      }
      return new Response(outBody, { status: 200, headers });
    }
    const requestBytes = new TextEncoder().encode(bodyStr);
    const responseBytes = new TextEncoder().encode(responseBody);
    const headers = await signResponseBytes(requestBytes, responseBytes, {
      ...(seam.signingChainId !== undefined ? { signingChainId: seam.signingChainId } : {}),
    });
    return new Response(responseBody, { status: 200, headers });
  };
}

function client(
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  overrides: { chainId?: bigint } = {},
) {
  return createPublicClient({
    transport: vrpcHttp(URL, {
      chainId: overrides.chainId ?? CHAIN_ID,
      fetchFn,
      replayWindowMs: WIDE_WINDOW,
    }),
  });
}

describe("vrpcHttp transport wiring (TEST-03)", () => {
  // VIEM-01/02 — a verified eth_getBalance routes through the transport request.
  test("verified value routes through request: getBalance returns the decoded balance", async () => {
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX)));
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // 2 ETH in wei
  });

  // VIEM-01/02 — a uint256 view eth_call → ABI-encoded result verifies + decodes.
  test("verified readContract returns the decoded value", async () => {
    const abi = parseAbi(["function totalSupply() view returns (uint256)"]);
    const value = 123_456_789n;
    const encoded = encodeFunctionResult({ abi, functionName: "totalSupply", result: value });
    const c = client(signingFetch(jsonResult(encoded)));
    const result = await c.readContract({
      address: "0x2222222222222222222222222222222222222222",
      abi,
      functionName: "totalSupply",
    });
    expect(result).toBe(value);
  });

  // VIEM-02 — tampered response fails closed. buildRequest re-wraps the typed
  // error as UnknownRpcError at the client surface; the typed error is `.cause`,
  // recovered via err.walk. (Transport-level type is asserted separately below.)
  test("tampered response → BadSignature, fail-closed (strict default)", async () => {
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { tamper: true }));
    const err = await c.getBalance({ address: ADDR }).then(
      () => {
        throw new Error("expected rejection");
      },
      (e) => e,
    );
    const typed =
      typeof err?.walk === "function" ? err.walk((e: unknown) => e instanceof BadSignature) : err;
    expect(typed).toBeInstanceOf(BadSignature);
  });

  // VIEM-02 — assert the typed error AT THE TRANSPORT request level (no
  // buildRequest re-wrap), matching how ethers asserts at the Provider surface.
  test("tampered response → BadSignature at the transport request level", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { tamper: true }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  // VIEM-02 / MD-01 — wrong-chain signature (signed for chain 1, verified
  // against arbitrum) → BadSignature.
  test("wrong chainId → BadSignature (signed for one chain, verified against another)", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { signingChainId: 1n }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  // MD-01 — chain id beyond Number.MAX_SAFE_INTEGER round-trips exactly (bigint,
  // no number coercion); the pre-image binds the full u64 chain id.
  const LARGE_CHAIN_ID = (1n << 53n) + 12_345n; // 9_007_199_254_753_337n > 2^53−1

  test("MD-01: large chainId > 2^53−1 round-trips exactly (bigint, no precision loss)", async () => {
    const c = client(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { chainId: LARGE_CHAIN_ID }),
      { chainId: LARGE_CHAIN_ID },
    );
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });

  // VIEM-02 — stripped vRPC-* headers (downgrade) → MissingHeader, fail-closed.
  test("unsigned response → MissingHeader, fail-closed (strict default)", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { unsigned: true }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MissingHeader);
  });

  // VIEM-02 — a signed JSON-RPC {error} body is an ordinary RPC error, NOT a
  // VerificationError (verification passes first; the error surfaces after).
  test("signed JSON-RPC {error} → ordinary viem RpcError, NOT a VerificationError", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
      ),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const err = await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .then(
        () => {
          throw new Error("expected rejection");
        },
        (e) => e,
      );
    expect(err).not.toBeInstanceOf(VerificationError);
  });

  // VIEM-02 — a signed {result:null} returns null (e.g. getBlock of a missing
  // block). Asserted at the transport level (viem's getBlock would otherwise
  // throw BlockNotFoundError on null, which is its own behavior, not the wiring).
  test("signed {result:null} returns null (missing block)", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(null)),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const result = await transport.config.request({
      method: "eth_getBlockByNumber",
      params: ["0x5f5e0ff", false],
    });
    expect(result).toBeNull();
  });

  // TEST-03 (retry) — a single failing action triggers exactly ONE fetch,
  // proving retryCount:0 (a verify failure is not retried 3×).
  test("retryCount:0 — injected fetch is called exactly once per failing action", async () => {
    const counter = { n: 0 };
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { tamper: true, counter }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .catch(() => {});
    expect(counter.n).toBe(1);
  });

  // VIEM-03 — batching OFF by default: a single action produces exactly one fetch
  // with a single (non-array) JSON body. Batched-as-one-unit is the deferred
  // opt-in (consistent with ETHERS-05).
  test("VIEM-03: per-request default — one action is one non-batched fetch", async () => {
    const bodies: string[] = [];
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bodies }));
    await c.getBalance({ address: ADDR });
    expect(bodies).toHaveLength(1);
    const parsed = JSON.parse(bodies[0]);
    expect(Array.isArray(parsed)).toBe(false);
    expect(parsed.method).toBe("eth_getBalance");
  });

  // CROSS-ADAPTER PARITY (VIEM-02) — the unsigned-response error from
  // @ankr.com/vrpc-viem is an instance of the SAME VerificationError family the
  // ethers adapter re-exports (class identity from @ankr.com/vrpc-core). A caller
  // cannot tell the two adapters apart by error shape.
  test("cross-adapter parity: unsigned error is the SAME VerificationError family as ethers", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { unsigned: true }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const err = await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .then(
        () => {
          throw new Error("expected rejection");
        },
        (e) => e,
      );
    // Instance of the viem-re-exported family AND the core class identity — the
    // same identity vrpc-ethers re-exports.
    expect(err).toBeInstanceOf(MissingHeader);
    expect(err).toBeInstanceOf(VerificationError);
    expect(err).toBeInstanceOf(CoreVerificationError);
  });

  // MD-01 — an UNSIGNED non-2xx response (gateway 502 / timeout error page)
  // surfaces as a transport-level HttpRequestError BEFORE verify, NOT as a
  // MissingHeader that looks like a verify attack. Parity with the ethers
  // adapter's `response.assertOk()` → SERVER_ERROR (not a VerificationError).
  test("MD-01: unsigned non-2xx → HttpRequestError (not MissingHeader), NOT a VerificationError", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch("upstream unavailable", { unsigned: true, status: 502 }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const err = await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .then(
        () => {
          throw new Error("expected rejection");
        },
        (e) => e,
      );
    expect(err).toBeInstanceOf(HttpRequestError);
    expect(err).not.toBeInstanceOf(VerificationError);
  });

  // MD-01 — fail-closed is NOT weakened by the status check: a SIGNED non-2xx
  // body still flows into verifyResponse, and its signed JSON-RPC {error}
  // surfaces as an ordinary RpcError (NOT an HttpRequestError, NOT a
  // VerificationError) — the sidecar attested the error response.
  test("MD-01: signed non-2xx with {error} body still verifies, surfaces as ordinary RpcError", async () => {
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: signingFetch(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
        { status: 500 },
      ),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const err = await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .then(
        () => {
          throw new Error("expected rejection");
        },
        (e) => e,
      );
    expect(err).not.toBeInstanceOf(HttpRequestError);
    expect(err).not.toBeInstanceOf(VerificationError);
  });

  // LO-03 — the transport `timeout` is applied to the actual fetch as an
  // AbortSignal (parity with viem `http()`). createPublicClient injects a
  // default timeout, so the own-fetch init carries a signal.
  test("LO-03: transport timeout is applied to the fetch as an AbortSignal", async () => {
    const inits: RequestInit[] = [];
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { inits }));
    await c.getBalance({ address: ADDR });
    expect(inits).toHaveLength(1);
    expect(inits[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  // CHAINID-OPTIONAL — chainId is now optional; the bare-url form auto-derives
  // it from a SIGNED eth_chainId response, VERIFIED self-consistently (the
  // response's own result IS the chainId), memoized so concurrent first calls
  // share a single fetch, and a tampered/forged/unsigned bootstrap fails FAST.

  test("bare-url auto-derive: NO chainId → SIGNED bootstrap is verified, then a verified read succeeds", async () => {
    const c = createPublicClient({
      transport: vrpcHttp(URL, {
        fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX)),
        replayWindowMs: WIDE_WINDOW,
      }),
    });
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });

  test("auto-derive memoization: N concurrent first calls fire exactly ONE eth_chainId bootstrap", async () => {
    const bootstrapHits = { n: 0 };
    const transport = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bootstrapHits }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await Promise.all([
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ]);
    expect(bootstrapHits.n).toBe(1);
  });

  test("auto-derive FAIL-FAST: a lying bootstrap (result claims a chain ≠ what it was signed for) → BadSignature AT BOOTSTRAP", async () => {
    // Bootstrap CLAIMS chain 1 (result=0x1) but is SIGNED for arbitrum
    // (CHAIN_ID). resolveChainId parses C=1 and verifies with chainId=1 → the
    // pre-image binds 1 while the signature is over CHAIN_ID → BadSignature,
    // thrown at bootstrap (fail-FAST) BEFORE any real read. No silent-accept,
    // no deferred BadSignature on a later call.
    const transport = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
        bootstrapChainId: 1n,
        bootstrapSigningChainId: CHAIN_ID,
        signingChainId: CHAIN_ID,
      }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  test("auto-derive FAIL-FAST: a tampered bootstrap response → BadSignature AT BOOTSTRAP", async () => {
    const transport = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bootstrapTamper: true }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  test("auto-derive FAIL-FAST: an UNSIGNED bootstrap response → MissingHeader AT BOOTSTRAP", async () => {
    const transport = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bootstrapUnsigned: true }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MissingHeader);
  });

  test("auto-derive FAIL-FAST: a malformed bootstrap body → typed MalformedHeader (not raw SyntaxError/TypeError) AT BOOTSTRAP (LOW-01/02)", async () => {
    // Invalid JSON → would throw a raw SyntaxError before verify; coerced to a
    // typed VerificationError so the malformed bootstrap reads as a verify
    // failure (LOW-02).
    const badJson = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
        bootstrapRawBody: "{not valid json",
      }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      badJson.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MalformedHeader);

    // Missing `result` → would throw a raw TypeError from BigInt(undefined);
    // coerced to MalformedHeader (LOW-01).
    const missingResult = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
        bootstrapRawBody: JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32000 } }),
      }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      missingResult.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MalformedHeader);

    // Non-hex `result` → would throw a raw SyntaxError from BigInt("0xZZ");
    // coerced to MalformedHeader (LOW-01).
    const nonHex = vrpcHttp(URL, {
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
        bootstrapRawBody: JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0xZZ" }),
      }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    await expect(
      nonHex.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MalformedHeader);
  });

  test("explicit-pin → ZERO bootstrap fetch (eth_chainId is never issued)", async () => {
    const bootstrapHits = { n: 0 };
    const transport = vrpcHttp(URL, {
      chainId: CHAIN_ID,
      fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bootstrapHits }),
      replayWindowMs: WIDE_WINDOW,
    })({} as never);
    const result = await transport.config.request({
      method: "eth_getBalance",
      params: [ADDR, "latest"],
    });
    expect(result).toBe(SINGLE_RESULT_BALANCE_HEX);
    expect(bootstrapHits.n).toBe(0);
  });
});
