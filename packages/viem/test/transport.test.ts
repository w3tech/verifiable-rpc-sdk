// vrpcHttp transport WIRING suite.
//
// Asserts ADAPTER WIRING ONLY: that vrpcHttp's `request` routes every viem
// action through vrpc-core `verifyResponse` over the raw response bytes before
// parse, maps result/error/null back to callers, forces retryCount:0, defaults
// to per-request (non-batched) verification, and is fail-closed (always strict)
// + the re-exported VerificationError family.
//
// It does NOT re-test Ed25519 / pre-image / replay-window correctness — that is
// core's verify.test.ts. The request-aware fetch seam signs over the
// EXACT bytes the transport POSTs (via signResponseBytes), so a real
// getBalance / readContract / getBlock payload verifies without the test
// predicting viem's internal body encoding. No `ethers` import (manifest
// isolation) — cross-adapter parity is proved against the vrpc-core class
// identity that BOTH adapters re-export.

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
import { getPublicKeyAsync } from "@noble/ed25519";
import {
  createPublicClient,
  defineChain,
  encodeFunctionResult,
  HttpRequestError,
  parseAbi,
} from "viem";
import { describe, expect, test } from "vitest";

import { CHAIN_ID, SINGLE_RESULT_BALANCE_HEX, signResponseBytes } from "./fixtures";

const URL = "http://test.invalid";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
// Wide window neutralizes the static FIXTURE_TIMESTAMP_MS staleness; production
// keeps the vrpc-core default (60s).
const WIDE_WINDOW = Number.MAX_SAFE_INTEGER;
// Fixed seed used by the fixture signer — its pubkey is what the always-on
// TrustedVerifier's attestation leg must correlate to (same shape as the core
// trust mock). The signed responses carry `vRPC-NodeId` so the verifier's
// attestation GET routes by node id.
const TEST_SEED = new Uint8Array(32).fill(0x42);
const NODE_ID = "node-abc";

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Answer the verifier's attestation GET with a body whose `pubkey` correlates to
 * TEST_SEED (same shape as core/tests/trusted-verifier.test.ts). The always-on
 * TrustedVerifier fetches this once per unknown pubkey; the mock verifier then
 * resolves and the verified read proceeds.
 */
async function attestationResponse(url: string): Promise<Response> {
  const attPubkey = await getPublicKeyAsync(TEST_SEED);
  // CHK-A1: report_data = pubkey(bare) ‖ nonce(bare); echo the seam's `?nonce=`
  // query so the binding + 128-hex shape gate pass (nonceSource is random).
  // Regex-extract (not `new URL`) — viem shadows the global URL constructor here.
  const nonceHex = url.match(/[?&]nonce=([0-9a-fA-F]+)/)?.[1] ?? "";
  const reportData = `${hex(attPubkey)}${nonceHex}`;
  const body = {
    quote: { quote: "00", event_log: "00", report_data: reportData, vm_config: "" },
    pubkey: `0x${hex(attPubkey)}`,
    composeHash: "deadbeef",
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

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
  /** Override the HTTP status code (e.g. 502) for the status check. */
  status?: number;
  /** Capture each call's RequestInit (e.g. to assert the timeout signal). */
  inits?: RequestInit[];
}

/**
 * Build an injected `fetchFn` that returns `responseBody` signed over the EXACT
 * request bytes the transport POSTed. Mirrors the ethers `signingRequest` helper
 * at the fetch layer. The always-on TrustedVerifier's attestation GET (an unknown
 * signing pubkey triggers it once) is served with a TEST_SEED-correlated body;
 * the `counter`/`bodies`/`inits` capture hooks fire ONLY on the RPC POST leg so
 * the per-action assertions are unaffected by the attestation fetch.
 */
function signingFetch(
  responseBody: string,
  seam: SeamOptions = {},
): (url: string, init: RequestInit) => Promise<Response> {
  return async (url, init) => {
    // Attestation GET leg (no body): serve the correlated-pubkey attestation so
    // the verifier resolves the unknown pubkey. Do NOT bump the RPC capture hooks.
    if (url.includes("/attestation")) {
      return attestationResponse(url);
    }
    // Best-effort /info side-fetch (CHK-A2 app_compose): not served here →
    // 404 so the seam's best-effort catch leaves app_compose empty (CHK-A2 skips).
    // Excluded from the RPC capture hooks, same as /attestation.
    if (url.includes("/info")) {
      return new Response("not found", { status: 404 });
    }
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
      nodeId: NODE_ID,
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
    // the parse/shape guard must reject it BEFORE verifyResponse runs.
    bootstrapRawBody?: string;
    signingChainId?: bigint;
    bootstrapHits?: { n: number };
  } = {},
): (url: string, init: RequestInit) => Promise<Response> {
  const bootstrapChainId = seam.bootstrapChainId ?? CHAIN_ID;
  return async (url, init) => {
    // Attestation GET leg: served for the always-on verifier's lazy attest of the
    // (post-bootstrap) read's unknown signing pubkey.
    if (url.includes("/attestation")) {
      return attestationResponse(url);
    }
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
      nodeId: NODE_ID,
      ...(seam.signingChainId !== undefined ? { signingChainId: seam.signingChainId } : {}),
    });
    return new Response(responseBody, { status: 200, headers });
  };
}

// viem injects the client's `chain` into the transport factory; `chain.id` is the
// pin source now that chainId left the options bag. TEST_CHAIN pins CHAIN_ID.
const TEST_CHAIN = defineChain({
  id: Number(CHAIN_ID),
  name: "vrpc-test",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [URL] } },
});
// Inject TEST_CHAIN into a directly-invoked transport factory (what
// createPublicClient does under the hood for `client()`).
const PINNED = { chain: TEST_CHAIN } as never;

function client(fetchFn: (url: string, init: RequestInit) => Promise<Response>) {
  return createPublicClient({
    chain: TEST_CHAIN,
    transport: vrpcHttp(URL, { fetchFn, replayWindowMs: WIDE_WINDOW }),
  });
}

function pinnedTransport(fetchFn: (url: string, init: RequestInit) => Promise<Response>) {
  return vrpcHttp(URL, { fetchFn, replayWindowMs: WIDE_WINDOW })(PINNED);
}

describe("vrpcHttp transport wiring", () => {
  // a verified eth_getBalance routes through the transport request.
  test("verified value routes through request: getBalance returns the decoded balance", async () => {
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX)));
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // 2 ETH in wei
  });

  // a uint256 view eth_call → ABI-encoded result verifies + decodes.
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

  // tampered response fails closed. buildRequest re-wraps the typed
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

  // assert the typed error AT THE TRANSPORT request level (no
  // buildRequest re-wrap), matching how ethers asserts at the Provider surface.
  test("tampered response → BadSignature at the transport request level", async () => {
    const transport = pinnedTransport(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { tamper: true }),
    );
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  // wrong-chain signature (signed for chain 1, verified
  // against arbitrum) → BadSignature.
  test("wrong chainId → BadSignature (signed for one chain, verified against another)", async () => {
    const transport = pinnedTransport(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { signingChainId: 1n }),
    );
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(BadSignature);
  });

  // a chain id beyond Number.MAX_SAFE_INTEGER round-trips exactly through
  // the auto-derive bootstrap (parseChainId reads the full u64 off the hex; no
  // number coercion). Explicit pinning of such ids is N/A — viem's chain.id is a
  // number — but the verified bootstrap still binds the full u64.
  const LARGE_CHAIN_ID = (1n << 53n) + 12_345n; // 9_007_199_254_753_337n > 2^53−1

  test("large chainId > 2^53−1 derives + binds exactly via the verified bootstrap", async () => {
    const c = createPublicClient({
      transport: vrpcHttp(URL, {
        fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
          bootstrapChainId: LARGE_CHAIN_ID,
          signingChainId: LARGE_CHAIN_ID,
        }),
        replayWindowMs: WIDE_WINDOW,
      }),
    });
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });

  // stripped vRPC-* headers (downgrade) → MissingHeader, fail-closed.
  test("unsigned response → MissingHeader, fail-closed (strict default)", async () => {
    const transport = pinnedTransport(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { unsigned: true }),
    );
    await expect(
      transport.config.request({ method: "eth_getBalance", params: [ADDR, "latest"] }),
    ).rejects.toBeInstanceOf(MissingHeader);
  });

  // a signed JSON-RPC {error} body is an ordinary RPC error, NOT a
  // VerificationError (verification passes first; the error surfaces after).
  test("signed JSON-RPC {error} → ordinary viem RpcError, NOT a VerificationError", async () => {
    const transport = pinnedTransport(
      signingFetch(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
      ),
    );
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

  // a signed {result:null} returns null (e.g. getBlock of a missing
  // block). Asserted at the transport level (viem's getBlock would otherwise
  // throw BlockNotFoundError on null, which is its own behavior, not the wiring).
  test("signed {result:null} returns null (missing block)", async () => {
    const transport = pinnedTransport(signingFetch(jsonResult(null)));
    const result = await transport.config.request({
      method: "eth_getBlockByNumber",
      params: ["0x5f5e0ff", false],
    });
    expect(result).toBeNull();
  });

  // Retry — a single failing action triggers exactly ONE fetch,
  // proving retryCount:0 (a verify failure is not retried 3×).
  test("retryCount:0 — injected fetch is called exactly once per failing action", async () => {
    const counter = { n: 0 };
    const transport = pinnedTransport(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { tamper: true, counter }),
    );
    await transport.config
      .request({ method: "eth_getBalance", params: [ADDR, "latest"] })
      .catch(() => {});
    expect(counter.n).toBe(1);
  });

  // batching OFF by default: a single action produces exactly one fetch
  // with a single (non-array) JSON body. Batched-as-one-unit is the deferred
  // opt-in (consistent with the ethers adapter).
  test("per-request default — one action is one non-batched fetch", async () => {
    const bodies: string[] = [];
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bodies }));
    await c.getBalance({ address: ADDR });
    expect(bodies).toHaveLength(1);
    const parsed = JSON.parse(bodies[0]);
    expect(Array.isArray(parsed)).toBe(false);
    expect(parsed.method).toBe("eth_getBalance");
  });

  // CROSS-ADAPTER PARITY — the unsigned-response error from
  // @ankr.com/vrpc-viem is an instance of the SAME VerificationError family the
  // ethers adapter re-exports (class identity from @ankr.com/vrpc-core). A caller
  // cannot tell the two adapters apart by error shape.
  test("cross-adapter parity: unsigned error is the SAME VerificationError family as ethers", async () => {
    const transport = pinnedTransport(
      signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { unsigned: true }),
    );
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

  // an UNSIGNED non-2xx response (gateway 502 / timeout error page)
  // surfaces as a transport-level HttpRequestError BEFORE verify, NOT as a
  // MissingHeader that looks like a verify attack. Parity with the ethers
  // adapter's `response.assertOk()` → SERVER_ERROR (not a VerificationError).
  test("unsigned non-2xx → HttpRequestError (not MissingHeader), NOT a VerificationError", async () => {
    const transport = pinnedTransport(
      signingFetch("upstream unavailable", { unsigned: true, status: 502 }),
    );
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

  // fail-closed is NOT weakened by the status check: a SIGNED non-2xx
  // body still flows into verifyResponse, and its signed JSON-RPC {error}
  // surfaces as an ordinary RpcError (NOT an HttpRequestError, NOT a
  // VerificationError) — the sidecar attested the error response.
  test("signed non-2xx with {error} body still verifies, surfaces as ordinary RpcError", async () => {
    const transport = pinnedTransport(
      signingFetch(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
        { status: 500 },
      ),
    );
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

  // the transport `timeout` is applied to the actual fetch as an
  // AbortSignal (parity with viem `http()`). createPublicClient injects a
  // default timeout, so the own-fetch init carries a signal.
  test("transport timeout is applied to the fetch as an AbortSignal", async () => {
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

  test("auto-derive FAIL-FAST: a malformed bootstrap body → typed MalformedHeader (not raw SyntaxError/TypeError) AT BOOTSTRAP", async () => {
    // Invalid JSON → would throw a raw SyntaxError before verify; coerced to a
    // typed VerificationError so the malformed bootstrap reads as a verify
    // failure.
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
    // coerced to MalformedHeader.
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
    // coerced to MalformedHeader.
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
    const transport = pinnedTransport(
      autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { bootstrapHits }),
    );
    const result = await transport.config.request({
      method: "eth_getBalance",
      params: [ADDR, "latest"],
    });
    expect(result).toBe(SINGLE_RESULT_BALANCE_HEX);
    expect(bootstrapHits.n).toBe(0);
  });
});
