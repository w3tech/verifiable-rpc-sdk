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
// EXACT bytes the transport POSTs (via signedJsonHeaders), so a real
// getBalance / readContract / getBlock payload verifies without the test
// predicting viem's internal body encoding. No `ethers` import (manifest
// isolation) — cross-adapter parity is proved against the vrpc-core class
// identity that BOTH adapters re-export.

import {
  attestationAnswer,
  CHAIN_ID,
  mockHardwareVerifier,
  signedJsonHeaders,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import {
  BadSignature,
  InvalidOption,
  MissingHeader,
  VerificationError,
  vrpcHttp,
} from "@w3tech.io/vrpc-viem";
import {
  createPublicClient,
  defineChain,
  encodeFunctionResult,
  HttpRequestError,
  parseAbi,
  RpcRequestError,
} from "viem";
import { describe, expect, test } from "vitest";
import { APP_COMPOSE, jsonResult, SINGLE_RESULT_BALANCE_HEX, WIDE_WINDOW } from "./fixtures";

const URL = "http://test.invalid";
const ADDR = "0x1111111111111111111111111111111111111111" as const;
// Signed responses carry `vRPC-NodeId`, so the verifier's attestation GET routes by node id.
const NODE_ID = "node-abc";

const sentText = (init: RequestInit): string => new TextDecoder().decode(init.body as Uint8Array);

interface SeamOptions {
  /** Strip the vRPC-* headers entirely (downgrade attack) → MissingHeader. */
  unsigned?: boolean;
  /** Flip one ASCII digit of the response body AFTER signing → BadSignature. */
  tamper?: boolean;
  /** Chain id used ONLY for signing (forge a chain-id-mismatch fixture). */
  signingChainId?: string;
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
      return attestationAnswer(url, { appCompose: APP_COMPOSE });
    }
    if (seam.counter) {
      seam.counter.n += 1;
    }
    if (seam.inits) {
      seam.inits.push(init);
    }
    const requestBytes = init.body as Uint8Array;
    if (seam.bodies) {
      seam.bodies.push(sentText(init));
    }
    const responseBytes = new TextEncoder().encode(responseBody);

    if (seam.unsigned) {
      return new Response(responseBody, {
        status: seam.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }

    const chainId = seam.signingChainId ?? CHAIN_ID;
    const headers = signedJsonHeaders(chainId, requestBytes, responseBytes, { nodeId: NODE_ID });

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

/**
 * A `fetchFn` answering `eth_chainId` with `bootstrapChainId` (default CHAIN_ID) signed for
 * `bootstrapSigningChainId`, and every other call with `responseBody` signed for `signingChainId`.
 */
function autoDeriveFetch(
  responseBody: string,
  seam: {
    bootstrapChainId?: string;
    bootstrapSigningChainId?: string;
    signingChainId?: string;
  } = {},
): (url: string, init: RequestInit) => Promise<Response> {
  const bootstrapChainId = seam.bootstrapChainId ?? CHAIN_ID;
  return async (url, init) => {
    if (url.includes("/attestation")) {
      return attestationAnswer(url, { appCompose: APP_COMPOSE });
    }
    const requestBytes = init.body as Uint8Array;
    const payload = JSON.parse(sentText(init)) as { method?: string };
    if (payload.method === "eth_chainId") {
      const bootstrapBody = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: `0x${BigInt(bootstrapChainId).toString(16)}`,
      });
      // `bootstrapSigningChainId` forges a claim the signature does not cover.
      const headers = signedJsonHeaders(
        seam.bootstrapSigningChainId ?? bootstrapChainId,
        requestBytes,
        new TextEncoder().encode(bootstrapBody),
      );
      return new Response(bootstrapBody, { status: 200, headers });
    }
    const responseBytes = new TextEncoder().encode(responseBody);
    const chainId = seam.signingChainId ?? CHAIN_ID;
    const headers = signedJsonHeaders(chainId, requestBytes, responseBytes, { nodeId: NODE_ID });
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
const OTHER_CHAIN = { chain: defineChain({ ...TEST_CHAIN, id: 1 }) } as never;
const GET_BALANCE = { method: "eth_getBalance", params: [ADDR, "latest"] } as const;

// Hardware verification is mandatory + defaults to a network cloud POST; inject
// the no-network mock so transport-wiring tests verify offline.
const MOCK_HV = mockHardwareVerifier();

function client(fetchFn: (url: string, init: RequestInit) => Promise<Response>) {
  return createPublicClient({
    chain: TEST_CHAIN,
    transport: vrpcHttp(URL, { fetchFn, replayWindowMs: WIDE_WINDOW, hardwareVerifier: MOCK_HV }),
  });
}

function pinnedTransport(fetchFn: (url: string, init: RequestInit) => Promise<Response>) {
  return vrpcHttp(URL, { fetchFn, replayWindowMs: WIDE_WINDOW, hardwareVerifier: MOCK_HV })(PINNED);
}

describe("vrpcHttp transport wiring", () => {
  // a verified eth_getBalance routes through the transport request.
  test("verified value routes through request: getBalance returns the decoded balance", async () => {
    const c = client(signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX)));
    const balance = await c.getBalance({ address: ADDR });
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX)); // 2 ETH in wei
  });

  test("a signed body starting with a UTF-8 BOM verifies against the raw bytes", async () => {
    const json = new TextEncoder().encode(jsonResult(SINGLE_RESULT_BALANCE_HEX));
    const body = new Uint8Array([0xef, 0xbb, 0xbf, ...json]);
    const fetchFn = async (url: string, init: RequestInit) => {
      if (url.includes("/attestation")) return attestationAnswer(url, { appCompose: APP_COMPOSE });
      const requestBytes = init.body as Uint8Array;
      const headers = signedJsonHeaders(CHAIN_ID, requestBytes, body, { nodeId: NODE_ID });
      return new Response(body, { status: 200, headers });
    };
    await expect(pinnedTransport(fetchFn).config.request(GET_BALANCE)).resolves.toBe(
      SINGLE_RESULT_BALANCE_HEX,
    );
  });

  test("a client on another chain gets InvalidOption and sends nothing", async () => {
    const counter = { n: 0 };
    const t = vrpcHttp(URL, {
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), { counter }),
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: MOCK_HV,
    });
    const a = t(PINNED);
    const b = t(OTHER_CHAIN);
    await expect(a.config.request(GET_BALANCE)).resolves.toBe(SINGLE_RESULT_BALANCE_HEX);
    await expect(b.config.request(GET_BALANCE)).rejects.toBeInstanceOf(InvalidOption);
    expect(counter.n).toBe(1);
  });

  test("a transport pinned to a wrong chain gives InvalidOption to a client on the right chain", async () => {
    const t = vrpcHttp(URL, {
      fetchFn: signingFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX)),
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: MOCK_HV,
    });
    const wrong = t(OTHER_CHAIN);
    const right = t(PINNED);
    await expect(wrong.config.request(GET_BALANCE)).rejects.toBeInstanceOf(BadSignature);
    await expect(right.config.request(GET_BALANCE)).rejects.toBeInstanceOf(InvalidOption);
  });

  test("a chain pinned while the bootstrap is in flight is not overwritten by it", async () => {
    const node = autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX));
    let bootstrapStarted!: () => void;
    const started = new Promise<void>((resolve) => (bootstrapStarted = resolve));
    let releaseBootstrap!: () => void;
    const bootstrapGate = new Promise<void>((resolve) => (releaseBootstrap = resolve));
    let releaseSecondRead!: () => void;
    const secondReadGate = new Promise<void>((resolve) => (releaseSecondRead = resolve));
    let reads = 0;
    const fetchFn = async (url: string, init: RequestInit) => {
      if (!url.includes("/attestation")) {
        if (sentText(init).includes('"eth_chainId"')) {
          bootstrapStarted();
          await bootstrapGate;
        } else if (++reads === 2) {
          await secondReadGate;
        }
      }
      return node(url, init);
    };
    const t = vrpcHttp(URL, { fetchFn, replayWindowMs: WIDE_WINDOW, hardwareVerifier: MOCK_HV });

    const noChain = t({} as never).config.request(GET_BALANCE);
    const noChainSettled = noChain.catch(() => {});
    await started;
    const otherChain = t(OTHER_CHAIN);
    const otherChainRead = otherChain.config.request(GET_BALANCE);
    releaseBootstrap();
    await noChainSettled;
    releaseSecondRead();

    await expect(otherChainRead).rejects.toBeInstanceOf(BadSignature);
    await expect(noChain).rejects.toMatchObject({ kind: "InvalidChainId", executed: "unknown" });
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

  // a chain id beyond Number.MAX_SAFE_INTEGER round-trips exactly through
  // the auto-derive bootstrap (parseChainId decodes the full value off the hex
  // into a decimal string; no number coercion). Explicit pinning of such ids is
  // N/A — viem's chain.id is a number — but the verified bootstrap still binds
  // the exact decimal string.
  const LARGE_CHAIN_ID = ((1n << 53n) + 12_345n).toString(10); // "9007199254753337" > 2^53−1

  test("large chainId > 2^53−1 derives + binds exactly via the verified bootstrap", async () => {
    const c = createPublicClient({
      transport: vrpcHttp(URL, {
        fetchFn: autoDeriveFetch(jsonResult(SINGLE_RESULT_BALANCE_HEX), {
          bootstrapChainId: LARGE_CHAIN_ID,
          signingChainId: LARGE_CHAIN_ID,
        }),
        replayWindowMs: WIDE_WINDOW,
        hardwareVerifier: MOCK_HV,
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
    await expect(transport.config.request(GET_BALANCE)).rejects.toBeInstanceOf(MissingHeader);
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
    const err = await transport.config.request(GET_BALANCE).then(
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
    await transport.config.request(GET_BALANCE).catch(() => {});
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
    const parsed = JSON.parse(bodies[0] ?? "");
    expect(Array.isArray(parsed)).toBe(false);
    expect(parsed.method).toBe("eth_getBalance");
  });

  // an UNSIGNED non-2xx response (gateway 502 / timeout error page)
  // surfaces as a transport-level HttpRequestError BEFORE verify, NOT as a
  // MissingHeader that looks like a verify attack. Parity with the ethers
  // adapter's `response.assertOk()` → SERVER_ERROR (not a VerificationError).
  test("unsigned non-2xx → HttpRequestError (not MissingHeader), NOT a VerificationError", async () => {
    const transport = pinnedTransport(
      signingFetch("upstream unavailable", { unsigned: true, status: 502 }),
    );
    const err = await transport.config.request(GET_BALANCE).then(
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
    const err = await transport.config.request(GET_BALANCE).then(
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

  test("auto-derive retry: a failed bootstrap is retried and the next call verifies with the honest chainId", async () => {
    const answer = jsonResult(SINGLE_RESULT_BALANCE_HEX);
    const lying = autoDeriveFetch(answer, {
      bootstrapChainId: "1",
      bootstrapSigningChainId: CHAIN_ID,
    });
    const honest = autoDeriveFetch(answer);
    let bootstraps = 0;
    const fetchFn = (url: string, init: RequestInit) => {
      if (!url.includes("/attestation") && sentText(init).includes('"eth_chainId"')) {
        bootstraps += 1;
        if (bootstraps === 1) return lying(url, init);
      }
      return honest(url, init);
    };
    const transport = vrpcHttp(URL, {
      fetchFn,
      replayWindowMs: WIDE_WINDOW,
      hardwareVerifier: MOCK_HV,
    })({} as never);
    await expect(transport.config.request(GET_BALANCE)).rejects.toBeInstanceOf(BadSignature);
    await expect(transport.config.request(GET_BALANCE)).resolves.toBe(SINGLE_RESULT_BALANCE_HEX);
    expect(bootstraps).toBe(2);
  });
});

describe("response classes", () => {
  const VALUE = jsonResult(SINGLE_RESULT_BALANCE_HEX);
  const ERROR = JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "x" } });
  test.each<[string, string, SeamOptions, unknown]>([
    ["signed 2xx → value", VALUE, {}, SINGLE_RESULT_BALANCE_HEX],
    ["tampered signed 2xx → BadSignature", VALUE, { tamper: true }, BadSignature],
    ["signed 500 with an error member → RpcRequestError", ERROR, { status: 500 }, RpcRequestError],
    [
      "signed 502 without an error member → HttpRequestError",
      VALUE,
      { status: 502 },
      HttpRequestError,
    ],
    [
      "signed 502 with a non-JSON body → HttpRequestError",
      "bad gateway",
      { status: 502 },
      HttpRequestError,
    ],
    ["tampered signed 502 → BadSignature", VALUE, { status: 502, tamper: true }, BadSignature],
    ["unsigned 2xx → MissingHeader", VALUE, { unsigned: true }, MissingHeader],
    [
      "unsigned 502 → HttpRequestError",
      "unavailable",
      { unsigned: true, status: 502 },
      HttpRequestError,
    ],
  ])("%s", async (_, body, seam, expected) => {
    const attests: string[] = [];
    const node = signingFetch(body, seam);
    const transport = pinnedTransport((url, init) => {
      if (url.includes("/attestation")) attests.push(url);
      return node(url, init);
    });
    const result = transport.config.request(GET_BALANCE);
    if (typeof expected !== "function") return expect(await result).toBe(expected);
    await expect(result).rejects.toBeInstanceOf(expected);
    if (expected === HttpRequestError) await expect(result).rejects.toMatchObject({ status: 502 });
    if (seam.unsigned) expect(attests).toEqual([]);
  });
});

describe("vrpcHttp options", () => {
  function invalidOption(make: () => unknown): InvalidOption {
    const err = thrownBy(make);
    expect(err).toBeInstanceOf(InvalidOption);
    return err as InvalidOption;
  }

  test("a bad URL is InvalidOption in both modes and its message omits the URL", () => {
    for (const confidential of [false, true]) {
      const err = invalidOption(() => vrpcHttp("::bad SECRETKEY42", { confidential }));
      expect(err).toMatchObject({ option: "url", executed: "no" });
      expect(`${String(err)} ${JSON.stringify(err)}`).not.toContain("SECRETKEY42");
    }
  });

  test("a non-boolean confidential flag and an open-mode TTL are checked before any request", () => {
    const sent: string[] = [];
    const fetchFn = async (url: string) => {
      sent.push(url);
      throw new Error("nothing may be sent");
    };
    const url = "http://test.invalid/eth_vrpc";

    expect(invalidOption(() => vrpcHttp(url, { confidential: "yes" } as never))).toMatchObject({
      option: "confidential",
    });
    expect(
      invalidOption(() => vrpcHttp(url, { fetchFn, pubkeyCacheTtlMs: Number.POSITIVE_INFINITY })),
    ).toMatchObject({ option: "pubkeyCacheTtlMs" });
    expect(sent).toEqual([]);
  });
});
