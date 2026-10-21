// VrpcProvider open-mode wiring: FetchRequest behaviour, response classes and
// option rules. Bootstrap, verify and decode are tested once in core
// (`packages/core/tests/open-session.test.ts`).

import { InvalidOption, VerificationError, VrpcProvider } from "@w3tech.io/vrpc-ethers";
import {
  attestationStub,
  CHAIN_ID,
  mockHardwareVerifier,
  signedJsonHeaders,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import {
  type ServedAnswer,
  type ServedRequest,
  serveUpstream,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support/server";
import { Contract, FetchRequest, FetchResponse, Interface, isError, toBeHex } from "ethers";
import { afterEach, describe, expect, test } from "vitest";
import { jsonResult, SINGLE_RESULT_BALANCE_HEX, WIDE_WINDOW } from "./fixtures";
import { flipFirstDigit, type SigningRequestOptions, signingRequest } from "./helpers";

// Always-on verify seam: the FIRST verified read per pubkey lazily fetches the
// node attestation. These adapter-WIRING tests are offline — the RPC POST leg is
// the request-aware getUrlFunc mock (per-instance), and the `/attestation` GET
// leg is served by this injected `fetch`. The mock's pubkey is derived from the
// SAME TEST_SEED the RPC responses are signed with, so pubkey correlation passes
// and the v5.0 mock verifier (allowInsecureMock) resolves — the read reaches its
// assertion. Each VrpcProvider below threads `fetch: ATT.fetch`; signed RPC
// responses carry a `vRPC-NodeId` so the seam routes the attestation fetch with
// `node_id` (the no-node_id path is exercised in provider.attestation.test.ts).
const ATT = attestationStub();
const NODE_ID = "node-abc";

// Answers `eth_chainId` with a signed `bootstrapChainId` and every other method with
// `responseBody` signed for CHAIN_ID.
function autoDeriveRequest(
  responseBody: string,
  opts: {
    bootstrapChainId?: string;
    bootstrapHits?: { n: number };
  } = {},
): FetchRequest {
  const bootstrapChainId = opts.bootstrapChainId ?? CHAIN_ID;
  const req = new FetchRequest("http://test.invalid");
  const responseBytes = new TextEncoder().encode(responseBody);
  req.getUrlFunc = async (sentReq) => {
    const requestBytes = sentReq.body ?? new Uint8Array();
    const payload = JSON.parse(new TextDecoder().decode(requestBytes)) as { method?: string };
    if (payload.method === "eth_chainId") {
      if (opts.bootstrapHits) {
        opts.bootstrapHits.n += 1;
      }
      const bootstrapResult = `0x${BigInt(bootstrapChainId).toString(16)}`;
      const body = new TextEncoder().encode(
        JSON.stringify({ jsonrpc: "2.0", id: 1, result: bootstrapResult }),
      );
      const headers = signedJsonHeaders(bootstrapChainId, requestBytes, body);
      return { statusCode: 200, statusMessage: "OK", headers, body };
    }
    const headers = signedJsonHeaders(CHAIN_ID, requestBytes, responseBytes, { nodeId: NODE_ID });
    return { statusCode: 200, statusMessage: "OK", headers, body: responseBytes };
  };
  return req;
}

const CHAIN_ID_NUMBER = Number(CHAIN_ID); // 42161 (arbitrum)
const ADDR = "0x1111111111111111111111111111111111111111";
// `fetch: ATT.fetch` serves the always-on
// attestation leg offline (every provider below threads it).
// Hardware verification is mandatory + defaults to a network cloud POST; inject
// the no-network mock so every provider built with WIDE_OPTIONS verifies offline.
const WIDE_OPTIONS = {
  replayWindowMs: WIDE_WINDOW,
  fetch: ATT.fetch,
  hardwareVerifier: mockHardwareVerifier(),
} as const;

describe("VrpcProvider._send wiring", () => {
  test("verified value routes through _send: getBalance returns the decoded balance", async () => {
    // The id ethers assigns to the first call is 1; the request-aware signer
    // signs whatever ethers actually POSTs, so we only need the response shape.
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
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
      signingRequest(jsonResult(1, encoded), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
    );
    const contract = new Contract("0x2222222222222222222222222222222222222222", iface, provider);
    expect(await contract.getFunction("totalSupply")()).toBe(value);
  });

  test("signed JSON-RPC {error} → ordinary ethers RPC error, NOT a VerificationError", async () => {
    const provider = new VrpcProvider(
      signingRequest(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: -32000, message: "execution reverted" },
        }),
        { nodeId: NODE_ID },
      ),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
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
      signingRequest(jsonResult(1, null), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
    );
    expect(await provider.getBlock(99_999_999)).toBeNull();
  });

  const RAW_SIGNED_TX =
    "0x02f8730182012c8459682f008502540be40082520894aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa880de0b6b3a764000080c001a0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2a04f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";
  const TX_HASH = "0x88df020a2f000000000000000000000000000000000000000000000000000088";

  test("verified broadcast — eth_sendRawTransaction returns the verified tx hash", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, TX_HASH), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
    );
    const hash = await provider.send("eth_sendRawTransaction", [RAW_SIGNED_TX]);
    expect(hash).toBe(TX_HASH);
  });

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

  test("verified eth_getLogs — polling/event funnels through verified _send", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY]), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
    );
    const logs = await provider.getLogs({ address: LOG_ENTRY.address, fromBlock: 0x10d4f });
    expect(logs).toHaveLength(1);
    expect(logs[0]?.transactionHash).toBe(TX_HASH);
  });

  test("verified eth_getFilterChanges — filter-subscription poll funnels through verified _send", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, [LOG_ENTRY]), { nodeId: NODE_ID }),
      CHAIN_ID_NUMBER,
      WIDE_OPTIONS,
    );
    // The filter-poll RPC ethers fires on each tick. Driving it via `_send`
    // proves the poll-loop's RPC is verified before the parsed changes surface.
    const changes = await provider.send("eth_getFilterChanges", ["0x1"]);
    expect(changes).toHaveLength(1);
    expect((changes as Array<{ transactionHash: string }>)[0]?.transactionHash).toBe(TX_HASH);
  });

  // The pre-image binds the exact decimal string, so a number-widened id would fail an intact answer.
  const LARGE_CHAIN_ID = (1n << 53n) + 12_345n; // 9_007_199_254_753_337n > 2^53−1

  test("large chainId > 2^53−1 round-trips exactly (bigint, no precision loss)", async () => {
    const provider = new VrpcProvider(
      signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), {
        signingChainId: LARGE_CHAIN_ID.toString(10),
        nodeId: NODE_ID,
      }),
      LARGE_CHAIN_ID,
      WIDE_OPTIONS,
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
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
      const headers = signedJsonHeaders(CHAIN_ID, requestBytes, responseBytes, { nodeId: NODE_ID });
      return { statusCode: 200, statusMessage: "OK", headers, body: responseBytes };
    };

    const provider = new VrpcProvider(req, CHAIN_ID_NUMBER, {
      ...WIDE_OPTIONS,
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

  test("bare-url auto-derive: NO chainId → SIGNED bootstrap is verified, then a verified read succeeds", async () => {
    const provider = new VrpcProvider(
      autoDeriveRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX)),
      undefined,
      WIDE_OPTIONS,
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
  });

  test("positional bigint chainId pins (zero bootstrap)", async () => {
    const bootstrapHits = { n: 0 };
    const provider = new VrpcProvider(
      autoDeriveRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { bootstrapHits }),
      BigInt(CHAIN_ID),
      WIDE_OPTIONS,
    );
    const balance = await provider.getBalance(ADDR);
    expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    expect(bootstrapHits.n).toBe(0);
  });

  // STRING-CHAINID — the constructor accepts number | bigint | string and
  // normalizes to ONE canonical decimal string, so all three arg forms bind the
  // IDENTICAL pre-image bytes (fixtures sign with the string "42161").

  test("number, bigint and string chainId args all bind the same decimal string", async () => {
    for (const arg of [42_161, 42_161n, "42161"] as const) {
      const provider = new VrpcProvider(
        signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID }),
        arg,
        WIDE_OPTIONS,
      );
      const balance = await provider.getBalance(ADDR);
      expect(balance).toBe(BigInt(SINGLE_RESULT_BALANCE_HEX));
    }
  });

  test("non-EVM string chainId is accepted at construction (no network pin)", () => {
    // No network assertions and no requests fired — ethers cannot represent a
    // non-EVM network; the verifier would bind the exact string on first use.
    // "-239" is TON's global id (non-decimal → no staticNetwork pin).
    expect(() => new VrpcProvider("http://test.invalid", "-239", WIDE_OPTIONS)).not.toThrow();
  });
});

const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function provide(url: string | FetchRequest): VrpcProvider {
  const provider = new VrpcProvider(url, CHAIN_ID_NUMBER, WIDE_OPTIONS);
  cleanups.push(() => provider.destroy());
  return provider;
}

async function outcome(provider: VrpcProvider): Promise<string> {
  try {
    const balance = await provider.getBalance(ADDR);
    return balance === BigInt(SINGLE_RESULT_BALANCE_HEX) ? "value" : String(balance);
  } catch (err) {
    return isError(err, "SERVER_ERROR") ? "SERVER_ERROR" : (err as Error).name;
  }
}

function signed(request: ServedRequest): ServedAnswer {
  const { id } = JSON.parse(new TextDecoder().decode(request.body)) as { id: number };
  const body = new TextEncoder().encode(jsonResult(id, SINGLE_RESULT_BALANCE_HEX));
  return { status: 200, headers: signedJsonHeaders(CHAIN_ID, request.body, body), body };
}

async function serve(options?: TestNodeServerOptions) {
  const server = await serveUpstream(() => ({ status: 500 }), options);
  cleanups.push(() => server.close());
  return server;
}

describe("FetchRequest semantics", () => {
  test("a 429 answer is retried and the retried answer verifies", async () => {
    const req = signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID });
    const sign = req.getUrlFunc;
    let posts = 0;
    req.getUrlFunc = async (sentReq, signal) => {
      posts += 1;
      if (posts > 1) return sign(sentReq, signal);
      return { statusCode: 429, statusMessage: "", headers: { "retry-after": "1" }, body: null };
    };
    expect(await outcome(provide(req))).toBe("value");
    expect(posts).toBe(2);
  });

  test("a 307 redirect is followed and the final answer verifies", async () => {
    const server = await serve();
    server.answer((request) =>
      request.path === "/rpc"
        ? { status: 307, headers: { location: `${server.url}/elsewhere` } }
        : signed(request),
    );
    expect(await outcome(provide(`${server.url}/rpc`))).toBe("value");
    const [first, second] = server.requests;
    expect([first?.path, second?.path]).toEqual(["/rpc", "/elsewhere"]);
    expect(second?.body).toEqual(first?.body);
  });

  test("a gzip answer verifies over the decoded bytes", async () => {
    const server = await serve({ gzipWhenAccepted: true });
    server.answer(signed);
    expect(await outcome(provide(`${server.url}/rpc`))).toBe("value");
    expect(server.requests[0]?.gzipped).toBe(true);
  });

  test.each([
    ["throws a throttle error once, the retry verifies", false, "value"],
    ["changes the body, BadSignature", true, "BadSignature"],
  ])("processFunc %s", async (_, change, expected) => {
    const req = signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), { nodeId: NODE_ID });
    let calls = 0;
    req.processFunc = async (request, response) => {
      calls += 1;
      if (!change && calls === 1) response.throwThrottleError("busy", 1);
      if (!change) return response;
      const { statusCode, statusMessage, headers, body } = response;
      return new FetchResponse(
        statusCode,
        statusMessage,
        headers,
        flipFirstDigit(body ?? new Uint8Array()),
        request,
      );
    };
    expect(await outcome(provide(req))).toBe(expected);
    expect(calls).toBe(change ? 1 : 2);
  });
});

describe("response classes", () => {
  test.each<[string, SigningRequestOptions, string, number]>([
    ["signed 2xx → value", {}, "value", 1],
    ["signed 500 → SERVER_ERROR", { status: 500 }, "SERVER_ERROR", 1],
    ["tampered signed 500 → BadSignature", { status: 500, tamper: true }, "BadSignature", 0],
    ["unsigned 2xx → MissingHeader", { unsigned: true }, "MissingHeader", 0],
    ["unsigned 502 → SERVER_ERROR", { status: 502, unsigned: true }, "SERVER_ERROR", 0],
  ])("%s", async (_, answer, expected, attestations) => {
    const req = signingRequest(jsonResult(1, SINGLE_RESULT_BALANCE_HEX), {
      nodeId: NODE_ID,
      ...answer,
    });
    const sign = req.getUrlFunc;
    const posts: string[] = [];
    req.getUrlFunc = async (sentReq, signal) => {
      posts.push(new TextDecoder().decode(sentReq.body ?? new Uint8Array()));
      return sign(sentReq, signal);
    };
    const attested: string[] = [];
    const provider = new VrpcProvider(req, CHAIN_ID_NUMBER, {
      ...WIDE_OPTIONS,
      fetch: (async (input: string | URL | Request) => {
        attested.push(String(input));
        return ATT.fetch(input);
      }) as typeof fetch,
    });
    expect(await outcome(provider)).toBe(expected);
    expect(posts).toHaveLength(1);
    expect(posts[0]).toContain("eth_getBalance");
    expect(attested).toHaveLength(attestations);
  });
});

describe("constructor options", () => {
  const sent: string[] = [];
  const counting = {
    ...WIDE_OPTIONS,
    fetch: (async (input: string | URL | Request) => {
      sent.push(String(input));
      return ATT.fetch(input);
    }) as typeof fetch,
  };

  function invalidOption(make: () => unknown): InvalidOption {
    const err = thrownBy(make);
    expect(err).toBeInstanceOf(InvalidOption);
    return err as InvalidOption;
  }

  test("a bad URL is InvalidOption in both modes and its message omits the URL", () => {
    for (const confidential of [false, true]) {
      const err = invalidOption(() => new VrpcProvider("::bad SECRETKEY42", 1, { confidential }));
      expect(err).toMatchObject({ option: "url", executed: "no" });
      expect(`${String(err)} ${JSON.stringify(err)}`).not.toContain("SECRETKEY42");
    }
  });

  test("a fractional chain id is InvalidOption", () => {
    expect(invalidOption(() => new VrpcProvider("http://test.invalid", 1.5))).toMatchObject({
      option: "chainId",
    });
  });

  test.each(
    [false, true].flatMap((confidential) =>
      ["replayWindowMs", "pubkeyCacheTtlMs"].flatMap((option) =>
        [0, -1, 1.5, Number.POSITIVE_INFINITY].map((value) => ({ confidential, option, value })),
      ),
    ),
  )("confidential=$confidential $option=$value throws InvalidOption and sends nothing", ({
    confidential,
    option,
    value,
  }) => {
    const url = new FetchRequest("http://test.invalid");
    url.getUrlFunc = async (req) => {
      sent.push(req.url);
      throw new Error("nothing may be sent");
    };
    const make = () =>
      new VrpcProvider(url, CHAIN_ID, { ...counting, confidential, [option]: value });
    expect(invalidOption(make)).toMatchObject({ option, executed: "no" });
    expect(sent).toEqual([]);
  });

  test("confidentialReady in open mode still rejects with TypeError", async () => {
    const provider = new VrpcProvider("http://test.invalid", CHAIN_ID, WIDE_OPTIONS);
    await expect(provider.confidentialReady()).rejects.toBeInstanceOf(TypeError);
  });
});
