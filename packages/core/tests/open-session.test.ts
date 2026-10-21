import {
  attestationStub,
  CHAIN_ID,
  mockHardwareVerifier,
  signedJsonHeaders,
  thrownBy,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";
import { mayHaveExecuted } from "../src/errors";
import { createOpenSession, type PostResponse } from "../src/open-session";

const utf8 = new TextEncoder();
const READ = { jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] };
const RESULT = '{"jsonrpc":"2.0","id":1,"result":"0x1"}';

interface Answer {
  status?: number;
  unsigned?: boolean;
  tamper?: boolean;
  chain?: string;
  body?: string | Uint8Array;
  timestampMs?: bigint;
}

// In-memory node: signs each answer for `chain` (default CHAIN_ID) and counts posts and bootstraps.
function node(read: Answer = {}, boot: Answer = {}) {
  const stats = { posts: 0, bootstraps: 0 };
  let gate: Promise<void> | undefined;
  const post = async (request: Uint8Array): Promise<PostResponse> => {
    stats.posts++;
    const bootstrap = new TextDecoder().decode(request).includes('"eth_chainId"');
    if (bootstrap) {
      stats.bootstraps++;
      await gate;
    }
    const a = bootstrap ? boot : read;
    const text = a.body ?? (bootstrap ? '{"jsonrpc":"2.0","id":1,"result":"0xa4b1"}' : RESULT);
    const body = typeof text === "string" ? utf8.encode(text) : text;
    const headers = a.unsigned
      ? { "content-type": "application/json" }
      : signedJsonHeaders(a.chain ?? CHAIN_ID, request, body, { timestampMs: a.timestampMs });
    const sent = a.tamper ? new Uint8Array([...body, 0x20]) : body;
    return { status: a.status ?? 200, headers, body: sent };
  };
  return { post, stats, read, boot, hold: (until: Promise<void>) => (gate = until) };
}

function session(chainId?: string, wideWindow = true) {
  const stub = attestationStub();
  const s = createOpenSession<PostResponse>({
    chainId,
    attestationUrl: "https://rpc.example/eth_vrpc/attestation",
    fetch: stub.fetch,
    hardwareVerifier: mockHardwareVerifier(),
    replayWindowMs: wideWindow ? Number.MAX_SAFE_INTEGER : undefined,
    httpError: (response) => ({ httpError: response.status }),
  });
  return { s, attests: stub.urls };
}

// "ok:<json>" for a result, else the error kind (`httpError` for the hook result, else the class).
async function outcome(promise: Promise<{ json: unknown }>): Promise<string> {
  try {
    return `ok:${JSON.stringify((await promise).json)}`;
  } catch (err) {
    expect(mayHaveExecuted(err)).toBe(true);
    const e = err as { kind?: string; httpError?: number; constructor: { name: string } };
    return e.kind ?? (e.httpError === undefined ? e.constructor.name : "httpError");
  }
}

describe("createOpenSession bootstrap", () => {
  test("a chainless session bootstraps once and reuses the verifier", async () => {
    const n = node();
    const { s, attests } = session();
    expect(await outcome(s.send(READ, n.post))).toBe(`ok:${RESULT}`);
    expect(await s.chainId(n.post)).toBe(CHAIN_ID);
    await s.send(READ, n.post);
    expect(n.stats).toEqual({ posts: 3, bootstraps: 1 });
    expect(attests).toHaveLength(1);
  });

  test("parallel first sends make one bootstrap", async () => {
    const n = node();
    const { s } = session();
    await Promise.all(Array.from({ length: 5 }, () => s.send(READ, n.post)));
    expect(n.stats.bootstraps).toBe(1);
  });

  test.each<[string, Answer, string]>([
    ["lying chain id", { chain: "1" }, "BadSignature"],
    ["tampered", { tamper: true }, "BadSignature"],
    ["unsigned", { unsigned: true }, "MissingHeader"],
    ["malformed", { unsigned: true, body: "not json" }, "MalformedHeader"],
    ["chain id over 64 bytes", { body: `{"result":"0x${"f".repeat(60)}"}` }, "InvalidChainId"],
    ["signed non-2xx", { status: 503 }, "httpError"],
    ["unsigned non-2xx", { status: 503, unsigned: true }, "httpError"],
  ])("a %s bootstrap answer fails the send before the caller's post", async (_, boot, expected) => {
    const n = node({}, boot);
    const { s, attests } = session();
    expect(await outcome(s.send(READ, n.post))).toBe(expected);
    expect(n.stats).toEqual({ posts: 1, bootstraps: 1 });
    if (expected === "httpError") expect(attests).toHaveLength(0);
  });

  test.each<[string, string | Uint8Array]>([
    ["non-JSON", `<html>${"x".repeat(10_000)}</html>`],
    ["over 256 bits", `{"result":"0x${"f".repeat(10_000)}"}`],
    [
      "invalid UTF-8",
      new Uint8Array([...utf8.encode('{"result":"0xa4b1","x":"'), 0xff, 0x22, 0x7d]),
    ],
  ])("an unverified %s bootstrap body is MalformedHeader that never echoes it", async (_, body) => {
    const { s } = session();
    const err = await s.send(READ, node({}, { body }).post).catch((e: unknown) => e);
    expect(err).toMatchObject({ kind: "MalformedHeader" });
    expect(`${String(err)}${(err as { value: string }).value}`.length).toBeLessThan(200);
  });

  test("a failed bootstrap leaves no memo and the next send bootstraps again", async () => {
    const n = node({}, { unsigned: true });
    const { s } = session();
    expect(await outcome(s.send(READ, n.post))).toBe("MissingHeader");
    n.boot.unsigned = false;
    expect(await outcome(s.send(READ, n.post))).toBe(`ok:${RESULT}`);
    expect(n.stats.bootstraps).toBe(2);
  });
});

describe("createOpenSession pin", () => {
  test("a configured chain id never bootstraps and pinning it again is a no-op", async () => {
    const n = node();
    const { s } = session(CHAIN_ID);
    s.pin(CHAIN_ID);
    expect(await outcome(s.send(READ, n.post))).toBe(`ok:${RESULT}`);
    expect(await s.chainId(n.post)).toBe(CHAIN_ID);
    expect(n.stats.bootstraps).toBe(0);
  });

  test("pinning another chain throws InvalidOption before any post", () => {
    const { s } = session(CHAIN_ID);
    expect(thrownBy(() => s.pin("1"))).toMatchObject({ kind: "InvalidOption", executed: "no" });
  });

  test("a pin during a bootstrap fails it with InvalidChainId and keeps the pin", async () => {
    const n = node();
    let release!: () => void;
    n.hold(new Promise<void>((resolve) => (release = resolve)));
    const { s } = session();
    const first = s.send(READ, n.post);
    await expect.poll(() => n.stats.bootstraps).toBe(1);
    s.pin("1");
    release();
    await expect(first).rejects.toMatchObject({ kind: "InvalidChainId", executed: "unknown" });
    n.read.chain = "1";
    expect(await outcome(s.send(READ, n.post))).toBe(`ok:${RESULT}`);
    expect(n.stats.bootstraps).toBe(1);
  });
});

describe("createOpenSession answers", () => {
  const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...utf8.encode(RESULT)]);
  test.each<[string, Answer, string]>([
    ["signed 2xx", {}, `ok:${RESULT}`],
    ["signed non-2xx", { status: 500, body: '{"error":1}' }, 'ok:{"error":1}'],
    ["signed non-2xx without JSON", { status: 502, body: "bad gateway" }, "ok:undefined"],
    ["tampered 2xx", { tamper: true }, "BadSignature"],
    ["tampered non-2xx", { status: 502, tamper: true }, "BadSignature"],
    ["unsigned 2xx", { unsigned: true }, "MissingHeader"],
    ["signed for another chain", { chain: "1" }, "BadSignature"],
    ["signed 2xx with a BOM", { body: bom }, `ok:${RESULT}`],
    ["signed 2xx with invalid UTF-8", { body: new Uint8Array([0xff]) }, "TypeError"],
  ])("%s", async (_, read, expected) => {
    const { s } = session(CHAIN_ID);
    expect(await outcome(s.send(READ, node(read).post))).toBe(expected);
  });

  test("an unsigned non-2xx answer is the httpError result with no attestation", async () => {
    const { s, attests } = session(CHAIN_ID);
    expect(await outcome(s.send(READ, node({ status: 502, unsigned: true }).post))).toBe(
      "httpError",
    );
    expect(attests).toHaveLength(0);
  });

  test("without replayWindowMs the default window rejects an old signature", async () => {
    const { s } = session(CHAIN_ID, false);
    expect(await outcome(s.send(READ, node().post))).toBe("StaleTimestamp");
  });
});
