// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Every attestation outcome in both modes: each row runs through the open-mode TrustedVerifier
// and the Ankr Confidential RPC handshake against the same `/attestation` answer, then checks
// that the failure is not remembered.

import { AttestationError } from "@w3tech.io/dstack-verify";
import {
  attestationBody,
  CHAIN_ID,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  signResponse,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test, vi } from "vitest";
import { ATTESTATION_TIMEOUT_MS } from "../src/attestation";
import { ConfidentialClient } from "../src/confidential-client";
import {
  AttestationFailed,
  AttestationUnavailable,
  UnavailableError,
  VerificationError,
} from "../src/errors";
import { fetchTransport, ResponseTooLarge } from "../src/transport";
import { TrustedVerifier } from "../src/trusted-verifier";

const MiB = 1_048_576;
const BASE_URL = "https://rpc.example/eth_vrpc";
const SECRET = "sentinel-SECRET";
const BAD_PUBKEY = "pubkey must be 0x + 64 hex chars";
const NOT_JSON = "response is not valid JSON";

type ModeName = "open" | "confidential";

interface Row {
  name: string;
  /** The `/attestation` answer for the requested nonce; a throw is the fetch failing. */
  answer: (nonceHex: string, init: RequestInit) => Response | Promise<Response>;
  /** Omitted when the attestation verifies. */
  error?: {
    type: typeof AttestationUnavailable | typeof AttestationFailed;
    reason: string;
    status?: number;
    chkId?: string;
    detail?: string;
  };
  /** Omitted when the hardware verifier is never reached. */
  hardwareCalls?: number;
  /** Thrown once by the hardware verifier; the error must carry it as `cause`. */
  hardwareError?: Error;
  /** Text of the answer that no part of the error may carry. */
  hidden?: string;
  modes?: ModeName[];
  /** The answer never comes: the deadline settles the attestation. */
  stalls?: boolean;
}

const reply = (
  body: string | Uint8Array | null,
  status = 200,
  headers: Record<string, string> = { "vRPC-NodeId": NODE_ID },
): Response => new Response(body, { status, headers });

type Fields = Record<string, unknown> & { quote: Record<string, unknown> };

/** The valid answer with its JSON body edited. */
const edited =
  (edit: (body: Fields) => void) =>
  (nonceHex: string): Response => {
    const body = JSON.parse(attestationBody(nonceHex)) as Fields;
    edit(body);
    return reply(JSON.stringify(body));
  };

const valid = (nonceHex: string): Response => reply(attestationBody(nonceHex));
const unavailable = (reason: string, status?: number) => ({
  type: AttestationUnavailable,
  reason,
  ...(status === undefined ? {} : { status }),
});
const failed = (reason: string, detail?: string, chkId?: string) => ({
  type: AttestationFailed,
  reason,
  ...(detail === undefined ? {} : { detail }),
  ...(chkId === undefined ? {} : { chkId }),
});

const ROWS: Row[] = [
  {
    name: "a fetch that throws",
    answer: () => {
      throw new TypeError(`fetch failed: https://k/${SECRET}`);
    },
    error: unavailable("transport"),
    hidden: SECRET,
  },
  {
    name: "status 404",
    answer: () => reply("not found", 404),
    error: unavailable("status", 404),
  },
  {
    name: "status 500 with a valid body",
    answer: (nonceHex) => reply(attestationBody(nonceHex), 500),
    error: unavailable("status", 500),
  },
  {
    name: "a redirect, which is not followed",
    answer: (nonceHex, init) => (init.redirect === "manual" ? reply(null, 302) : valid(nonceHex)),
    error: unavailable("status", 302),
  },
  {
    name: "status 299 with a valid body",
    answer: (nonceHex) => reply(attestationBody(nonceHex), 299),
    hardwareCalls: 1,
  },
  {
    name: "a body of 1 MiB + 1 byte",
    answer: () => reply(new Uint8Array(MiB + 1)),
    error: unavailable("too-large"),
  },
  {
    name: "a valid body padded to exactly 1 MiB",
    answer: (nonceHex) => reply(attestationBody(nonceHex).padEnd(MiB, " ")),
    hardwareCalls: 1,
  },
  {
    name: "a transport over its own size cap",
    answer: () => {
      throw new ResponseTooLarge();
    },
    error: unavailable("too-large"),
  },
  {
    name: "a non-JSON body",
    answer: () => reply(`<html>${SECRET}</html>`),
    error: failed("malformed", NOT_JSON),
    hidden: SECRET,
  },
  {
    name: "an empty body",
    answer: () => reply(""),
    error: failed("malformed", NOT_JSON),
  },
  {
    name: "a body without pubkey",
    answer: edited((body) => delete body.pubkey),
    error: failed("malformed", "missing field: pubkey"),
  },
  {
    name: "a body without composeHash",
    answer: edited((body) => delete body.composeHash),
    error: failed("malformed", "missing field: composeHash"),
  },
  {
    name: "a quote without event_log",
    answer: edited((body) => delete body.quote.event_log),
    error: failed("malformed", "missing field: quote.event_log"),
  },
  {
    name: "a quote that is a string",
    answer: edited((body) => Object.assign(body, { quote: "abcdef" })),
    error: failed("malformed", "quote must be an object"),
  },
  {
    name: "a pubkey of 63 hex characters",
    answer: edited((body) => Object.assign(body, { pubkey: String(body.pubkey).slice(0, -1) })),
    error: failed("malformed", BAD_PUBKEY),
  },
  {
    name: "a pubkey without 0x",
    answer: edited((body) => Object.assign(body, { pubkey: String(body.pubkey).slice(2) })),
    error: failed("malformed", BAD_PUBKEY),
  },
  {
    name: "a pubkey with non-hex characters",
    answer: edited((body) => Object.assign(body, { pubkey: `0x${"zz".repeat(32)}` })),
    error: failed("malformed", BAD_PUBKEY),
  },
  {
    name: "report_data bound to another nonce",
    answer: edited((body) => {
      body.quote.report_data = `${String(body.quote.report_data).slice(0, 64)}${"0".repeat(64)}`;
    }),
    error: failed("check", undefined, "CHK-A1"),
  },
  {
    name: "a hardware verifier rejecting the quote",
    answer: valid,
    error: failed("check", undefined, "CHK-P1"),
    hardwareCalls: 1,
    hardwareError: new AttestationError("CHK-P1", "verified false"),
  },
  {
    name: "a hardware verifier outage",
    answer: valid,
    error: unavailable("verifier"),
    hardwareCalls: 1,
    hardwareError: new AttestationError("CHK-P1", "HTTP 503", { unavailable: true }),
  },
  {
    name: "a hardware verifier throwing a foreign error",
    answer: valid,
    error: failed("check", "hardware verifier failed", "CHK-P1"),
    hardwareCalls: 1,
    hardwareError: new TypeError("verifier bug"),
  },
  {
    name: "an attestation of another key",
    answer: (nonceHex) => reply(attestationBody(nonceHex, { seed: new Uint8Array(32).fill(9) })),
    error: failed("pubkey-mismatch"),
    modes: ["open"],
  },
  {
    name: "a non-JSON answer without vRPC-NodeId",
    answer: () => reply("not json", 200, {}),
    error: unavailable("node-id-missing", 200),
    modes: ["confidential"],
  },
  {
    name: "a fetch that never answers",
    answer: (_nonceHex, { signal }) =>
      new Promise((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason))),
    error: unavailable("timeout"),
    stalls: true,
  },
];

type HardwareMock = ReturnType<typeof mockHardwareVerifier>;
type Mode = (
  fetch: typeof globalThis.fetch,
  hardwareVerifier: HardwareMock,
) => () => Promise<unknown>;

const REQUEST = new TextEncoder().encode('{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}');
const RESPONSE = new TextEncoder().encode('{"jsonrpc":"2.0","id":1,"result":"0x1"}');

const MODES: Record<ModeName, Mode> = {
  open: (fetch, hardwareVerifier) => {
    const verifier = new TrustedVerifier({
      chainId: CHAIN_ID,
      attestationUrl: `${BASE_URL}/attestation`,
      fetch,
      hardwareVerifier,
    });
    return () =>
      verifier.verify(
        REQUEST,
        RESPONSE,
        signResponse(CHAIN_ID, REQUEST, RESPONSE, { nodeId: NODE_ID }),
      );
  },
  confidential: (fetch, hardwareVerifier) => {
    const client = new ConfidentialClient({
      url: BASE_URL,
      chainId: CHAIN_ID,
      transport: fetchTransport(fetch),
      hardwareVerifier,
    });
    return () => client.ready();
  },
};

const CASES = ROWS.flatMap((row) =>
  (row.modes ?? (Object.keys(MODES) as ModeName[])).map((mode) => ({ ...row, mode })),
);

describe("attestation outcomes in both modes", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  test.each(CASES)("$name ($mode)", async (row) => {
    const { answer, error, hardwareCalls = 0, hardwareError, hidden, mode, stalls } = row;
    if (stalls) vi.useFakeTimers();
    const globalFetch = vi.spyOn(globalThis, "fetch");
    const gets: string[] = [];
    let healthy = false;
    const fetch = (async (url: string, init: RequestInit) => {
      gets.push(url);
      const nonceHex = new URL(url).searchParams.get("nonce") ?? "";
      return healthy ? valid(nonceHex) : answer(nonceHex, init);
    }) as typeof globalThis.fetch;
    const hardwareVerifier = mockHardwareVerifier();
    const verifyHardware = vi.spyOn(hardwareVerifier, "verifyHardware");
    if (hardwareError) verifyHardware.mockRejectedValueOnce(hardwareError);
    const attest = MODES[mode](fetch, hardwareVerifier);

    if (error === undefined) {
      await attest();
    } else {
      const pending = rejectionOf(attest());
      if (stalls) {
        await vi.waitFor(() => expect(gets).toHaveLength(1));
        await vi.advanceTimersByTimeAsync(ATTESTATION_TIMEOUT_MS);
      }
      const err = await pending;
      const { type, ...fields } = error;
      expect(err).toBeInstanceOf(type);
      expect(err instanceof VerificationError).toBe(type === AttestationFailed);
      expect(err instanceof UnavailableError).toBe(type === AttestationUnavailable);
      expect(err).toMatchObject(fields);
      if (hardwareError) expect((err as Error).cause).toBe(hardwareError);
      if (hidden) {
        const e = err as Error;
        for (const text of [String(e), e.stack, JSON.stringify(e), String(e.cause)]) {
          expect(text).not.toContain(hidden);
        }
      }
    }
    expect(verifyHardware).toHaveBeenCalledTimes(hardwareCalls);
    expect(gets).toHaveLength(1);
    if (error !== undefined) {
      healthy = true;
      await attest();
      expect(gets).toHaveLength(2);
    }
    expect(globalFetch).not.toHaveBeenCalled();
  });
});
