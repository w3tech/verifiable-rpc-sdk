// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Every attestation outcome in both modes: each row runs through the open-mode TrustedVerifier
// and the Ankr Confidential RPC handshake against the same `/attestation` answer.

import {
  attestationBody,
  CHAIN_ID,
  mockHardwareVerifier,
  NODE_ID,
  rejectionOf,
  signResponse,
} from "@w3tech.io/vrpc-test-support";
import { describe, expect, test, vi } from "vitest";
import { ConfidentialClient } from "../src/confidential-client";
import { AttestationUnavailable } from "../src/errors";
import { fetchTransport, ResponseTooLarge } from "../src/transport";
import { TrustedVerifier } from "../src/trusted-verifier";

const MiB = 1_048_576;
const BASE_URL = "https://rpc.example/eth_vrpc";

interface Row {
  name: string;
  /** The `/attestation` body for the requested nonce; a throw is the fetch failing. */
  body: (nonceHex: string) => string | Uint8Array;
  /** Omitted when the attestation verifies. */
  error?: { type: new (...args: never[]) => Error; reason: string };
  hardwareCalls: number;
}

const ROWS: Row[] = [
  {
    name: "a body of 1 MiB + 1 byte",
    body: () => new Uint8Array(MiB + 1),
    error: { type: AttestationUnavailable, reason: "too-large" },
    hardwareCalls: 0,
  },
  {
    name: "a valid body padded to exactly 1 MiB",
    body: (nonceHex) => attestationBody(nonceHex).padEnd(MiB, " "),
    hardwareCalls: 1,
  },
  {
    name: "a transport over its own size cap",
    body: () => {
      throw new ResponseTooLarge();
    },
    error: { type: AttestationUnavailable, reason: "too-large" },
    hardwareCalls: 0,
  },
];

type Mode = (fetch: typeof globalThis.fetch, hardwareVerifier: HardwareMock) => Promise<unknown>;
type HardwareMock = ReturnType<typeof mockHardwareVerifier>;

const MODES: Record<string, Mode> = {
  open: (fetch, hardwareVerifier) => {
    const request = new TextEncoder().encode('{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}');
    const response = new TextEncoder().encode('{"jsonrpc":"2.0","id":1,"result":"0x1"}');
    const headers = signResponse(CHAIN_ID, request, response, { nodeId: NODE_ID });
    const attestationUrl = `${BASE_URL}/attestation`;
    const verifier = new TrustedVerifier({
      chainId: CHAIN_ID,
      attestationUrl,
      fetch,
      hardwareVerifier,
    });
    return verifier.verify(request, response, headers);
  },
  confidential: (fetch, hardwareVerifier) =>
    new ConfidentialClient({
      url: BASE_URL,
      chainId: CHAIN_ID,
      transport: fetchTransport(fetch),
      hardwareVerifier,
    }).ready(),
};

const CASES = ROWS.flatMap((row) => Object.keys(MODES).map((mode) => ({ ...row, mode })));

describe("attestation outcomes in both modes", () => {
  test.each(CASES)("$name ($mode)", async ({ body, error, hardwareCalls, mode }) => {
    const fetch = (async (url: string) => {
      const nonceHex = new URL(url).searchParams.get("nonce") ?? "";
      return new Response(body(nonceHex), { headers: { "vRPC-NodeId": NODE_ID } });
    }) as typeof globalThis.fetch;
    const hardwareVerifier = mockHardwareVerifier();
    const verifyHardware = vi.spyOn(hardwareVerifier, "verifyHardware");
    const run = (MODES[mode] as Mode)(fetch, hardwareVerifier);

    if (error === undefined) {
      await run;
    } else {
      const err = await rejectionOf(run);
      expect(err).toBeInstanceOf(error.type);
      expect(err).toMatchObject({ reason: error.reason });
    }
    expect(verifyHardware).toHaveBeenCalledTimes(hardwareCalls);
  });
});
