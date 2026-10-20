// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Sidecar `/attestation` answers and a fetch stub serving them.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { TEST_SEED } from "./sign";

export interface AttestationOptions {
  seed?: Uint8Array | undefined;
  appCompose?: string | undefined;
}

// JSON body binding the seed's pubkey and the nonce; appCompose also sets its composeHash.
export function attestationBody(nonceHex: string, options: AttestationOptions = {}): string {
  const pubkey = bytesToHex(ed25519.getPublicKey(options.seed ?? TEST_SEED));
  const appCompose = options.appCompose;
  return JSON.stringify({
    quote: { quote: "00", event_log: "00", report_data: `${pubkey}${nonceHex}`, vm_config: "" },
    pubkey: `0x${pubkey}`,
    composeHash:
      appCompose === undefined
        ? "deadbeef"
        : bytesToHex(sha256(new TextEncoder().encode(appCompose))),
    ...(appCompose === undefined ? {} : { app_compose: appCompose }),
  });
}

// 200 answer echoing the `nonce` query parameter of url.
export function attestationAnswer(url: string, options: AttestationOptions = {}): Response {
  const nonceHex = new URL(url).searchParams.get("nonce") ?? "";
  return new Response(attestationBody(nonceHex, options), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

export interface AttestationStub {
  readonly fetch: typeof fetch;
  readonly urls: string[];
  seed: Uint8Array;
  failNext: number | undefined;
}

// fetch answering only `/attestation`; failNext answers once with that status.
export function attestationStub(options: { requireNodeId?: boolean } = {}): AttestationStub {
  const urls: string[] = [];
  const stub: AttestationStub = {
    fetch: (async (input: string | URL | Request) => {
      const url = input instanceof Request ? input.url : String(input);
      if (!url.includes("/attestation")) throw new Error(`unexpected fetch: ${url}`);
      urls.push(url);
      const status = stub.failNext;
      if (status !== undefined) {
        stub.failNext = undefined;
        return new Response("internal error", {
          status,
          headers: { "content-type": "text/plain" },
        });
      }
      if (options.requireNodeId === true && !url.includes("node_id=")) {
        return new Response("not found", { status: 404 });
      }
      return attestationAnswer(url, { seed: stub.seed });
    }) as typeof fetch,
    urls,
    seed: TEST_SEED,
    failNext: undefined,
  };
  return stub;
}
