// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Open-mode session: chain id bootstrap and pin, one verifier, verify, response classes, decode.

import { InvalidChainId, InvalidOption } from "./errors";
import type { OuterResponse } from "./transport";
import { TrustedVerifier, type TrustedVerifierOptions } from "./trusted-verifier";
import { parseChainId, strictUtf8 } from "./utils";
import { isSignedVrpcResponse } from "./verify";

/** Options of {@link createOpenSession}. */
export type OpenSessionOptions<R extends OuterResponse> = Omit<
  TrustedVerifierOptions,
  "chainId"
> & {
  /** Pins the chain; without it the chain id comes from a verified `eth_chainId` answer. */
  chainId?: string | undefined;
  /** The library's own error for a non-2xx answer; `json` is its parsed body, set only for a verified answer. */
  httpError(response: R, payload: unknown, json?: unknown): unknown;
};

/** One open-mode connection: sends exactly the bytes it verifies and returns only verified answers. */
export interface OpenSession<R extends OuterResponse> {
  /** Posts `payload` as JSON, verifies the answer and returns its parsed body; a non-2xx answer throws `httpError`. */
  send(payload: unknown, post: (body: Uint8Array) => Promise<R>): Promise<unknown>;
  /** The pinned chain id, bootstrapped through `post` when nothing is pinned yet. */
  chainId(post: (body: Uint8Array) => Promise<R>): Promise<string>;
  /** Binds the session to `chainId`; throws `InvalidOption` when it is bound to another chain. */
  pin(chainId: string): void;
}

const encoder = new TextEncoder();
const ETH_CHAIN_ID = { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] };

/** Creates an {@link OpenSession}. */
export function createOpenSession<R extends OuterResponse>(
  options: OpenSessionOptions<R>,
): OpenSession<R> {
  const { chainId: configured, httpError, ...verifierOptions } = options;
  let pinned: string | undefined;
  let verifier: Promise<TrustedVerifier> | undefined;
  const make = (chainId: string) => new TrustedVerifier({ ...verifierOptions, chainId });
  const ok = (response: R) => response.status >= 200 && response.status < 300;

  const bootstrap = (post: (body: Uint8Array) => Promise<R>): Promise<TrustedVerifier> => {
    const flight = (async () => {
      const body = encoder.encode(JSON.stringify(ETH_CHAIN_ID));
      const response = await post(body);
      if (!ok(response)) throw httpError(response, ETH_CHAIN_ID);
      const chainId = parseChainId(response.body);
      const derived = make(chainId);
      await derived.verify(body, response.body, response.headers);
      if (pinned !== undefined && pinned !== chainId) {
        throw new InvalidChainId(chainId, "the session is bound to another chain");
      }
      pinned = chainId;
      return derived;
    })();
    // A failed bootstrap clears the memo only if `pin` did not replace it meanwhile.
    flight.catch(() => {
      if (verifier === flight) verifier = undefined;
    });
    return flight;
  };
  const current = (post: (body: Uint8Array) => Promise<R>) => (verifier ??= bootstrap(post));

  const session: OpenSession<R> = {
    pin(chainId) {
      if (pinned === undefined) {
        pinned = chainId;
        verifier = Promise.resolve(make(chainId));
      } else if (pinned !== chainId) {
        throw new InvalidOption("chainId", "this transport is bound to another chain");
      }
    },
    async send(payload, post) {
      // Bootstrap first, so a failed bootstrap never follows a request the node already ran.
      const verifier = await current(post);
      const body = encoder.encode(JSON.stringify(payload));
      const response = await post(body);
      if (!ok(response) && !isSignedVrpcResponse(response.headers)) {
        throw httpError(response, payload);
      }
      await verifier.verify(body, response.body, response.headers);
      let json: unknown;
      try {
        json = JSON.parse(strictUtf8.decode(response.body));
      } catch (err) {
        if (ok(response)) throw err;
      }
      if (!ok(response)) throw httpError(response, payload, json);
      return json;
    },
    async chainId(post) {
      await current(post);
      return pinned as string;
    },
  };
  if (configured !== undefined) session.pin(configured);
  return session;
}
