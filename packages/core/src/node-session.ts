// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Attest one node and hold the pinned result for the Ankr Confidential RPC client.

import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";

import { raceAbort } from "./abort";
import { ATTESTATION_TIMEOUT_MS, type AttestNodeOptions, attestNode } from "./attestation";
import { AttestationUnavailable, MalformedAttestationResponse } from "./errors";
import { defaultLogger } from "./logger";

export interface AttestedNode {
  readonly nodeId: string;
  readonly pubkeyHex: string;
  readonly nodeKey: Uint8Array;
  readonly composeHash: string;
  readonly attestedAt: number;
}

export function nodeKeyFromEd25519(ed25519PublicKey: Uint8Array): Uint8Array {
  try {
    const point = ed25519.Point.fromBytes(ed25519PublicKey);
    if (!point.isSmallOrder() && point.isTorsionFree()) {
      return ed25519.utils.toMontgomery(ed25519PublicKey);
    }
  } catch {
    // a malformed point or a failed conversion is rejected below
  }
  throw new MalformedAttestationResponse("attested pubkey is not a usable encryption key");
}

export type Pin = AttestedNode & { readonly expiresAt: number };

/** A log-safe name for a failure: the error's `kind`, else its `name`. */
export function errorKind(err: unknown): string {
  if (typeof err === "object" && err !== null) {
    const { kind, name } = err as { kind?: unknown; name?: unknown };
    if (typeof kind === "string") return kind;
    if (typeof name === "string") return name;
  }
  return typeof err;
}

type AttestOptions = Omit<AttestNodeOptions, "expectPubkey" | "nodeId">;

export async function attestPin(opts: AttestOptions): Promise<AttestedNode> {
  const { logger } = opts;
  if (logger === defaultLogger) return attest(opts);
  const started = Date.now();
  logger.debug("confidential.attest.start");
  try {
    const node = await attest(opts);
    logger.debug("confidential.attest.ok", {
      nodeId: node.nodeId,
      pubkey: node.pubkeyHex,
      composeHash: node.composeHash,
      durationMs: Date.now() - started,
    });
    return node;
  } catch (err) {
    logger.debug("confidential.attest.fail", {
      kind: errorKind(err),
      durationMs: Date.now() - started,
    });
    throw err;
  }
}

async function attest(opts: AttestOptions): Promise<AttestedNode> {
  const node = await attestNode(opts);
  return {
    nodeId: node.nodeId,
    pubkeyHex: node.pubkey,
    nodeKey: nodeKeyFromEd25519(hexToBytes(node.pubkey.slice(2))),
    composeHash: node.composeHash,
    attestedAt: node.attestedAt,
  };
}

export class PinSlot {
  readonly #attest: (signal?: AbortSignal) => Promise<AttestedNode>;
  readonly #ttlMs: number;
  #pin: Pin | undefined;
  #flight: Promise<Pin> | undefined;

  constructor(attest: (signal?: AbortSignal) => Promise<AttestedNode>, ttlMs: number) {
    this.#attest = attest;
    this.#ttlMs = ttlMs;
  }

  current(now = Date.now()): Pin | undefined {
    return this.#pin !== undefined && now < this.#pin.expiresAt ? this.#pin : undefined;
  }

  acquire(signal?: AbortSignal): Promise<Pin> {
    if (signal?.aborted) return Promise.reject(signal.reason);
    const pin = this.current();
    if (pin !== undefined) return Promise.resolve(pin);
    if (this.#flight === undefined) {
      const deadline = new AbortController();
      const timer = setTimeout(
        () => deadline.abort(new AttestationUnavailable("timeout")),
        ATTESTATION_TIMEOUT_MS,
      );
      // The verifier takes no signal, so the deadline also settles the flight itself.
      const flight: Promise<Pin> = raceAbort(this.#attest(deadline.signal), deadline.signal)
        .then(
          (node) => {
            const next: Pin = Object.freeze({ ...node, expiresAt: node.attestedAt + this.#ttlMs });
            this.#pin = next;
            this.#flight = undefined;
            return next;
          },
          (err: unknown) => {
            this.#flight = undefined;
            throw err;
          },
        )
        .finally(() => clearTimeout(timer));
      // Nobody may be waiting when the flight settles.
      flight.catch(() => {});
      this.#flight = flight;
    }
    // A waiter's abort never cancels the shared flight.
    return raceAbort(this.#flight, signal);
  }

  evict(pin: Pin): void {
    if (this.#pin === pin) this.#pin = undefined;
  }
}
