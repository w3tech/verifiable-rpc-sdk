// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Attest one node and hold the pinned result for the Ankr Confidential RPC client.

import { hexToBytes } from "@noble/hashes/utils.js";
import {
  AttestationError,
  type HardwareVerifier,
  verifyDstackAttestation,
} from "@w3tech.io/dstack-verify";

import { raceAbort } from "./abort";
import { fetchAttestationWithNodeId } from "./attestation";
import { AttestationFailed, AttestationUnavailable, MalformedAttestationResponse } from "./errors";
import { defaultLogger, type Logger } from "./logger";
import { InvalidNodeKey, nodeKeyFromEd25519 } from "./node-key";
import type { ConfidentialTransport } from "./transport";
import { buildVerifyPolicy, mapAttestationToBundle } from "./trusted-verifier";

export interface AttestedNode {
  readonly nodeId: string;
  readonly pubkeyHex: string;
  readonly nodeKey: Uint8Array;
  readonly composeHash: string;
  readonly attestedAt: number;
}

const ATTESTED_PUBKEY_RE = /^0x[0-9a-fA-F]{64}$/;

function attestedNodeKey(pubkeyHex: string): Uint8Array {
  try {
    return nodeKeyFromEd25519(hexToBytes(pubkeyHex.slice(2)));
  } catch (err) {
    if (err instanceof InvalidNodeKey) {
      throw new MalformedAttestationResponse("attested pubkey is not a usable encryption key");
    }
    throw err;
  }
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

interface AttestOptions {
  transport: ConfidentialTransport;
  attestationUrl: string;
  headers: Record<string, string>;
  hardwareVerifier: HardwareVerifier;
  logger: Logger;
  signal?: AbortSignal;
}

export async function attestNode(opts: AttestOptions): Promise<AttestedNode> {
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
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const { attestation, nodeId } = await fetchAttestationWithNodeId(opts.transport, {
    attestationUrl: opts.attestationUrl,
    nonce,
    headers: opts.headers,
    ...(opts.signal === undefined ? {} : { signal: opts.signal }),
  });
  if (!ATTESTED_PUBKEY_RE.test(attestation.pubkey)) {
    throw new MalformedAttestationResponse("pubkey must be 0x + 64 hex chars");
  }
  const pubkeyHex = attestation.pubkey.toLowerCase();
  const nodeKey = attestedNodeKey(pubkeyHex);
  try {
    await verifyDstackAttestation(
      mapAttestationToBundle(attestation, pubkeyHex, nonce),
      buildVerifyPolicy(pubkeyHex, nonce, opts.hardwareVerifier, opts.logger),
    );
  } catch (err) {
    if (err instanceof AttestationError) {
      throw new AttestationFailed(err.chkId, err.detail, { cause: err });
    }
    throw err;
  }
  return {
    nodeId,
    pubkeyHex,
    nodeKey,
    composeHash: attestation.composeHash,
    attestedAt: Date.now(),
  };
}

// Above the gateway's attestation timeout plus the hardware verifier's.
const ATTESTATION_TIMEOUT_MS = 60_000;

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
