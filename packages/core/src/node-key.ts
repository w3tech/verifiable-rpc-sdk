// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Derive the X25519 node encryption key from the attested Ed25519 public key.

import { ed25519 } from "@noble/curves/ed25519.js";

export type InvalidNodeKeyReason =
  | "malformed"
  | "small-order"
  | "not-torsion-free"
  | "encap-failed";

export class InvalidNodeKey extends Error {
  readonly kind = "InvalidNodeKey" as const;

  constructor(
    readonly reason: InvalidNodeKeyReason,
    options?: { cause?: unknown },
  ) {
    super(`Node encryption key rejected: ${reason}`, options);
    this.name = "InvalidNodeKey";
  }
}

export function nodeKeyFromEd25519(ed25519PublicKey: Uint8Array): Uint8Array {
  let point: ReturnType<typeof ed25519.Point.fromBytes>;
  try {
    point = ed25519.Point.fromBytes(ed25519PublicKey);
  } catch (cause) {
    throw new InvalidNodeKey("malformed", { cause });
  }
  if (point.isSmallOrder()) throw new InvalidNodeKey("small-order");
  if (!point.isTorsionFree()) throw new InvalidNodeKey("not-torsion-free");
  try {
    return ed25519.utils.toMontgomery(ed25519PublicKey);
  } catch (cause) {
    throw new InvalidNodeKey("malformed", { cause });
  }
}
