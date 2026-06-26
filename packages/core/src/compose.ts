// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// computeComposeHash — the dstack compose-hash of an `app_compose` string.
//
// compose_hash is ALWAYS `sha256(utf8(app_compose))` as bare lowercase hex,
// matching dstack's rule exactly — the raw file bytes are hashed verbatim, with
// no canonicalization / re-serialization. Used by the SDK's CHK-A2 check to
// confirm a node's self-reported `app_compose` (served verbatim in the
// `/attestation` body) is internally consistent with its `compose_hash`.

import { bytesToHex } from "@noble/hashes/utils.js";

import { sha256 } from "./preimage";

/**
 * Compute the dstack compose-hash of an `app_compose` string:
 * `sha256(utf8(appCompose))` as bare lowercase hex. No canonicalization —
 * dstack hashes the raw file bytes verbatim.
 */
export function computeComposeHash(appCompose: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(appCompose)));
}
