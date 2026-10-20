// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Test node signing key material.

export { bytesToHex as toHex } from "@noble/hashes/utils.js";

// Ed25519 seed of the test node key.
export const TEST_SEED = new Uint8Array(32).fill(0x42);
