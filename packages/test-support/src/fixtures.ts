// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Node identity, chain and key shared by the suites, and the inner request they send.

import { hexToBytes } from "@noble/hashes/utils.js";

// Ed25519 seed of the node in the confidential vectors.
export const NODE_SEED = hexToBytes(
  "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee",
);
export const NODE_ID = "alpha-vrpc-1";
// Arbitrum, as the decimal string the sidecar hashes into the pre-image.
export const CHAIN_ID = "42161";
// Fake key literal, never a real key.
export const KEY = "0123456789abcdefghijABCDEFGHIJkl";

const utf8 = new TextEncoder();

// Inner `eth_blockNumber` request.
export function jsonRpcCall() {
  return {
    method: "POST",
    path: "/",
    contentType: "application/json",
    accept: "application/json",
    body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
  };
}
