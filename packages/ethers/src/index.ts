// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// @w3tech.io/vrpc-ethers — ethers v6 verifiable adapter.
//
// `VrpcProvider` is a `JsonRpcProvider` subclass whose `_send` override feeds
// raw request + raw (content-decoded) response bytes into vrpc-core's verify
// seam before any value reaches the caller. ethers is a peerDependency
// (consumer-supplied, single instance); ALL verification logic is reused from
// @w3tech.io/vrpc-core — never copied (no viem import here, manifest isolation).

// Re-export the shared vrpc-core error family so consumers `instanceof`-check
// without importing core directly. This is the SAME error type the viem adapter
// reuses — one error family across both adapters.
export {
  BadSignature,
  InvalidChainId,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "@w3tech.io/vrpc-core";
export type { VrpcOptions } from "./options";
export { VrpcProvider } from "./provider";
