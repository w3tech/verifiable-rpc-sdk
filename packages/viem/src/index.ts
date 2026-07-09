// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// @w3tech.io/vrpc-viem — viem verifiable adapter.
//
// `vrpcHttp` is a viem custom transport whose `request` hands raw request + raw
// (content-decoded) response bytes to vrpc-core's verify seam before any value
// reaches the client. viem is a peerDependency (consumer-supplied, single
// instance); ALL verification logic is reused from @w3tech.io/vrpc-core — never
// copied (no ethers import here, manifest isolation).

// (v6.0: the `PinnedAllowlist`/`TcbPolicy` re-export was dropped along with the
// inert `allowlist`/`tcb` options. v7.0 reintroduces both. The types remain
// importable from `@w3tech.io/dstack-verify` directly.)
// Re-export the shared vrpc-core error family — the EXACT SAME set the ethers
// adapter re-exports — so a caller cannot tell the two adapters apart by error
// shape. `instanceof`-checks work without importing core directly.
export {
  BadSignature,
  InvalidChainId,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "@w3tech.io/vrpc-core";
export type { VrpcHttpOptions } from "./options";
export { vrpcHttp } from "./transport";
