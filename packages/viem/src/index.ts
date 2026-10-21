// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// @w3tech.io/vrpc-viem — viem verifiable adapter.
//
// `vrpcHttp` is a viem custom transport whose `request` hands raw request + raw
// (content-decoded) response bytes to vrpc-core's verify seam before any value
// reaches the client. viem is a peerDependency (consumer-supplied, single
// instance); ALL verification logic is reused from @w3tech.io/vrpc-core — never
// copied (no ethers import here, manifest isolation).

export type { ConfidentialInfo } from "@w3tech.io/vrpc-core/confidential";
// One error family from core: the same classes, so `instanceof` works across packages.
export * from "@w3tech.io/vrpc-core/errors";
export type { VrpcHttpOptions } from "./options";
export { vrpcHttp } from "./transport";
