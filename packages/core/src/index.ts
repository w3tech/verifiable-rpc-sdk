// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verify      — transport-agnostic verifyResponse seam
//   - ./attestation — fetchAttestation helper + Attestation/GetQuoteResponse types
//   - ./errors      — VerificationError abstract base + typed subclasses
//   - ./preimage    — canonical 104-byte pre-image builder (exported for
//                     advanced consumers and test infrastructure)

// Hardware-verifier surface re-exported from @w3tech.io/dstack-verify so adapters
// and consumers can configure or override the (mandatory, always-on) verifier —
// e.g. point it at a self-hosted endpoint, a future local-DCAP verifier, or a
// test mock. The default is the Phala cloud verifier.
export type { CloudVerifierConfig, HardwareVerifier } from "@w3tech.io/dstack-verify";
export { createCloudVerifier, DEFAULT_PHALA_VERIFY_ENDPOINT } from "@w3tech.io/dstack-verify";
export type {
  Attestation,
  FetchAttestationOptions,
  GetQuoteResponse,
} from "./attestation";
export { fetchAttestation } from "./attestation";
export type { InnerRequest, InnerResponse } from "./bhttp";
export type {
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialResponse,
} from "./confidential-client";
export * from "./errors";
export { LazyConfidentialClient } from "./lazy-confidential";
export { byteLen, pickVrpcHeaders } from "./log-redact";
export type { Logger } from "./logger";
export { createConsoleLogger, defaultLogger } from "./logger";
export type { OpenSession, OpenSessionOptions, PostResponse } from "./open-session";
export { createOpenSession } from "./open-session";
export type { CheckedOptions, OptionsInput } from "./options";
export { checkOptions, DEFAULT_PUBKEY_CACHE_TTL_MS } from "./options";
export { buildPreImage, validateChainId } from "./preimage";
export { fetchTransport, readCappedBody } from "./transport";
export type { TrustedVerifierOptions } from "./trusted-verifier";
export { TrustedVerifier } from "./trusted-verifier";
export { parseChainId } from "./utils";
export type { ResponseHeaders, VerifiedPair, VerifyResponseOptions } from "./verify";
export { DEFAULT_REPLAY_WINDOW_MS, isSignedVrpcResponse, verifyResponse } from "./verify";
export type { VrpcUrls } from "./vrpc-url";
export { deriveVrpcUrls } from "./vrpc-url";
