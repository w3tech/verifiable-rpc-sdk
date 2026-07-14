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
// test mock. The default is the Phala cloud verifier wired by buildVerifyPolicy.
export type { CloudVerifierConfig, HardwareVerifier } from "@w3tech.io/dstack-verify";
export { createCloudVerifier, DEFAULT_PHALA_VERIFY_ENDPOINT } from "@w3tech.io/dstack-verify";
export type {
  Attestation,
  FetchAttestationOptions,
  GetQuoteResponse,
} from "./attestation";
export { fetchAttestation, verifyAttestationCorrelation } from "./attestation";
export type { BadSignatureContext, StaleTimestampContext, VerificationErrorKind } from "./errors";
export {
  AttestationCorrelationError,
  AttestationFailed,
  AttestationNodeNotFoundError,
  BadSignature,
  InvalidChainId,
  InvalidNonce,
  MalformedAttestationResponse,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "./errors";
export { byteLen, pickVrpcHeaders, truncateHex } from "./log-redact";
export type { Logger } from "./logger";
export { createConsoleLogger, defaultLogger, safeLogger } from "./logger";
export { buildPreImage, validateChainId } from "./preimage";
export type { TrustedVerifierOptions } from "./trusted-verifier";
export {
  DEFAULT_PUBKEY_CACHE_MAX,
  DEFAULT_PUBKEY_CACHE_TTL_MS,
  TrustedVerifier,
} from "./trusted-verifier";
export { parseChainId } from "./utils";
export type { ResponseHeaders, VerifiedPair, VerifyResponseOptions } from "./verify";
export { isSignedVrpcResponse, verifyResponse } from "./verify";
export type { VrpcUrls } from "./vrpc-url";
export { deriveVrpcUrls } from "./vrpc-url";
