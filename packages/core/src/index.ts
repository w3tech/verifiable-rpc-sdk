// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verifier    — VerifierClient class + options/response types
//   - ./verify      — transport-agnostic verifyResponse seam
//   - ./attestation — fetchAttestation helper + Attestation/GetQuoteResponse types
//   - ./compose     — computeComposeHash (dstack compose-hash helper)
//   - ./errors      — VerificationError abstract base + typed subclasses
//   - ./preimage    — canonical 80-byte pre-image builder (exported for
//                     advanced consumers and test infrastructure)

// Hardware-verifier surface re-exported from @ankr.com/dstack-verify so adapters
// and consumers can configure or override the (mandatory, always-on) verifier —
// e.g. point it at a self-hosted endpoint, a future local-DCAP verifier, or a
// test mock. The default is the Phala cloud verifier wired by buildVerifyPolicy.
export type { CloudVerifierConfig, HardwareVerifier } from "@ankr.com/dstack-verify";
export { createCloudVerifier, DEFAULT_PHALA_VERIFY_ENDPOINT } from "@ankr.com/dstack-verify";
export type { AnchorTrustOptions, AnchorTrustResult } from "./anchor";
export { anchorTrust } from "./anchor";
export type {
  Attestation,
  FetchAttestationOptions,
  GetQuoteResponse,
} from "./attestation";
export { fetchAttestation, verifyAttestationCorrelation } from "./attestation";
export { computeComposeHash } from "./compose";
export type { BadSignatureContext, StaleTimestampContext, VerificationErrorKind } from "./errors";
export {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  BadSignature,
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
export { buildPreImage } from "./preimage";
export type { TrustedVerifierOptions } from "./trusted-verifier";
export {
  DEFAULT_PUBKEY_CACHE_MAX,
  DEFAULT_PUBKEY_CACHE_TTL_MS,
  TrustedVerifier,
} from "./trusted-verifier";
export { parseChainId } from "./utils";
export type { VerifiedResponse, VerifierClientOptions } from "./verifier";
export { VerifierClient } from "./verifier";
export type { ResponseHeaders, VerifiedPair, VerifyResponseOptions } from "./verify";
export { isSignedVrpcResponse, verifyResponse } from "./verify";
export type { VrpcUrls } from "./vrpc-url";
export { deriveVrpcUrls } from "./vrpc-url";
