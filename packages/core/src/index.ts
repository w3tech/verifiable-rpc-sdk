// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verifier    — VerifierClient class + options/response types
//   - ./verify      — transport-agnostic verifyResponse seam (CORE-02)
//   - ./attestation — fetchAttestation helper + Attestation/GetQuoteResponse types
//   - ./compose     — ComposeSource interface + InfoEndpoint (dev) / Registry
//                     (future) implementations + computeComposeHash
//   - ./errors      — VerificationError abstract base + typed subclasses
//   - ./preimage    — canonical 80-byte pre-image builder (exported for
//                     advanced consumers and test infrastructure)

export type { AnchorTrustOptions, AnchorTrustResult } from "./anchor";
export { anchorTrust } from "./anchor";
export type {
  Attestation,
  FetchAttestationOptions,
  GetQuoteResponse,
} from "./attestation";
export { fetchAttestation, verifyAttestationCorrelation } from "./attestation";
export type {
  ComposeSource,
  InfoEndpointComposeSourceOptions,
  RegistryComposeSourceOptions,
} from "./compose";
export { computeComposeHash, InfoEndpointComposeSource, RegistryComposeSource } from "./compose";
export type { BadSignatureContext, StaleTimestampContext, VerificationErrorKind } from "./errors";
export {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  BadSignature,
  ComposeSourceNotImplemented,
  InvalidNonce,
  MalformedAttestationResponse,
  MalformedHeader,
  MalformedInfoResponse,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "./errors";
export { buildPreImage } from "./preimage";
export type { TrustedVerifierOptions } from "./trusted-verifier";
export { DEFAULT_PUBKEY_CACHE_TTL_MS, TrustedVerifier } from "./trusted-verifier";
export type { VerifiedResponse, VerifierClientOptions } from "./verifier";
export { VerifierClient } from "./verifier";
export type { ResponseHeaders, VerifiedPair, VerifyResponseOptions } from "./verify";
export { verifyResponse } from "./verify";
export type { VrpcUrls } from "./vrpc-url";
export { deriveVrpcUrls } from "./vrpc-url";
