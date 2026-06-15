// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verifier    — VerifierClient class + options/response types
//   - ./attestation — fetchAttestation helper + Attestation/GetQuoteResponse types
//   - ./compose     — ComposeSource interface + InfoEndpoint (dev) / Registry
//                     (future) implementations + computeComposeHash
//   - ./errors      — VerificationError abstract base + typed subclasses
//   - ./preimage    — canonical 80-byte pre-image builder (exported for
//                     advanced consumers and test infrastructure)

export type {
  Attestation,
  FetchAttestationViaSharkOptions,
  GetQuoteResponse,
} from "./attestation";
export {
  fetchAttestation,
  fetchAttestationViaShark,
  verifyAttestationCorrelation,
} from "./attestation";
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
export type { VerifiedResponse, VerifierClientOptions } from "./verifier";
export { VerifierClient } from "./verifier";
