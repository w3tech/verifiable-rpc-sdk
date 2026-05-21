// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verifier    — VerifierClient class + options/response types
//   - ./attestation — fetchAttestation helper + Attestation/GetQuoteResponse types
//   - ./errors      — VerificationError abstract base + 6 typed subclasses
//   - ./preimage    — canonical 80-byte pre-image builder (exported for
//                     advanced consumers and test infrastructure)

export type { Attestation, GetQuoteResponse } from "./attestation";
export { fetchAttestation } from "./attestation";
export type { BadSignatureContext, StaleTimestampContext, VerificationErrorKind } from "./errors";
export {
  BadSignature,
  InvalidNonce,
  MalformedAttestationResponse,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "./errors";
export { buildPreImage } from "./preimage";
export type { VerifiedResponse, VerifierClientOptions } from "./verifier";
export { VerifierClient } from "./verifier";
