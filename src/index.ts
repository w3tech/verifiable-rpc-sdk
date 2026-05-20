// Public barrel — re-exports the SDK's public surface.
//
// Implementation lives in:
//   - ./verifier  — VerifierClient class + options/response types + (Phase-20)
//                   Attestation type stubs
//   - ./errors    — VerificationError abstract base + 4 typed subclasses
//   - ./preimage  — SPEC-04 80-byte pre-image builder (exported for advanced
//                   consumers and test infrastructure)

export type { BadSignatureContext, StaleTimestampContext, VerificationErrorKind } from "./errors";
export {
  BadSignature,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "./errors";
export { buildPreImage } from "./preimage";
export type {
  Attestation,
  GetQuoteResponse,
  VerifiedResponse,
  VerifierClientOptions,
} from "./verifier";
export { VerifierClient } from "./verifier";
