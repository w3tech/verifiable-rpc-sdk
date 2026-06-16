// Public barrel — re-exports the @ankr.com/dstack-verify public surface only.
//
// Implementation lives in:
//   - ./types     — AttestationBundle / VerifyPolicy + sub-types (frozen contract)
//   - ./errors    — AttestationError extends VerificationError
//   - ./checklist — ChkId union (CHK-A1..G3 + CHK-MOCK) + frozen CHK record
//   - ./helpers   — v6.0 helper signatures (v5.0 throwing stubs)
//   - ./mock      — verifyDstackAttestation mock body (added in Plan 02)
//
// verbatimModuleSyntax + isolatedModules require `export type { ... }` to be
// a separate statement from `export { ... }`.

export type { ChkDisposition, ChkEntry, ChkId } from "./checklist";
export { CHK } from "./checklist";
export type { AttestationErrorKind } from "./errors";
export { AttestationError } from "./errors";
export { computeComposeHash, extractKeyProvider, parseReportData, replayRtmr } from "./helpers";
export { verifyDstackAttestation } from "./mock";
export type {
  AttestationBundle,
  EventLogEntry,
  KeyProvider,
  PinnedAllowlist,
  QuoteEnvelope,
  ReportDataBinding,
  TcbInfo,
  TcbPolicy,
  VerifyPolicy,
} from "./types";
