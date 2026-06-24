// Public barrel — re-exports the @ankr.com/dstack-verify public surface only.
//
// Implementation lives in:
//   - ./types     — AttestationBundle / VerifyPolicy + sub-types (frozen contract)
//   - ./errors    — AttestationError extends VerificationError
//   - ./checklist — ChkId union (CHK-A1..G3 + CHK-MOCK) + frozen CHK record
//   - ./verify-steps — frozen verify-step signatures (currently throwing stubs)
//   - ./verify    — verifyDstackAttestation entrypoint (current mock body; a future release fills it in place)
//
// verbatimModuleSyntax + isolatedModules require `export type { ... }` to be
// a separate statement from `export { ... }`.

export type { ChkDisposition, ChkEntry, ChkId } from "./checklist";
export { CHK } from "./checklist";
export type { AttestationErrorKind } from "./errors";
export { AttestationError } from "./errors";
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
export { EMPTY_ALLOWLIST } from "./types";
export { verifyDstackAttestation } from "./verify";
export { parseReportData } from "./verify-steps";
