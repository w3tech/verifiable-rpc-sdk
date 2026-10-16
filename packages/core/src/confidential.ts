// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client entry: the client, its transport seam types and the errors it throws.

export type { InnerRequest } from "./bhttp";
export type {
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialResponse,
} from "./confidential-client";
export { ConfidentialClient } from "./confidential-client";
export type {
  AttestationUnavailableReason,
  InvalidInnerRequestReason,
  MalformedConfidentialResponseReason,
  TransportFailedReason,
  UnavailableErrorKind,
  VerificationErrorKind,
} from "./errors";
export {
  AttestationFailed,
  AttestationUnavailable,
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSealFailed,
  ConfidentialSignerMismatch,
  InvalidChainId,
  InvalidInnerRequest,
  MalformedAttestationResponse,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnavailableError,
  UnexpectedResponse,
  VerificationError,
} from "./errors";
export type { ConfidentialTransport, OuterRequest, OuterResponse } from "./transport";
