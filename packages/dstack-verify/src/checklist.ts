// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.

/**
 * A dstack/TDX chain-of-trust checklist item (CHK-A1..G3, verbatim from Phala's
 * chain-of-trust.mdx); `AttestationError.chkId` names the one that failed.
 */
export type ChkId =
  /** reportData contains expected challenge/public key */
  | "CHK-A1"
  /** compose-hash matches calculated hash */
  | "CHK-A2"
  /** All Docker images use SHA256 digests (not tags) */
  | "CHK-A3"
  /** RTMR3 event log replays to quoted RTMR3 */
  | "CHK-A4"
  /** Image digests link to audited source code (Sigstore/reproducible) */
  | "CHK-A5"
  /** compose-hash whitelisted in DstackApp contract */
  | "CHK-A6"
  /** TDX quote signature valid (Intel root certs / hosted verifier verdict) */
  | "CHK-P1"
  /** tee_tcb_svn matches latest patches */
  | "CHK-P2"
  /** MRTD and RTMR0-2 match calculated OS measurements */
  | "CHK-P3"
  /** VM config (CPU/mem/GPU) matches deployment */
  | "CHK-P4"
  /** OS image hash whitelisted in DstackKms contract */
  | "CHK-P5"
  /** (Optional) OS rebuilt reproducibly */
  | "CHK-P6"
  /** KMS ID from key-provider event known and trusted */
  | "CHK-P7"
  /** KMS's own attestation quote valid */
  | "CHK-P8"
  /** KMS aggregated MR whitelisted in DstackKms contract */
  | "CHK-P9"
  /** TLS cert fingerprint matches served cert */
  | "CHK-N1"
  /** /evidences/ files cryptographically bind to quote */
  | "CHK-N2"
  /** CAA DNS records restrict cert issuance */
  | "CHK-N3"
  /** Smart-contract addresses verified and trusted */
  | "CHK-G1"
  /** Contract permissions match security policy */
  | "CHK-G2"
  /** Contract ownership/upgrade mechanisms understood */
  | "CHK-G3";
