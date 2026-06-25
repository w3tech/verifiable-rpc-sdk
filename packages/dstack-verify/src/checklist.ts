// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Frozen audit vocabulary for the dstack/TDX chain-of-trust verification.
//
// `ChkId` enumerates the complete CHK-A1..G3 checklist (verbatim from
// phala chain-of-trust.mdx) plus the synthetic `CHK-MOCK` id used by the
// current release's fail-closed mock-deny path. The `CHK` const record carries
// each item's verbatim meaning and its target disposition so the checklist is
// queryable from code and tests. A future release fills the verification bodies
// WITHOUT changing this set.

/** Frozen string-literal union of every chain-of-trust checklist identifier. */
export type ChkId =
  | "CHK-A1"
  | "CHK-A2"
  | "CHK-A3"
  | "CHK-A4"
  | "CHK-A5"
  | "CHK-A6"
  | "CHK-P1"
  | "CHK-P2"
  | "CHK-P3"
  | "CHK-P4"
  | "CHK-P5"
  | "CHK-P6"
  | "CHK-P7"
  | "CHK-P8"
  | "CHK-P9"
  | "CHK-N1"
  | "CHK-N2"
  | "CHK-N3"
  | "CHK-G1"
  | "CHK-G2"
  | "CHK-G3"
  | "CHK-MOCK"; // synthetic id for the current release's mock-deny path

/** Target disposition for each checklist item. */
export type ChkDisposition = "implement" | "mock" | "pinned" | "out" | "mock-deny";

/** One checklist entry: its verbatim meaning + the target implementation disposition. */
export interface ChkEntry {
  meaning: string;
  disposition: ChkDisposition;
}

/**
 * Frozen const record mapping every `ChkId` to its verbatim meaning + target
 * disposition. Frozen so the audit dictionary is immutable and queryable from
 * code and tests.
 */
export const CHK = Object.freeze({
  "CHK-A1": {
    meaning: "reportData contains expected challenge/public key",
    disposition: "implement",
  },
  "CHK-A2": { meaning: "compose-hash matches calculated hash", disposition: "implement" },
  "CHK-A3": {
    meaning: "All Docker images use SHA256 digests (not tags)",
    disposition: "implement",
  },
  "CHK-A4": { meaning: "RTMR3 event log replays to quoted RTMR3", disposition: "implement" },
  "CHK-A5": {
    meaning: "Image digests link to audited source code (Sigstore/reproducible)",
    disposition: "mock",
  },
  "CHK-A6": {
    meaning: "compose-hash whitelisted in DstackApp contract",
    disposition: "pinned",
  },
  // CHK-P1 is the hardware-signature verdict. It is now reachable via a
  // configured HardwareVerifier (see ./hardware-verifier): the CloudVerifier
  // path asserts the cloud verdict AND binds the cloud-extracted reportdata /
  // composeHash to our values (B+). A future LocalDcapVerifier verifies the
  // quote locally against Intel root certs under this same id. No new ChkId.
  "CHK-P1": {
    meaning: "TDX quote signature valid (Intel root certs / hosted verifier verdict)",
    disposition: "implement",
  },
  "CHK-P2": { meaning: "tee_tcb_svn matches latest patches", disposition: "implement" },
  "CHK-P3": {
    meaning: "MRTD and RTMR0-2 match calculated OS measurements",
    disposition: "implement",
  },
  "CHK-P4": {
    meaning: "VM config (CPU/mem/GPU) matches deployment",
    disposition: "implement",
  },
  "CHK-P5": {
    meaning: "OS image hash whitelisted in DstackKms contract",
    disposition: "pinned",
  },
  "CHK-P6": { meaning: "(Optional) OS rebuilt reproducibly", disposition: "out" },
  "CHK-P7": {
    meaning: "KMS ID from key-provider event known and trusted",
    disposition: "implement",
  },
  "CHK-P8": { meaning: "KMS's own attestation quote valid", disposition: "mock" },
  "CHK-P9": {
    meaning: "KMS aggregated MR whitelisted in DstackKms contract",
    disposition: "pinned",
  },
  "CHK-N1": {
    meaning: "TLS cert fingerprint matches served cert",
    disposition: "out",
  },
  "CHK-N2": {
    meaning: "/evidences/ files cryptographically bind to quote",
    disposition: "out",
  },
  "CHK-N3": { meaning: "CAA DNS records restrict cert issuance", disposition: "out" },
  "CHK-G1": {
    meaning: "Smart-contract addresses verified and trusted",
    disposition: "pinned",
  },
  "CHK-G2": { meaning: "Contract permissions match security policy", disposition: "pinned" },
  "CHK-G3": {
    meaning: "Contract ownership/upgrade mechanisms understood",
    disposition: "pinned",
  },
  "CHK-MOCK": {
    meaning: "current mock: real attestation verification not implemented; default-deny",
    disposition: "mock-deny",
  },
} as const satisfies Record<ChkId, ChkEntry>);
