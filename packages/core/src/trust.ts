// Verify-and-trust seam (INTEG-01) — the single orchestration unit that combines
// the existing Ed25519 verify path (`verifyResponse`) with a TTL pubkey cache and
// lazy TDX attestation: on an unknown/expired signing pubkey it fetches the node
// attestation through shark, maps it to the frozen `AttestationBundle`, builds a
// `VerifyPolicy` from client options, and calls `verifyDstackAttestation`
// (Phase 33). Fail-closed: a verified pubkey is cached with a TTL ONLY after a
// resolved attestation verify; a thrown `AttestationError` propagates and the
// pubkey is NOT cached (FLOW-05).
//
// This module composes existing primitives — it implements NO crypto: the single
// Ed25519 path is `verifyResponse` (verify.ts, never forked), the attestation
// fetch is `fetchAttestationViaShark`, and the pubkey correlation is
// `verifyAttestationCorrelation` (attestation.ts). `mapAttestationToBundle` and
// `buildVerifyPolicy` are pure mappers with no crypto.

import { bytesToHex } from "@noble/hashes/utils.js";

import type { AttestationBundle, PinnedAllowlist, TcbPolicy, VerifyPolicy } from "@ankr.com/dstack-verify";

import { type Attestation } from "./attestation";

/** Default pubkey-cache TTL: 1 hour in ms (FLOW-02 default). */
export const DEFAULT_PUBKEY_CACHE_TTL_MS = 3_600_000;

/**
 * Construction options for {@link TrustedVerifier}. The transport inputs
 * (`sharkBase`/`chain`/auth) target the attestation fetch; the policy inputs
 * (`allowlist`/`tcb`/`pccsUrl`) build the `VerifyPolicy`; the test injectables
 * (`now`/`nonceSource`/`verifyAttestation`) keep TTL + fail-closed tests
 * deterministic and offline.
 */
export interface TrustedVerifierOptions {
  /**
   * EVM-style chain id bound into the canonical pre-image (8 bytes LE). MUST
   * match the chain id the sidecar was configured with — mismatch produces a
   * `BadSignature` even on intact responses.
   */
  chainId: bigint;
  /** Allowed skew between client clock and signed timestamp; default 60_000 ms. */
  replayWindowMs?: number;
  /** Shark proxy base URL (no trailing slash), e.g. `https://rpc.ankr.com`. */
  sharkBase: string;
  /** Chain slug used to build the `<chain>_vrpc` attestation route, e.g. `eth`. */
  chain: string;
  /** Auth key sent as `x-api-key` on the attestation fetch. */
  apiKey?: string;
  /** Extra request headers for the attestation fetch; `x-api-key` here wins. */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Verified-pubkey cache TTL in ms; default {@link DEFAULT_PUBKEY_CACHE_TTL_MS}. */
  pubkeyCacheTtl?: number;
  /** Pinned trust anchors (INTEG-02). Required — built into every `VerifyPolicy`. */
  allowlist: PinnedAllowlist;
  /** DCAP TCB acceptance; default `{ allowedStatuses: [], rejectDebug: true }`. */
  tcb?: TcbPolicy;
  /** Operational collateral source for dcap-qvl (NOT a trust dependency). */
  pccsUrl?: string;
  /** Injected wall clock (epoch ms); default `() => Date.now()`. Test-only. */
  now?: () => number;
  /** Fresh 32-byte nonce source; default `crypto.getRandomValues`. Test-only. */
  nonceSource?: () => Uint8Array;
  /** Attestation verifier; default `verifyDstackAttestation`. Test-only stub. */
  verifyAttestation?: (b: AttestationBundle, p: VerifyPolicy) => Promise<void>;
}

/**
 * Map a fetched {@link Attestation} (shark `/attestation` wire shape) to the
 * frozen {@link AttestationBundle}. The `quote.*` fields and `pubkey` pass
 * through directly; `nonce` is the SDK-generated fetch nonce (bare hex, not from
 * the attestation body). `tcbInfo` and `signature_chain` are mock-tolerated
 * stubs in v5.0 — the v5.0 mock verifier does not inspect `bundle`. Each stub
 * carries a `// GAP v5.0` anchor recording where v6.0 must source the real data.
 */
export function mapAttestationToBundle(
  att: Attestation,
  pubkeyHex: string,
  nonce: Uint8Array,
): AttestationBundle {
  return {
    quote: {
      quote: att.quote.quote,
      event_log: att.quote.event_log,
      report_data: att.quote.report_data,
      vm_config: att.quote.vm_config,
    },
    pubkey: pubkeyHex,
    nonce: bytesToHex(nonce),
    // GAP v5.0 / fills in v6.0: structural tcbInfo from GET /info tcb_info — see
    // InfoEndpointComposeSource in compose.ts (narrowInfoAppCompose) for the
    // narrower; the current /attestation route does not emit it. Mock does not
    // inspect bundle, so a stub is valid until v6.0.
    tcbInfo: {
      mrtd: "",
      rtmr0: "",
      rtmr1: "",
      rtmr2: "",
      rtmr3: "",
      app_compose: "",
      event_log: [],
      // composeHash is available as a (recompute-only) hint, never a trust anchor.
      compose_hash: att.composeHash,
    },
    // GAP v5.0 / fills in v6.0: signature_chain from dstack get_key chain
    // ([link0_sig, k256_signature]) — 3b cross-repo ticket; not emitted by the
    // current /attestation route.
    signature_chain: [],
  };
}

/**
 * Build a {@link VerifyPolicy} from client options + the verified pubkey + the
 * SDK-generated nonce (INTEG-02). `binding` carries the reportData binding
 * (`report_data[0:32]==pubkey`, `[32:64]==nonce`); `allowlist` is the pinned
 * trust anchors; `allowInsecureMock` is HARD-SET `true` in v5.0 (v6.0 flips it
 * off with zero changes outside dstack-verify).
 */
export function buildVerifyPolicy(
  opts: TrustedVerifierOptions,
  pubkeyHex: string,
  nonce: Uint8Array,
): VerifyPolicy {
  return {
    binding: {
      expectedPubkey: pubkeyHex,
      expectedNonce: bytesToHex(nonce),
    },
    allowlist: opts.allowlist,
    tcb: opts.tcb ?? { allowedStatuses: [], rejectDebug: true },
    ...(opts.pccsUrl === undefined ? {} : { pccsUrl: opts.pccsUrl }),
    allowInsecureMock: true,
  };
}
