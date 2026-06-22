// TrustedVerifier (INTEG-01) — the single orchestration unit that combines
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
// fetch is `fetchAttestation`, and the pubkey correlation is
// `verifyAttestationCorrelation` (attestation.ts). `mapAttestationToBundle` and
// `buildVerifyPolicy` are pure mappers with no crypto.

import {
  type AttestationBundle,
  type PinnedAllowlist,
  type TcbPolicy,
  type VerifyPolicy,
  verifyDstackAttestation,
} from "@ankr.com/dstack-verify";
import { bytesToHex } from "@noble/hashes/utils.js";

import { type Attestation, fetchAttestation, verifyAttestationCorrelation } from "./attestation";
import type { VerifiedResponse } from "./verifier";
import { type ResponseHeaders, type VerifiedPair, verifyResponse } from "./verify";

/** Default pubkey-cache TTL: 1 hour in ms (FLOW-02 default). */
export const DEFAULT_PUBKEY_CACHE_TTL_MS = 3_600_000;

/**
 * Construction options for {@link TrustedVerifier}. The transport inputs
 * (`attestationUrl`/auth) target the attestation fetch; the policy inputs
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
  /** Full attestation endpoint URL, e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
  /** Auth key sent as `x-api-key` on the attestation fetch. */
  apiKey?: string;
  /** Extra request headers for the attestation fetch; `x-api-key` here wins. */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Verified-pubkey cache TTL in ms; default {@link DEFAULT_PUBKEY_CACHE_TTL_MS}. */
  pubkeyCacheTtlMs?: number;
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
  attestation: Attestation,
  pubkeyHex: string,
  nonce: Uint8Array,
): AttestationBundle {
  return {
    quote: {
      quote: attestation.quote.quote,
      event_log: attestation.quote.event_log,
      report_data: attestation.quote.report_data,
      vm_config: attestation.quote.vm_config,
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
      compose_hash: attestation.composeHash,
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

/**
 * The verify-and-trust seam (INTEG-01). Holds a long-lived pubkey cache (keyed by
 * `pubkeyHex` → expiry epoch-ms) across `verify()` calls. On a cache hit within
 * TTL it returns the verified pair before any attestation fetch (FLOW-04); on a
 * miss/expiry it lazily fetches + correlates + verifies the attestation, caching
 * the pubkey ONLY after a resolved attestation verify (FLOW-05).
 */
export class TrustedVerifier {
  private readonly pubkeyExpiryCache = new Map<string, number>(); // pubkeyHex -> expiry epoch-ms
  private readonly opts: TrustedVerifierOptions;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly nonceSource: () => Uint8Array;
  private readonly verifyAttestationImpl: (b: AttestationBundle, p: VerifyPolicy) => Promise<void>;
  private readonly chainId: bigint;
  private readonly replayWindowMs: number | undefined;
  private readonly attestationUrl: string;
  private readonly apiKey: string | undefined;
  private readonly headers: Record<string, string> | undefined;
  private readonly fetchImpl: typeof fetch | undefined;

  constructor(opts: TrustedVerifierOptions) {
    this.opts = opts;
    this.ttlMs = opts.pubkeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS;
    this.now = opts.now ?? (() => Date.now());
    this.nonceSource = opts.nonceSource ?? (() => crypto.getRandomValues(new Uint8Array(32)));
    this.verifyAttestationImpl = opts.verifyAttestation ?? verifyDstackAttestation;
    this.chainId = opts.chainId;
    this.replayWindowMs = opts.replayWindowMs;
    this.attestationUrl = opts.attestationUrl;
    this.apiKey = opts.apiKey;
    this.headers = opts.headers;
    this.fetchImpl = opts.fetch;
  }

  /** True when `pubkeyHex` is cached and the entry has not expired. */
  private isFresh(pubkeyHex: string): boolean {
    const expiry = this.pubkeyExpiryCache.get(pubkeyHex);
    return expiry !== undefined && this.now() < expiry;
  }

  /** Cache `pubkeyHex` with a fresh TTL window. Called ONLY on a resolved verify. */
  private cacheVerifiedPubkey(pubkeyHex: string): void {
    this.pubkeyExpiryCache.set(pubkeyHex, this.now() + this.ttlMs);
  }

  /**
   * Verify a (requestBytes, responseBytes, headers) triple and, on an
   * unknown/expired signing pubkey, lazily attest it. Fail-closed throughout.
   * Exact ordering (FLOW-03/04/05):
   *   1. `verifyResponse` (the single Ed25519 path) — throws propagate.
   *   2. cache hit & fresh → return before any fetch (FLOW-04).
   *   3. nodeId is OPTIONAL — included in the attestation fetch when present,
   *      omitted when absent (no pre-throw; the endpoint decides — fail-closed).
   *   4. one fresh nonce, reused below (no rebinding).
   *   5. fetch attestation via shark — throws propagate, cache untouched.
   *   6. correlate att.pubkey == response signer — throws on mismatch.
   *   7. map → bundle, build policy (same nonce).
   *   8. attestation verify — throw skips step 9 (FLOW-05). NO try/finally.
   *   9. cache the pubkey STRICTLY after the resolved verify; return.
   */
  async verify(
    requestBytes: Uint8Array,
    responseBytes: Uint8Array,
    headers: ResponseHeaders,
  ): Promise<VerifiedPair> {
    const pair = await verifyResponse(requestBytes, responseBytes, headers, {
      chainId: this.chainId,
      ...(this.replayWindowMs === undefined ? {} : { replayWindowMs: this.replayWindowMs }),
    });

    const pubkeyHex = pair.verification.pubkeyHex;
    if (this.isFresh(pubkeyHex)) {
      return pair;
    }

    const nonce = this.nonceSource();

    // nodeId is OPTIONAL: included when the response carried vRPC-NodeId, omitted
    // otherwise. Absent + behind shark → shark can't route → the fetch errors and
    // propagates (fail-closed); absent + direct node → the fetch works. No pre-throw.
    const att = await fetchAttestation({
      attestationUrl: this.attestationUrl,
      ...(pair.nodeId === undefined ? {} : { nodeId: pair.nodeId }),
      nonce,
      ...(this.apiKey === undefined ? {} : { apiKey: this.apiKey }),
      ...(this.headers === undefined ? {} : { headers: this.headers }),
      ...(this.fetchImpl === undefined ? {} : { fetch: this.fetchImpl }),
    });

    verifyAttestationCorrelation(att, { verification: { pubkeyHex } } as VerifiedResponse);

    const bundle = mapAttestationToBundle(att, pubkeyHex, nonce);
    const policy = buildVerifyPolicy(this.opts, pubkeyHex, nonce);

    await this.verifyAttestationImpl(bundle, policy);

    this.cacheVerifiedPubkey(pubkeyHex);
    return pair;
  }
}
