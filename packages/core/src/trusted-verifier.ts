// TrustedVerifier — the single orchestration unit that combines
// the existing Ed25519 verify path (`verifyResponse`) with a TTL pubkey cache and
// lazy TDX attestation: on an unknown/expired signing pubkey it fetches the node
// attestation through shark, maps it to the frozen `AttestationBundle`, builds a
// `VerifyPolicy` from client options, and calls `verifyDstackAttestation`.
// Fail-closed: a verified pubkey is cached with a TTL ONLY after a
// resolved attestation verify; a thrown `AttestationError` propagates and the
// pubkey is NOT cached.
//
// This module composes existing primitives — it implements NO crypto: the single
// Ed25519 path is `verifyResponse` (verify.ts, never forked), the attestation
// fetch is `fetchAttestation`, and the pubkey correlation is
// `verifyAttestationCorrelation` (attestation.ts). `mapAttestationToBundle` and
// `buildVerifyPolicy` are pure mappers with no crypto.

import {
  type AttestationBundle,
  EMPTY_ALLOWLIST,
  type VerifyPolicy,
  verifyDstackAttestation,
} from "@ankr.com/dstack-verify";
import { bytesToHex } from "@noble/hashes/utils.js";
import { LRUCache } from "lru-cache";

import { type Attestation, fetchAttestation, verifyAttestationCorrelation } from "./attestation";
import { InfoEndpointComposeSource } from "./compose";
import type { VerifiedResponse } from "./verifier";
import { type ResponseHeaders, type VerifiedPair, verifyResponse } from "./verify";

/** Default pubkey-cache TTL: 1 hour in ms. */
export const DEFAULT_PUBKEY_CACHE_TTL_MS = 3_600_000;

/** Default max distinct verified pubkeys held in the cache before LRU eviction. */
export const DEFAULT_PUBKEY_CACHE_MAX = 1024;

/**
 * Construction options for {@link TrustedVerifier}. The transport inputs
 * (`attestationUrl`/`headers`) target the attestation fetch; the test injectables
 * (`nonceSource`/`verifyAttestation`) keep fail-closed tests deterministic and
 * offline. (The policy inputs `allowlist`/`tcb`/`pccsUrl` were removed — the mock
 * verifier ignores them; a future release reintroduces them.)
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
  /** Extra request headers for the attestation fetch (e.g. `x-api-key`). */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Verified-pubkey cache TTL in ms; default {@link DEFAULT_PUBKEY_CACHE_TTL_MS}. */
  pubkeyCacheTtlMs?: number;
  /** Max distinct verified pubkeys cached before LRU eviction; default {@link DEFAULT_PUBKEY_CACHE_MAX}. */
  pubkeyCacheMax?: number;
  // NOTE: the policy inputs `allowlist`/`tcb`/`pccsUrl` were removed — the
  // mock verifier ignores them, so exposing them on the published surface is
  // misleading. A future release re-introduces them (consumer-pinned anchors) when
  // the real verifier needs them; re-adding optional fields is non-breaking.
  /** Fresh 32-byte nonce source; default `crypto.getRandomValues`. Test-only. */
  nonceSource?: () => Uint8Array;
  /** Attestation verifier; default `verifyDstackAttestation`. Test-only stub. */
  verifyAttestation?: (b: AttestationBundle, p: VerifyPolicy) => Promise<void>;
}

/**
 * Map a fetched {@link Attestation} (shark `/attestation` wire shape) to the
 * frozen {@link AttestationBundle}. The `quote.*` fields and `pubkey` pass
 * through directly; `nonce` is the SDK-generated fetch nonce (bare hex, not from
 * the attestation body). The remaining `tcbInfo` measurement fields and
 * `signature_chain` are still mock-tolerated stubs — the mock verifier does not
 * inspect them; each records where a future release must source the real data.
 *
 * `tcbInfo.app_compose` is now populated from the node's `GET /info`
 * (`tcb_info.app_compose`, via {@link InfoEndpointComposeSource}). `appCompose`
 * is OPTIONAL and defaults to `""` — when the caller could not fetch `/info`
 * (older nodes / the simulator / a fetch error) the field stays empty and the
 * SDK's CHK-A2 self-consistency check dormant-skips (backward-compatible).
 *
 * NOTE: `app_compose` here comes from the SAME node that produced `compose_hash`
 * (self-reported). The pair only proves the node is internally consistent — it
 * is attacker-forgeable and is NOT a trust anchor. Anchoring it (independent
 * compose source + RTMR3 replay + DCAP) is future work.
 */
export function mapAttestationToBundle(
  attestation: Attestation,
  pubkeyHex: string,
  nonce: Uint8Array,
  appCompose = "",
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
    // Future work: structural measurement fields (mrtd/rtmr0-3, event_log)
    // from GET /info tcb_info for RTMR replay anchoring. The mock does not inspect
    // them, so a stub is valid until the real DCAP/RTMR layers land.
    tcbInfo: {
      mrtd: "",
      rtmr0: "",
      rtmr1: "",
      rtmr2: "",
      rtmr3: "",
      // Raw app_compose text from GET /info tcb_info (self-reported;
      // empty when /info was unavailable → CHK-A2 dormant-skips).
      app_compose: appCompose,
      event_log: [],
      // composeHash is available as a (recompute-only) hint, never a trust anchor.
      compose_hash: attestation.composeHash,
    },
    // Future work: signature_chain from dstack get_key chain
    // ([link0_sig, k256_signature]) — cross-repo ticket; not emitted by the
    // current /attestation route.
    signature_chain: [],
  };
}

/**
 * Build a {@link VerifyPolicy} from the verified pubkey + the SDK-generated nonce
 * `binding` carries the reportData binding (`report_data[0:32]==pubkey`,
 * `[32:64]==nonce`); `allowInsecureMock` is HARD-SET `true` for the mock path.
 *
 * `allowlist`/`tcb`/`pccsUrl` are defaulted internally — the mock verifier
 * ignores them, so they were removed from the public options. A future release
 * reintroduces those options (consumer-pinned anchors) and threads them here when
 * the real verifier flips `allowInsecureMock` off.
 */
export function buildVerifyPolicy(pubkeyHex: string, nonce: Uint8Array): VerifyPolicy {
  return {
    binding: {
      expectedPubkey: pubkeyHex,
      expectedNonce: bytesToHex(nonce),
    },
    allowlist: EMPTY_ALLOWLIST,
    tcb: { allowedStatuses: [], rejectDebug: true },
    allowInsecureMock: true,
  };
}

/**
 * The verify-and-trust seam. Holds a long-lived, bounded pubkey cache
 * (`pubkeyHex` keys, fixed TTL, LRU-evicted) across `verify()` calls. On a cache
 * hit within TTL it returns the verified pair before any attestation fetch;
 * on a miss/expiry it lazily fetches + correlates + verifies the
 * attestation, caching the pubkey ONLY after a resolved attestation verify.
 */
export class TrustedVerifier {
  private readonly cache: LRUCache<string, true>;
  private readonly nonceSource: () => Uint8Array;
  private readonly verifyAttestationImpl: (b: AttestationBundle, p: VerifyPolicy) => Promise<void>;
  private readonly chainId: bigint;
  private readonly replayWindowMs: number | undefined;
  private readonly attestationUrl: string;
  private readonly headers: Record<string, string> | undefined;
  private readonly fetchImpl: typeof fetch | undefined;

  constructor(opts: TrustedVerifierOptions) {
    const ttlMs = opts.pubkeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS;
    if (ttlMs <= 0) {
      throw new RangeError("pubkeyCacheTtlMs must be a positive number of milliseconds");
    }
    this.cache = new LRUCache<string, true>({
      max: opts.pubkeyCacheMax ?? DEFAULT_PUBKEY_CACHE_MAX,
      ttl: ttlMs,
      updateAgeOnGet: false,
      updateAgeOnHas: false,
    });
    this.nonceSource = opts.nonceSource ?? (() => crypto.getRandomValues(new Uint8Array(32)));
    this.verifyAttestationImpl = opts.verifyAttestation ?? verifyDstackAttestation;
    this.chainId = opts.chainId;
    this.replayWindowMs = opts.replayWindowMs;
    this.attestationUrl = opts.attestationUrl;
    this.headers = opts.headers;
    this.fetchImpl = opts.fetch;
  }

  /** True when `pubkeyHex` is cached and the entry has not expired. */
  private isFresh(pubkeyHex: string): boolean {
    return this.cache.has(pubkeyHex);
  }

  /** Cache `pubkeyHex` with a fresh TTL window. Called ONLY on a resolved verify. */
  private cacheVerifiedPubkey(pubkeyHex: string): void {
    this.cache.set(pubkeyHex, true);
  }

  /**
   * Best-effort fetch of the node's raw `app_compose` (GET /info →
   * `tcb_info.app_compose`) for CHK-A2. Returns `""` on ANY failure (no /info
   * route, malformed body, network error) — CHK-A2 then dormant-skips. Never
   * throws; the attestation verify must not fail because /info is unavailable.
   * The base URL is `attestationUrl` with a single trailing `/attestation`
   * segment removed (InfoEndpointComposeSource re-appends `/info`).
   */
  private async fetchAppComposeBestEffort(): Promise<string> {
    try {
      const baseUrl = this.attestationUrl.replace(/\/attestation\/?$/i, "");
      const source = new InfoEndpointComposeSource(baseUrl, {
        ...(this.fetchImpl === undefined ? {} : { fetch: this.fetchImpl }),
      });
      return await source.getAppCompose();
    } catch {
      return "";
    }
  }

  /**
   * Verify a (requestBytes, responseBytes, headers) triple and, on an
   * unknown/expired signing pubkey, lazily attest it. Fail-closed throughout.
   * Exact ordering:
   *   1. `verifyResponse` (the single Ed25519 path) — throws propagate.
   *   2. cache hit & fresh → return before any fetch.
   *   3. nodeId is OPTIONAL — included in the attestation fetch when present,
   *      omitted when absent (no pre-throw; the endpoint decides — fail-closed).
   *   4. one fresh nonce, reused below (no rebinding).
   *   5. fetch attestation via shark — throws propagate, cache untouched.
   *   6. correlate att.pubkey == response signer — throws on mismatch.
   *   7. map → bundle, build policy (same nonce).
   *   8. attestation verify — throw skips step 9. NO try/finally.
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
      ...(this.headers === undefined ? {} : { headers: this.headers }),
      ...(this.fetchImpl === undefined ? {} : { fetch: this.fetchImpl }),
    });

    verifyAttestationCorrelation(att, { verification: { pubkeyHex } } as VerifiedResponse);

    // Best-effort fetch of the node's raw `app_compose` from GET /info so
    // the SDK can run CHK-A2 (compose-hash self-consistency). NON-FATAL: older
    // nodes / the simulator / a transient /info error leave it empty and CHK-A2
    // dormant-skips — the attestation verify must not fail just because /info is
    // missing. The base URL is `attestationUrl` minus its trailing `/attestation`
    // (InfoEndpointComposeSource appends `/info`).
    const appCompose = await this.fetchAppComposeBestEffort();

    const bundle = mapAttestationToBundle(att, pubkeyHex, nonce, appCompose);
    const policy = buildVerifyPolicy(pubkeyHex, nonce);

    await this.verifyAttestationImpl(bundle, policy);

    this.cacheVerifiedPubkey(pubkeyHex);
    return pair;
  }
}
