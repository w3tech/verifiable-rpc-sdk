// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// TrustedVerifier — the single orchestration unit that combines
// the existing Ed25519 verify path (`verifyResponse`) with a TTL pubkey cache and
// lazy TDX attestation: on an unknown/expired signing pubkey it fetches the node
// attestation through the gateway, maps it to the frozen `AttestationBundle`, builds a
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
  createCloudVerifier,
  EMPTY_ALLOWLIST,
  type HardwareVerifier,
  type VerifyPolicy,
  verifyDstackAttestation,
} from "@ankr.com/dstack-verify";
import { bytesToHex } from "@noble/hashes/utils.js";
import { LRUCache } from "lru-cache";

import { type Attestation, fetchAttestation, verifyAttestationCorrelation } from "./attestation";
import { InfoEndpointComposeSource } from "./compose";
import { byteLen, redactHeaders, truncateHex } from "./log-redact";
import { defaultLogger, type Logger, safeLogger } from "./logger";
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
  /**
   * Hardware-signature verifier wired into the policy and run (mandatorily) by
   * `verifyDstackAttestation`. Defaults to the Phala {@link createCloudVerifier}
   * — i.e. hardware verification is ALWAYS on. Override to point at a self-hosted
   * endpoint, a future local-DCAP verifier, or (in tests) a no-network mock.
   */
  hardwareVerifier?: HardwareVerifier;
  /**
   * OPT-IN debug logger. Inject to narrate the verify flow; omit (the default)
   * and the SDK stays silent. Wrapped in {@link safeLogger} at construction so a
   * throwing `debug()` can never break verification.
   */
  logger?: Logger;
}

/**
 * Map a fetched {@link Attestation} (gateway `/attestation` wire shape) to the
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
 * Build a {@link VerifyPolicy} from the verified pubkey + the SDK-generated nonce.
 * `binding` carries the reportData binding (`report_data[0:32]==pubkey`,
 * `[32:64]==nonce`). `hardwareVerifier` is ALWAYS set — `verifyDstackAttestation`
 * runs it as the mandatory hardware root of trust; it defaults to the Phala
 * {@link createCloudVerifier} and is overridable (self-hosted endpoint, a future
 * local-DCAP verifier, or a no-network test mock).
 *
 * `allowlist`/`tcb` are defaulted internally. A future release reintroduces
 * consumer-pinned anchors (`allowlist`/`tcb`/`pccsUrl`) and threads them here.
 */
export function buildVerifyPolicy(
  pubkeyHex: string,
  nonce: Uint8Array,
  hardwareVerifier: HardwareVerifier = createCloudVerifier(),
  logger?: Logger,
): VerifyPolicy {
  return {
    binding: {
      expectedPubkey: pubkeyHex,
      expectedNonce: bytesToHex(nonce),
    },
    allowlist: EMPTY_ALLOWLIST,
    tcb: { allowedStatuses: [], rejectDebug: true },
    hardwareVerifier,
    // Carry the verifier's logger into dstack-verify via VerifyPolicy.logger,
    // but ONLY when a real logger is present. The no-op `defaultLogger` is
    // treated as "no logger" so the silent path leaves `policy.logger` undefined
    // — dstack-verify's `if (policy.logger)` guard then stays allocation-free.
    ...(logger === undefined || logger === defaultLogger ? {} : { logger }),
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
  private readonly hardwareVerifier: HardwareVerifier;
  private readonly logger: Logger;
  /** Resolved pubkey-cache TTL (ms); narrated in the `cache.store` event. */
  private readonly ttlMs: number;

  constructor(opts: TrustedVerifierOptions) {
    const ttlMs = opts.pubkeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS;
    if (ttlMs <= 0) {
      throw new RangeError("pubkeyCacheTtlMs must be a positive number of milliseconds");
    }
    this.ttlMs = ttlMs;
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
    // Hardware verification is ALWAYS on. Default to the Phala CloudVerifier
    // (threaded the same fetch override so a custom transport applies); callers
    // override for a self-hosted endpoint, local DCAP, or a no-network test mock.
    this.hardwareVerifier =
      opts.hardwareVerifier ?? createCloudVerifier(opts.fetch ? { fetch: opts.fetch } : {});
    // Wrap the injected logger ONCE so a throwing debug() can never break verify;
    // default to the no-op singleton so the !== defaultLogger silent-path guard holds.
    this.logger = opts.logger ? safeLogger(opts.logger) : defaultLogger;
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
   *   5. fetch attestation via the gateway — throws propagate, cache untouched.
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
    if (this.logger !== defaultLogger) {
      // Headers are flattened to a plain Record then allowlist-redacted — the
      // raw authorization/x-api-key values never reach the logged `data`.
      const headerRecord: Record<string, string> =
        headers instanceof Headers ? Object.fromEntries(headers.entries()) : { ...headers };
      this.logger.debug("verify.start", {
        req: truncateHex(bytesToHex(requestBytes)),
        res: truncateHex(bytesToHex(responseBytes)),
        headers: redactHeaders(headerRecord),
      });
    }

    const pair = await verifyResponse(requestBytes, responseBytes, headers, {
      chainId: this.chainId,
      ...(this.replayWindowMs === undefined ? {} : { replayWindowMs: this.replayWindowMs }),
      // Thread the verifier's safe-wrapped logger so the preimage/signature/
      // timestamp steps (points 2-4) narrate from within verifyResponse. On the
      // silent path this is the no-op defaultLogger (verifyResponse guards on it).
      ...(this.logger === defaultLogger ? {} : { logger: this.logger }),
    });

    const pubkeyHex = pair.verification.pubkeyHex;
    const fresh = this.isFresh(pubkeyHex);
    if (this.logger !== defaultLogger) {
      this.logger.debug("cache.lookup", {
        pubkeyHex,
        hit: fresh,
        ...(fresh ? { note: "cached → skip attestation" } : {}),
      });
    }
    if (fresh) {
      return pair;
    }

    const nonce = this.nonceSource();

    // nodeId is OPTIONAL: included when the response carried vRPC-NodeId, omitted
    // otherwise. Absent + behind the gateway → the gateway can't route → the fetch errors and
    // propagates (fail-closed); absent + direct node → the fetch works. No pre-throw.
    if (this.logger !== defaultLogger) {
      this.logger.debug("attestation.fetch", {
        attestationUrl: this.attestationUrl,
        ...(pair.nodeId === undefined ? {} : { nodeId: pair.nodeId }),
        nonce: bytesToHex(nonce),
      });
    }

    const att = await fetchAttestation({
      attestationUrl: this.attestationUrl,
      ...(pair.nodeId === undefined ? {} : { nodeId: pair.nodeId }),
      nonce,
      ...(this.headers === undefined ? {} : { headers: this.headers }),
      ...(this.fetchImpl === undefined ? {} : { fetch: this.fetchImpl }),
    });

    // Pass the logger so the correlation step (point 8) is observable before
    // a mismatch throws. On the silent path defaultLogger is a no-op.
    verifyAttestationCorrelation(
      att,
      { verification: { pubkeyHex } } as VerifiedResponse,
      this.logger,
    );

    // Best-effort fetch of the node's raw `app_compose` from GET /info so
    // the SDK can run CHK-A2 (compose-hash self-consistency). NON-FATAL: older
    // nodes / the simulator / a transient /info error leave it empty and CHK-A2
    // dormant-skips — the attestation verify must not fail just because /info is
    // missing. The base URL is `attestationUrl` minus its trailing `/attestation`
    // (InfoEndpointComposeSource appends `/info`).
    const appCompose = await this.fetchAppComposeBestEffort();

    if (this.logger !== defaultLogger) {
      this.logger.debug("attestation.received", {
        reportData: att.quote.report_data,
        composeHash: att.composeHash,
        pubkeyHex,
        quote: truncateHex(att.quote.quote),
        eventLog: byteLen(att.quote.event_log),
        appCompose: byteLen(appCompose),
      });
    }

    const bundle = mapAttestationToBundle(att, pubkeyHex, nonce, appCompose);
    const policy = buildVerifyPolicy(pubkeyHex, nonce, this.hardwareVerifier, this.logger);

    await this.verifyAttestationImpl(bundle, policy);

    this.cacheVerifiedPubkey(pubkeyHex);
    if (this.logger !== defaultLogger) {
      this.logger.debug("cache.store", { pubkeyHex, ttlMs: this.ttlMs });
    }
    return pair;
  }
}
