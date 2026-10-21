// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// TrustedVerifier: `verifyResponse`, then a TTL pubkey cache, then one shared `attestNode` per
// unknown signer, bounded by a deadline. A pubkey is cached only after its attestation verified.

import type { HardwareVerifier } from "@w3tech.io/dstack-verify";
import { LRUCache } from "lru-cache";

import { attestNode } from "./attestation";
import { pickVrpcHeaders, truncateHex } from "./log-redact";
import type { Logger } from "./logger";
import { checkOptions, resolveSeams, type Seams } from "./options";
import { type ResponseHeaders, type VerifiedPair, verifyResponse } from "./verify";

/** Default max distinct verified pubkeys held in the cache before LRU eviction. */
const DEFAULT_PUBKEY_CACHE_MAX = 1024;

/** Construction options for {@link TrustedVerifier}. */
export interface TrustedVerifierOptions {
  /**
   * Opaque chain id string bound into the canonical pre-image as
   * `sha256(utf8(chainId))` at bytes [0..32]. MUST match the chain id string
   * the sidecar was configured with — mismatch produces a `BadSignature` even
   * on intact responses. Validated synchronously at construction; an invalid
   * id, like any other bad option, throws `InvalidOption`.
   */
  chainId: string;
  /** Allowed skew between client clock and signed timestamp; default 60_000 ms. */
  replayWindowMs?: number | undefined;
  /** Full attestation endpoint URL, e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
  /** Extra request headers for the attestation fetch (e.g. `x-api-key`). */
  headers?: Record<string, string> | undefined;
  /** `fetch` override — defaults to `globalThis.fetch`. */
  fetch?: typeof fetch | undefined;
  /** Verified-pubkey cache TTL in ms; default {@link DEFAULT_PUBKEY_CACHE_TTL_MS}. */
  pubkeyCacheTtlMs?: number | undefined;
  /** Max distinct verified pubkeys cached before LRU eviction; default 1024. */
  pubkeyCacheMax?: number | undefined;
  /**
   * Hardware-signature verifier wired into the policy and run (mandatorily) by
   * `verifyDstackAttestation`. Defaults to the Phala {@link createCloudVerifier}
   * — i.e. hardware verification is ALWAYS on. Override to point at a self-hosted
   * endpoint, a future local-DCAP verifier, or (in tests) a no-network mock.
   */
  hardwareVerifier?: HardwareVerifier | undefined;
  /**
   * OPT-IN debug logger. Inject to narrate the verify flow; omit (the default)
   * and the SDK stays silent. A throwing `debug()` is swallowed, so it can never
   * break verification.
   */
  logger?: Logger | undefined;
}

/** Verifies signed responses and attests each unknown signer once per cache TTL. */
export class TrustedVerifier {
  private readonly cache: LRUCache<string, true>;
  private readonly inflight = new Map<string, Promise<void>>();
  private readonly attestationUrl: string;
  private readonly headers: Record<string, string>;
  private readonly seams: Seams;
  private readonly ttlMs: number;

  constructor(opts: TrustedVerifierOptions) {
    const { chainId, replayWindowMs, pubkeyCacheTtlMs: ttlMs } = checkOptions(opts, ["chainId"]);
    this.ttlMs = ttlMs;
    this.cache = new LRUCache<string, true>({
      max: opts.pubkeyCacheMax ?? DEFAULT_PUBKEY_CACHE_MAX,
      ttl: ttlMs,
      updateAgeOnGet: false,
      updateAgeOnHas: false,
    });
    this.attestationUrl = opts.attestationUrl;
    this.headers = opts.headers ?? {};
    this.seams = resolveSeams(opts, chainId, replayWindowMs);
  }

  /** `verifyResponse` (throws propagate), then the cache, then a shared `attestNode` on a miss; caches only after success. */
  async verify(
    requestBytes: Uint8Array,
    responseBytes: Uint8Array,
    headers: ResponseHeaders,
  ): Promise<VerifiedPair> {
    const { logger, verifyOptions } = this.seams;
    if (logger) {
      // Only vrpc-* headers are logged, never authorization or x-api-key.
      const headerRecord: Record<string, string> =
        headers instanceof Headers ? Object.fromEntries(headers.entries()) : { ...headers };
      logger.debug("verify.start", {
        chainId: verifyOptions.chainId,
        req: truncateHex(requestBytes),
        res: truncateHex(responseBytes),
        headers: pickVrpcHeaders(headerRecord),
      });
    }

    const pair = await verifyResponse(requestBytes, responseBytes, headers, verifyOptions);

    const pubkeyHex = pair.verification.pubkeyHex;
    const fresh = this.cache.has(pubkeyHex);
    logger?.debug("cache.lookup", {
      pubkeyHex,
      hit: fresh,
      ...(fresh ? { note: "cached → skip attestation" } : {}),
    });
    if (fresh) {
      return pair;
    }

    // No await between the cache check and registering the flight: concurrent callers share it.
    let flight = this.inflight.get(pubkeyHex);
    if (flight === undefined) {
      flight = this.attest(pubkeyHex, pair.nodeId).finally(() => this.inflight.delete(pubkeyHex));
      this.inflight.set(pubkeyHex, flight);
    }
    await flight;
    return pair;
  }

  private async attest(pubkeyHex: string, nodeId: string | undefined): Promise<void> {
    await attestNode({
      transport: this.seams.transport,
      attestationUrl: this.attestationUrl,
      headers: this.headers,
      hardwareVerifier: this.seams.hardwareVerifier,
      logger: this.seams.logger,
      expectPubkey: pubkeyHex,
      nodeId,
    });
    this.cache.set(pubkeyHex, true);
    this.seams.logger?.debug("cache.store", { pubkeyHex, ttlMs: this.ttlMs });
  }
}
