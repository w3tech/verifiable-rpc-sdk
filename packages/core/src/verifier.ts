// VerifierClient — the public entry point. Wraps `fetch` with:
//   1. JSON-RPC 2.0 envelope construction (auto-increment id per instance)
//   2. Canonical 80-byte pre-image reconstruction
//   3. Ed25519 verifyAsync against `vRPC-Signature` / `vRPC-Pubkey`
//   4. Replay-window enforcement against `vRPC-Timestamp`
//
// All four error branches map to typed `VerificationError` subclasses.
// `fetchAttestation` is delegated to the standalone helper in `./attestation`.

import type { PinnedAllowlist, TcbPolicy } from "@ankr.com/dstack-verify";

import { type Attestation, fetchAttestation } from "./attestation";
import { DEFAULT_REPLAY_WINDOW_MS, verifyResponse } from "./verify";

export interface VerifierClientOptions {
  /**
   * EVM-style chain id bound into the canonical pre-image (8 bytes LE). MUST
   * match the chain id the sidecar was configured with — mismatch produces
   * a `BadSignature` even on intact responses.
   */
  chainId: bigint;
  /**
   * Allowed skew between the client clock and the sidecar's signed timestamp.
   * Default 60_000 ms. `0` rejects anything but an exact-millisecond
   * match — useful for tests, not for production.
   */
  replayWindowMs?: number;
  /**
   * Caller-supplied request headers (e.g. an auth `x-api-key`) merged into the
   * POST. The pinned `content-type: application/json` and
   * `accept-encoding: identity` always win over caller values (precedence:
   * pinned wins) because the signature contract depends on byte-exact wire
   * bytes and the response-hash leg.
   */
  headers?: Record<string, string>;
  /**
   * Convenience auth key sent as `x-api-key` on the RPC POST (and reused for
   * shark attestation fetches). An explicit `headers["x-api-key"]` entry wins
   * over this value; the pinned wire headers still win over both.
   */
  apiKey?: string;
  /**
   * Optional `fetch` override — primarily for tests against a mock sidecar.
   * Defaults to `globalThis.fetch`.
   */
  fetch?: typeof fetch;
  /**
   * TTL of a verified pubkey in the trust cache, ms; default 3_600_000 (1h).
   * Surfaced here for the trust-and-verify seam; wired in Phase 35.
   */
  pubkeyCacheTtl?: number;
  /**
   * Pinned trust anchors used to build the attestation `VerifyPolicy`.
   * Surfaced here; consumed by the seam in Phase 35.
   */
  allowlist?: PinnedAllowlist;
  /**
   * DCAP TCB acceptance policy for the attestation `VerifyPolicy`.
   * Surfaced here; consumed by the seam in Phase 35.
   */
  tcb?: TcbPolicy;
  /**
   * Operational collateral source for dcap-qvl (NOT a trust dependency).
   * Surfaced here; consumed by the seam in Phase 35.
   */
  pccsUrl?: string;
}

export interface VerifiedResponse<T = unknown> {
  result: T;
  /**
   * The serving node's id from the `vRPC-NodeId` response header, used to fetch
   * that node's attestation via shark. Absent when the proxy is older and does
   * not emit the header.
   */
  nodeId?: string;
  raw: {
    request: Uint8Array;
    response: Uint8Array;
  };
  verification: {
    /** `0x` + 128 lowercase hex chars. */
    signatureHex: string;
    /** `0x` + 64 lowercase hex chars. */
    pubkeyHex: string;
    timestampMs: bigint;
    /** sha256 of the 80-byte canonical pre-image, for diagnostics. */
    preImageSha256: Uint8Array;
  };
}

export class VerifierClient {
  private readonly url: string;
  private readonly chainId: bigint;
  private readonly replayWindowMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly extraHeaders: Record<string, string>;
  private readonly apiKey: string | undefined;
  private idCounter = 0;

  constructor(url: string, opts: VerifierClientOptions) {
    if (!/^https?:\/\//.test(url)) {
      throw new TypeError(`VerifierClient: url must start with http:// or https:// (got: ${url})`);
    }
    this.url = url;
    this.chainId = opts.chainId;
    this.replayWindowMs = opts.replayWindowMs ?? DEFAULT_REPLAY_WINDOW_MS;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.extraHeaders = opts.headers ?? {};
    this.apiKey = opts.apiKey;
  }

  async call<T = unknown>(method: string, params: unknown[]): Promise<VerifiedResponse<T>> {
    // 1. Build JSON-RPC envelope.
    const id = ++this.idCounter;
    const requestBytes = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    );

    // 2. POST. Pin `accept-encoding: identity` — the sidecar signs the exact
    //    wire bytes of the response body, but `fetch` transparently decodes a
    //    `content-encoding` (e.g. gzip from the upstream node) before we read
    //    `arrayBuffer()`. Hashing the decoded bytes would break the
    //    response-hash leg of the pre-image and surface as a spurious
    //    `BadSignature`. Forcing identity keeps the bytes we hash identical to
    //    the bytes the sidecar signed.
    //    Precedence (lowest to highest): apiKey-derived x-api-key, then caller
    //    headers (so an explicit x-api-key wins), then the two pinned headers
    //    LAST so pinned always win — a caller cannot override the wire-byte
    //    contract.
    const resp = await this.fetchImpl(this.url, {
      method: "POST",
      headers: {
        ...(this.apiKey === undefined ? {} : { "x-api-key": this.apiKey }),
        ...this.extraHeaders,
        "content-type": "application/json",
        "accept-encoding": "identity",
      },
      body: requestBytes,
    });

    // 3. Read response body bytes BEFORE parsing JSON — the signature covers
    //    the exact bytes received, not a re-serialised form.
    const responseBytes = new Uint8Array(await resp.arrayBuffer());

    // 4-9. Delegate the entire verify half to the transport-agnostic seam
    //      (header parse/validate -> pre-image -> Ed25519 verify -> replay
    //      window). ONE verify path — `verifyResponse` is the single source of
    //      truth shared with the ethers/viem adapters.
    const pair = await verifyResponse(requestBytes, responseBytes, resp.headers, {
      chainId: this.chainId,
      replayWindowMs: this.replayWindowMs,
    });

    // 10. JSON-RPC parse — assume 2.0 shape; consumer handles error envelopes.
    const parsed = JSON.parse(new TextDecoder().decode(pair.responseBytes)) as { result: T };

    // 11. Return. Omit nodeId entirely when absent (exactOptionalPropertyTypes).
    return {
      result: parsed.result,
      ...(pair.nodeId === undefined ? {} : { nodeId: pair.nodeId }),
      raw: { request: requestBytes, response: responseBytes },
      verification: pair.verification,
    };
  }

  async fetchAttestation(nonce: Uint8Array): Promise<Attestation> {
    return fetchAttestation(this.url, nonce);
  }
}
