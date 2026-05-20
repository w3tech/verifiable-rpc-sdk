// VerifierClient — the public entry point. Wraps `fetch` with:
//   1. JSON-RPC 2.0 envelope construction (auto-increment id per instance)
//   2. SPEC-04 80-byte pre-image reconstruction
//   3. Ed25519 verifyAsync against `vRPC-Signature` / `vRPC-Pubkey`
//   4. Replay-window enforcement against `vRPC-Timestamp`
//
// All four error branches map to typed `VerificationError` subclasses. The
// `fetchAttestation` Phase-18 stub stays in place — Phase 20 will implement.

import { verifyAsync } from "@noble/ed25519";

import { type Attestation, fetchAttestation } from "./attestation";
import { BadSignature, MalformedHeader, MissingHeader, StaleTimestamp } from "./errors";
import { buildPreImage, sha256 } from "./preimage";

const DEFAULT_REPLAY_WINDOW_MS = 60_000;

const SIGNATURE_HEADER = "vRPC-Signature";
const TIMESTAMP_HEADER = "vRPC-Timestamp";
const PUBKEY_HEADER = "vRPC-Pubkey";

const SIGNATURE_HEX_RE = /^0x[0-9a-f]{128}$/;
const PUBKEY_HEX_RE = /^0x[0-9a-f]{64}$/;
const TIMESTAMP_RE = /^\d+$/;

export interface VerifierClientOptions {
  /**
   * EVM-style chain id bound into the SPEC-04 pre-image (8 bytes LE). MUST
   * match the chain id the sidecar was configured with — mismatch produces
   * a `BadSignature` even on intact responses.
   */
  chainId: bigint;
  /**
   * Allowed skew between the client clock and the sidecar's signed timestamp.
   * Default 60_000 ms (SPEC-07). `0` rejects anything but an exact-millisecond
   * match — useful for tests, not for production.
   */
  replayWindowMs?: number;
  /**
   * Optional `fetch` override — primarily for tests against a mock sidecar.
   * Defaults to `globalThis.fetch`.
   */
  fetch?: typeof fetch;
}

export interface VerifiedResponse<T = unknown> {
  result: T;
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
    /** sha256 of the 80-byte SPEC-04 pre-image, for diagnostics. */
    preImageSha256: Uint8Array;
  };
}

/**
 * Convert `0x...` hex (already shape-validated) to a `Uint8Array`.
 * Caller is responsible for ensuring the input matches `0x[0-9a-f]{2n}`.
 */
function hexToBytes(hex0x: string): Uint8Array {
  const stripped = hex0x.slice(2);
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function absBigint(n: bigint): bigint {
  return n < 0n ? -n : n;
}

export class VerifierClient {
  private readonly url: string;
  private readonly chainId: bigint;
  private readonly replayWindowMs: number;
  private readonly fetchImpl: typeof fetch;
  private idCounter = 0;

  constructor(url: string, opts: VerifierClientOptions) {
    if (!/^https?:\/\//.test(url)) {
      throw new TypeError(`VerifierClient: url must start with http:// or https:// (got: ${url})`);
    }
    this.url = url;
    this.chainId = opts.chainId;
    this.replayWindowMs = opts.replayWindowMs ?? DEFAULT_REPLAY_WINDOW_MS;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
  }

  async call<T = unknown>(method: string, params: unknown[]): Promise<VerifiedResponse<T>> {
    // 1. Build JSON-RPC envelope.
    const id = ++this.idCounter;
    const requestBytes = new TextEncoder().encode(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    );

    // 2. POST.
    const resp = await this.fetchImpl(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestBytes,
    });

    // 3. Read response body bytes BEFORE parsing JSON — the signature covers
    //    the exact bytes received, not a re-serialised form.
    const responseBytes = new Uint8Array(await resp.arrayBuffer());

    // 4. Header parse — missing -> MissingHeader.
    const sigHex = resp.headers.get(SIGNATURE_HEADER);
    if (sigHex === null) {
      throw new MissingHeader(SIGNATURE_HEADER);
    }
    const pubkeyHex = resp.headers.get(PUBKEY_HEADER);
    if (pubkeyHex === null) {
      throw new MissingHeader(PUBKEY_HEADER);
    }
    const tsRaw = resp.headers.get(TIMESTAMP_HEADER);
    if (tsRaw === null) {
      throw new MissingHeader(TIMESTAMP_HEADER);
    }

    // 5. Header validate — bad shape -> MalformedHeader.
    if (!SIGNATURE_HEX_RE.test(sigHex)) {
      throw new MalformedHeader(SIGNATURE_HEADER, sigHex, "expected 0x + 128 lowercase hex chars");
    }
    if (!PUBKEY_HEX_RE.test(pubkeyHex)) {
      throw new MalformedHeader(PUBKEY_HEADER, pubkeyHex, "expected 0x + 64 lowercase hex chars");
    }
    if (!TIMESTAMP_RE.test(tsRaw)) {
      throw new MalformedHeader(TIMESTAMP_HEADER, tsRaw, "expected decimal u64 ms");
    }
    const timestampMs = BigInt(tsRaw);

    // 6. Pre-image reconstruct.
    const preImage = buildPreImage(this.chainId, requestBytes, responseBytes, timestampMs);

    // 7. Hex -> bytes (cheap, no dep).
    const sigBytes = hexToBytes(sigHex);
    const pubkeyBytes = hexToBytes(pubkeyHex);

    // 8. Ed25519 verify — bad signature -> BadSignature.
    const ok = await verifyAsync(sigBytes, preImage, pubkeyBytes);
    if (!ok) {
      throw new BadSignature({
        signatureHex: sigHex,
        pubkeyHex,
        preImageSha256: sha256(preImage),
      });
    }

    // 9. Replay-window check — outside the window -> StaleTimestamp.
    //    Done AFTER signature verify: a tampered timestamp would have failed
    //    step 8. We only reach here on a valid signature.
    const nowMs = BigInt(Date.now());
    const skewMs = timestampMs - nowMs;
    if (absBigint(skewMs) > BigInt(this.replayWindowMs)) {
      throw new StaleTimestamp({
        observedMs: timestampMs,
        nowMs,
        skewMs,
        allowedWindowMs: this.replayWindowMs,
      });
    }

    // 10. JSON-RPC parse — assume 2.0 shape; consumer handles error envelopes.
    const parsed = JSON.parse(new TextDecoder().decode(responseBytes)) as { result: T };

    // 11. Return.
    return {
      result: parsed.result,
      raw: { request: requestBytes, response: responseBytes },
      verification: {
        signatureHex: sigHex,
        pubkeyHex,
        timestampMs,
        preImageSha256: sha256(preImage),
      },
    };
  }

  async fetchAttestation(nonce: Uint8Array): Promise<Attestation> {
    return fetchAttestation(this.url, nonce);
  }
}
