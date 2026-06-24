// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// anchorTrust — adapter-neutral boot-time attestation-correlation helper.
//
// OPT-IN: the developer awaits this ONCE at startup, after constructing their
// provider/client. It does NOT block or alter the (sync) adapter constructors
// (VrpcProvider / vrpcHttp) — both the ethers and viem examples call this same
// helper, so the trust-anchor behaviour is identical across adapters.
//
// FAIL-CLOSED: on any correlation failure it throws a member of the
// `VerificationError` family (AttestationCorrelationError on pubkey mismatch,
// AttestationNodeNotFoundError on a stale node_id, MissingHeader when the proxy
// omits vRPC-NodeId) rather than silently resolving.
//
// NO COPIED CRYPTO: the Ed25519 signature verification is performed by
// `VerifierClient.call` (the successful return IS the verification), and the
// pubkey correlation reuses `verifyAttestationCorrelation`; the attestation
// fetch reuses `fetchAttestation`. This file orchestrates those
// existing primitives and maps their errors — it implements none of the crypto.
//
// Mirrors the proven v3.1 flow in examples/07-attestation-via-gateway.ts.

import { fetchAttestation, verifyAttestationCorrelation } from "./attestation";
import { MissingHeader } from "./errors";
import { VerifierClient } from "./verifier";

/** Input to {@link anchorTrust}. Secrets (headers) are caller-supplied. */
export interface AnchorTrustOptions {
  /** RPC gateway base URL (no trailing slash), e.g. `https://rpc.ankr.com`. */
  rpcBaseUrl: string;
  /** Chain slug used to build the `<chain>_vrpc` route, e.g. `arbitrum`. */
  chain: string;
  /**
   * EVM-style chain id bound into the canonical pre-image. Coerced to `bigint`
   * via `BigInt()` WITHOUT a number round-trip — chain ids may exceed
   * `Number.MAX_SAFE_INTEGER` and widening through `number` would lose precision
   * and reject intact responses (false `BadSignature`).
   */
  chainId: number | bigint;
  /** Extra request headers sent on both legs (e.g. `x-api-key`). */
  headers?: Record<string, string>;
  /** `fetch` override — defaults to `globalThis.fetch` (used by both legs). */
  fetch?: typeof fetch;
  /**
   * Fresh 32-byte attestation-nonce source. Defaults to
   * `crypto.getRandomValues`; injectable so the offline unit test can supply a
   * deterministic nonce. Called exactly once per `anchorTrust` invocation.
   */
  nonceSource?: () => Uint8Array;
}

/** Result of a successful {@link anchorTrust} correlation. */
export interface AnchorTrustResult {
  /** The serving node's id (`vRPC-NodeId`) whose attestation was correlated. */
  nodeId: string;
  /** The correlated Ed25519 pubkey (`0x` + 64 hex), == attestation pubkey == response signer. */
  pubkey: string;
}

function defaultNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Confirm the serving node's attestation pubkey matches the pubkey that signed a
 * fresh RPC response, end-to-end through the Ankr RPC gateway. Resolves with the correlated
 * `{ nodeId, pubkey }` on success; throws a `VerificationError`-family member on
 * any failure (fail-closed). Adapter-neutral — call after constructing either a
 * `VrpcProvider` (ethers) or a `vrpcHttp` client (viem).
 */
export async function anchorTrust(opts: AnchorTrustOptions): Promise<AnchorTrustResult> {
  const vrpcUrl = `${opts.rpcBaseUrl}/${opts.chain}_vrpc`;

  // 1. One signed read through the gateway. A successful return IS the Ed25519
  //    verification (VerifierClient throws BadSignature otherwise) — no copied
  //    crypto. eth_blockNumber is cheap and side-effect-free.
  const client = new VerifierClient(vrpcUrl, {
    chainId: BigInt(opts.chainId),
    ...(opts.headers === undefined ? {} : { headers: opts.headers }),
    ...(opts.fetch === undefined ? {} : { fetch: opts.fetch }),
  });
  const verified = await client.call<string>("eth_blockNumber", []);

  // 2. Boot-time anchor requires the serving node id. An older proxy that omits
  //    vRPC-NodeId cannot be targeted — fail closed with a typed error rather
  //    than silently resolving. MissingHeader is the existing VerificationError
  //    member whose semantics ("required vRPC-* header absent") match exactly.
  if (verified.nodeId === undefined) {
    throw new MissingHeader("vRPC-NodeId");
  }
  const nodeId = verified.nodeId;

  // 3. Fresh 32-byte nonce, then fetch THIS node's attestation through the gateway.
  const nonceSource = opts.nonceSource ?? defaultNonce;
  const nonce = nonceSource();
  const attestation = await fetchAttestation({
    attestationUrl: `${vrpcUrl}/attestation`,
    nodeId,
    nonce,
    ...(opts.headers === undefined ? {} : { headers: opts.headers }),
    ...(opts.fetch === undefined ? {} : { fetch: opts.fetch }),
  });

  // 4. Correlation: throws AttestationCorrelationError on pubkey mismatch.
  verifyAttestationCorrelation(attestation, verified);

  return { nodeId, pubkey: verified.verification.pubkeyHex };
}
