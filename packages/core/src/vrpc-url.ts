// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Single-URL derivation for the vRPC transport convention.
//
// The user passes ONE endpoint URL — the explicit vRPC route (e.g.
// `https://rpc.ankr.com/arbitrum_vrpc`). The SDK never rewrites the route: the
// URL is used as-is for the RPC leg, and only the `/attestation` sub-route
// derives from it, so there is no separate `attestationBaseUrl`/`chainSlug`.

/** RPC + attestation endpoints derived from one user-supplied URL. */
export interface VrpcUrls {
  /** JSON-RPC POST target — the user URL as-is, e.g. `https://rpc.ankr.com/arbitrum_vrpc`. */
  rpcUrl: string;
  /** Attestation GET target, e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
}

/**
 * Derive the `/attestation` sub-route from a single user URL. The URL itself is
 * the RPC leg, verbatim — the user spells the vRPC route out explicitly (the
 * SDK does NOT append `_vrpc`). Query/hash are not expected on a vRPC URL
 * (`fetchAttestation` adds `?nonce=…`) and are dropped.
 *
 * `https://rpc.ankr.com/arbitrum_vrpc`        → rpc unchanged, attest `…/arbitrum_vrpc/attestation`
 * `https://rpc.ankr.com/arbitrum_vrpc/<key>`  → rpc unchanged, attest `…/arbitrum_vrpc/<key>/attestation`
 */
export function deriveVrpcUrls(url: string): VrpcUrls {
  const u = new URL(url);
  const segments = u.pathname.split("/").filter(Boolean);
  const rpcUrl = segments.length === 0 ? u.origin : `${u.origin}/${segments.join("/")}`;
  return { rpcUrl, attestationUrl: `${rpcUrl}/attestation` };
}
