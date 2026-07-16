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

/** REST/HTTP-API route prefixes that precede the chain segment (see {@link deriveVrpcUrls}). */
const REST_PREFIXES = new Set(["premium-http", "rest"]);

/**
 * Derive the `/attestation` sub-route from a single user URL. The URL itself is
 * the RPC leg, verbatim — the user spells the vRPC route out explicitly (the
 * SDK does NOT append `_vrpc`). A known REST/HTTP-API prefix (`premium-http`
 * on the public `rpc.ankr.com` form, `rest` on shark's direct form) is kept on
 * the RPC leg but stripped from the attestation leg, because the attestation
 * ingress only matches the UNprefixed `/<chain>/<key>/attestation` route. Any
 * path segments after the chain (e.g. an API key) are preserved. Query/hash
 * are not expected on a vRPC URL (`fetchAttestation` adds `?nonce=…`) and are
 * dropped.
 *
 * `https://rpc.ankr.com/arbitrum_vrpc`        → rpc unchanged, attest `…/arbitrum_vrpc/attestation`
 * `https://rpc.ankr.com/arbitrum_vrpc/<key>`  → rpc unchanged, attest `…/arbitrum_vrpc/<key>/attestation`
 * `http://host:8545/_vrpc`                    → rpc unchanged, attest `…:8545/_vrpc/attestation`
 * `…/premium-http/ton_api_v2_vrpc/<key>`      → rpc unchanged, attest `…/ton_api_v2_vrpc/<key>/attestation`
 */
export function deriveVrpcUrls(url: string): VrpcUrls {
  const u = new URL(url);
  const segments = u.pathname.split("/").filter(Boolean);

  // A known REST prefix is kept on the RPC route but dropped from the
  // attestation route.
  if (segments.length >= 2 && REST_PREFIXES.has(segments[0] as string)) {
    const [prefix, ...tail] = segments as [string, ...string[]];
    return {
      rpcUrl: `${u.origin}/${prefix}/${tail.join("/")}`,
      attestationUrl: `${u.origin}/${tail.join("/")}/attestation`,
    };
  }

  const rpcUrl = segments.length === 0 ? u.origin : `${u.origin}/${segments.join("/")}`;
  return { rpcUrl, attestationUrl: `${rpcUrl}/attestation` };
}
