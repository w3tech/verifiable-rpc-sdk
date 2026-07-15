// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Single-URL derivation for the vRPC transport convention.
//
// The user passes ONE endpoint URL. The SDK owns the `_vrpc` route suffix and
// the `/attestation` sub-route — the user never spells either out. Both the RPC
// leg and the attestation leg derive from that single URL, so there is no
// separate `attestationBaseUrl`/`chainSlug`.
//
// `_vrpc` suffixes the CHAIN path segment (the first path segment), NOT the end
// of the URL — so a trailing API-key segment (the public `rpc.ankr.com/<chain>/<key>`
// form) is preserved after the suffix.

/** RPC + attestation endpoints derived from one user-supplied URL. */
export interface VrpcUrls {
  /** JSON-RPC POST target — the `_vrpc` route, e.g. `https://rpc.ankr.com/arbitrum_vrpc`. */
  rpcUrl: string;
  /** Attestation GET target, e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
}

/** REST/HTTP-API route prefixes that precede the chain segment (see {@link deriveVrpcUrls}). */
const REST_PREFIXES = new Set(["premium-http", "rest"]);

/**
 * Derive the `_vrpc` RPC route and its `/attestation` sub-route from a single
 * user URL. `_vrpc` is appended to the **chain** path segment, unless it
 * already ends with `_vrpc` (dup-guard — a caller who passes a `_vrpc` URL is not
 * doubled). The chain is normally the first segment; a known REST/HTTP-API
 * prefix (`premium-http` on the public `rpc.ankr.com` form, `rest` on shark's
 * direct form) shifts it to the second. The attestation ingress only matches
 * the UNprefixed `/<chain>/<key>/attestation` route, so such a prefix is kept
 * on the RPC leg and stripped from the attestation leg. Any path segments
 * after the chain (e.g. an API key) are preserved. Query/hash are not expected
 * on a vRPC URL (`fetchAttestation` adds `?nonce=…`) and are dropped.
 *
 * `https://rpc.ankr.com/arbitrum`        → rpc `…/arbitrum_vrpc`,        attest `…/arbitrum_vrpc/attestation`
 * `https://rpc.ankr.com/arbitrum/<key>`  → rpc `…/arbitrum_vrpc/<key>`,  attest `…/arbitrum_vrpc/<key>/attestation`
 * `https://rpc.ankr.com/arbitrum_vrpc`   → rpc `…/arbitrum_vrpc` (unchanged)
 * `http://host:8545` (no path)           → rpc `…:8545/_vrpc`            (direct node serves vRPC at `/_vrpc`)
 * `…/premium-http/ton_api_v2/<key>`      → rpc `…/premium-http/ton_api_v2_vrpc/<key>`, attest `…/ton_api_v2_vrpc/<key>/attestation`
 */
export function deriveVrpcUrls(url: string): VrpcUrls {
  const u = new URL(url);
  const segments = u.pathname.split("/").filter(Boolean);

  // A known REST prefix shifts the chain to the SECOND segment: suffix that,
  // keep the prefix on the RPC route, drop it from the attestation route.
  if (segments.length >= 2 && REST_PREFIXES.has(segments[0] as string)) {
    const [prefix, chain, ...rest] = segments as [string, string, ...string[]];
    const chainVrpc = chain.endsWith("_vrpc") ? chain : `${chain}_vrpc`;
    const tail = [chainVrpc, ...rest].join("/");
    return {
      rpcUrl: `${u.origin}/${prefix}/${tail}`,
      attestationUrl: `${u.origin}/${tail}/attestation`,
    };
  }

  if (segments.length === 0) {
    // No chain segment (e.g. a direct node root `http://host:port`). The node
    // serves the vRPC endpoint at `/_vrpc`.
    const rpcUrl = `${u.origin}/_vrpc`;
    return { rpcUrl, attestationUrl: `${rpcUrl}/attestation` };
  }

  // First path segment is the chain slug. Append `_vrpc` (dup-guard); preserve
  // everything after it (e.g. an API key).
  const chain = segments[0] as string;
  if (!chain.endsWith("_vrpc")) {
    segments[0] = `${chain}_vrpc`;
  }
  const rpcUrl = `${u.origin}/${segments.join("/")}`;
  return { rpcUrl, attestationUrl: `${rpcUrl}/attestation` };
}
