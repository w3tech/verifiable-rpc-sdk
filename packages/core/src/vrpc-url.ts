// Single-URL derivation for the vRPC transport convention.
//
// The user passes ONE endpoint URL (e.g. `https://rpc.ankr.com/arbitrum`). The
// SDK owns the `_vrpc` route suffix and the `/attestation` sub-route — the user
// never spells either out. Both the RPC leg and the attestation leg derive from
// that single URL, so there is no separate `attestationBaseUrl`/`chainSlug`.

/** RPC + attestation endpoints derived from one user-supplied URL. */
export interface VrpcUrls {
  /** JSON-RPC POST target — the `_vrpc` route, e.g. `https://rpc.ankr.com/arbitrum_vrpc`. */
  rpcUrl: string;
  /** Attestation GET target, e.g. `https://rpc.ankr.com/arbitrum_vrpc/attestation`. */
  attestationUrl: string;
}

/**
 * Derive the `_vrpc` RPC route and its `/attestation` sub-route from a single
 * user URL. Trailing slashes are stripped; `_vrpc` is appended only when the URL
 * does not already end with it (dup-guard, so a caller who passes a `_vrpc` URL
 * is not doubled to `_vrpc_vrpc`).
 *
 * `https://rpc.ankr.com/arbitrum`      → rpc `…/arbitrum_vrpc`, attest `…/arbitrum_vrpc/attestation`
 * `https://rpc.ankr.com/arbitrum_vrpc` → rpc `…/arbitrum_vrpc` (unchanged), attest `…/arbitrum_vrpc/attestation`
 */
export function deriveVrpcUrls(url: string): VrpcUrls {
  const trimmed = url.replace(/\/+$/, "");
  const rpcUrl = trimmed.endsWith("_vrpc") ? trimmed : `${trimmed}_vrpc`;
  return { rpcUrl, attestationUrl: `${rpcUrl}/attestation` };
}
