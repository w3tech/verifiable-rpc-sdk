# @w3tech.io/vrpc-proxy

Local verifying reverse proxy for vRPC endpoints. Point any plain HTTP client
at the proxy; it forwards every request verbatim to the configured upstream
vRPC endpoint, verifies every response with `@w3tech.io/vrpc-core`
(Ed25519 signature + attestation, fail-closed), and relays verified bytes
back unchanged. An unverified body is never returned to the client.

## What gets verified (trust boundary)

Every relayed response has passed the full `TrustedVerifier` policy from
`@w3tech.io/vrpc-core`: **signed + untampered** (Ed25519 over the canonical
104-byte pre-image), **fresh** (replay window), **correctly bound** (chain id +
signer key), plus the lazy attestation leg — correlation of the signing key to
the node's TDX attestation and the **mandatory, always-on hardware verify** of
the DCAP quote. A response failing any check is withheld and replaced with a
typed error (see [Failure semantics](#failure-semantics)).

## Quick start (npx)

```sh
npx @w3tech.io/vrpc-proxy --upstream <url> --chain-id <id>
```

The package is available from the npm registry after the next release.

## Usage (repo run)

```sh
pnpm run proxy -- --upstream https://rpc.example.com/arbitrum_vrpc/KEY --chain-id 42161
```

Inside the package:
`pnpm --filter @w3tech.io/vrpc-proxy start -- --upstream <url> --chain-id <id>`.

## Flags and environment variables

CLI flag wins over env var, env var wins over the default.

| Flag | Env var | Default | Description |
| ---- | ------- | ------- | ----------- |
| `--upstream` (required) | `VRPC_PROXY_UPSTREAM` | — | Upstream vRPC endpoint URL |
| `--chain-id` (required) | `VRPC_PROXY_CHAIN_ID` | — | Chain id (opaque string, validated at startup) |
| `--api-key` | `VRPC_PROXY_API_KEY` | — | Optional API key sent as `x-api-key` to both the upstream and the attestation endpoint; a client-supplied `x-api-key` header takes precedence |
| `--listen` | `VRPC_PROXY_LISTEN` | `127.0.0.1:8969` | Listen `host:port` |
| `--timeout` | `VRPC_PROXY_TIMEOUT` | `30000` | Upstream timeout, ms |
| `--replay-window` | `VRPC_PROXY_REPLAY_WINDOW` | core default (`60000`) | Replay window, ms |
| `--attestation-cache-ttl` | `VRPC_PROXY_ATTESTATION_CACHE_TTL` | core default (`3600000`) | How long a verified attestation (per signing pubkey) is reused before re-attestation, ms |
| `--log-level` | `VRPC_PROXY_LOG_LEVEL` | `silent` | `silent` or `debug` |
| `--max-body-bytes` | `VRPC_PROXY_MAX_BODY_BYTES` | `33554432` (32 MiB) | Request/response body cap |

## Failure semantics

The proxy fails closed: a response that cannot be verified is never relayed —
zero upstream body bytes reach the client. Every error path responds with a
typed JSON body:

```json
{ "error": { "kind": "...", "message": "..." } }
```

One row per `ProxyError` kind (source of truth: `src/errors.ts`):

| Error kind | HTTP status | Thrown when |
| ---------- | ----------- | ----------- |
| `Config` | — (startup: message on stderr, exit 1 before the socket binds) | Invalid or missing startup configuration |
| `BodyTooLarge` | `413` | Inbound request body exceeds the configured cap |
| `UpstreamTimeout` | `504` | Upstream did not answer within the configured timeout |
| `UpstreamConnect` | `502` | Upstream connection or dispatch failed (DNS, refused, reset, TLS, …) |
| `UpstreamBodyTooLarge` | `502` | Upstream response body exceeds the cap — cannot be safely verified |
| `UnsignedUpstream` | `502` | Upstream answered without vRPC signature headers — not a vRPC endpoint, or an unsigned gateway error |
| `UnsupportedEncoding` | `502` | Upstream used a `Content-Encoding` the proxy cannot decode — cannot verify |
| `DecodeFailed` | `502` | Upstream body failed to decode under its declared `Content-Encoding` |
| `Internal` | `502` | Unexpected internal failure — generic message, no details leaked |

Verification failures from core (`BadSignature`, `StaleTimestamp`, …) also
respond `502` with the same JSON shape, carrying core's `kind` discriminator.

Verified responses are relayed verbatim — body bytes, `Content-Encoding`, and
`vRPC-*` headers untouched. The one deviation: when the upstream's encoding is
not acceptable to the client, the already-verified decoded plaintext is served
instead (the signature covers the plaintext, so the fallback body remains
client-re-verifiable).

## Attestation URL note

The attestation URL is derived from the upstream URL (`deriveVrpcUrls`) — the
same single-URL model as the SDK adapters. Derivation drops query parameters
and the hash fragment; pass the API key via `--api-key` (or key-in-path)
instead of the query string.

## Integration tests

An env-gated real-wire suite (dstack simulator + attestation sidecar + this
proxy in-process) lives in `tests/integration/`. It needs three env vars —
`SIDECAR_BIN`, `DSTACK_SIMULATOR_BIN`, `DSTACK_SIMULATOR_FIXTURES_DIR` — and
runs with:

```sh
SIDECAR_BIN=… DSTACK_SIMULATOR_BIN=… DSTACK_SIMULATOR_FIXTURES_DIR=… \
  pnpm --filter @w3tech.io/vrpc-proxy test:integration
```

When the vars are unset the suite skips cleanly, so plain `pnpm -r test`
stays unit-only. See the repo `AGENTS.md` for where the binaries come from.

## Example

See `examples/04-proxy.ts` at the repo root: the proxy spawned as a child
process and queried by a plain `fetch` client that imports zero SDK code —
verified result plus the passed-through `vRPC-*` headers printed. Run with
`pnpm example:04-proxy`.
