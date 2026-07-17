# @w3tech.io/vrpc-proxy

Verifying reverse proxy for vRPC endpoints — get vRPC protection with **zero code
change**. Stand the proxy up in your infrastructure and route your RPC traffic
through it: any client, any language (Go, Rust, Python, curl, existing TypeScript
apps), any backend architecture. It forwards every request verbatim to the
configured upstream vRPC endpoint, verifies every response with
`@w3tech.io/vrpc-core` (Ed25519 signature + attestation, fail-closed), and relays
verified bytes back unchanged. An unverified body is never returned to the client.

Docker is the intended deployment (drops in as a sidecar/service); an npx CLI is
provided for local runs.

For what vRPC proves, the attestation flow, and the trust boundary, see the
[Quickstart and how-it-works guide](../../docs/quickstart.md).

One proxy instance serves exactly one blockchain: a single upstream vRPC
endpoint (`--upstream`) bound to a single chain id (`--chain-id`). Run one
instance per chain.

> 🚧 **Note:** a multichain proxy (routing several chains through one instance)
> is in development.

## Run with Docker

```sh
docker run --rm -p 8969:8969 ghcr.io/w3tech/vrpc-proxy --upstream <url> --chain-id <id>
```

The image binds `0.0.0.0:8969` by default (baked `VRPC_PROXY_LISTEN`) so port
mapping works; `--listen` or the env var still override it. The image is
amd64-only and has no `HEALTHCHECK` (distroless runtime, no health endpoint);
`docker run --init` is optional — SIGTERM is already handled.

The image is published to GHCR on each release tag; until the package is made
public, `docker login ghcr.io` is required to pull.

## Run with npx (local)

```sh
npx @w3tech.io/vrpc-proxy --upstream <url> --chain-id <id>
```

### Verify the image

Every release image is cosign-signed and provenance-attested by CI. Verify the
signature — proves the image was pushed by this repo's release workflow:

```sh
cosign verify ghcr.io/w3tech/vrpc-proxy:<version> \
  --certificate-identity-regexp 'https://github\.com/w3tech/verifiable-rpc-sdk/\.github/workflows/docker-publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify the image's build provenance — proves which workflow, commit, and repo
built exactly these bytes:

```sh
gh attestation verify oci://ghcr.io/w3tech/vrpc-proxy:<version> -R w3tech/verifiable-rpc-sdk
```

Verify a standalone copy of the bundled `cli.js` (extracted from the image) —
any distributed copy of the bundle file is attested per release. Attestation
matches by file **digest**, so the local filename does not matter:

```sh
# extract the exact bundle the release attested, from the pushed image
cid=$(docker create ghcr.io/w3tech/vrpc-proxy@sha256:<digest>)
docker cp "$cid":/app/cli.js ./cli.js && docker rm "$cid"

gh attestation verify ./cli.js -R w3tech/verifiable-rpc-sdk
```

## Usage (repo run)

```sh
pnpm run proxy -- --upstream https://rpc.ankr.com/arbitrum_vrpc --chain-id 42161 --api-key <key>
```

Inside the package:
`pnpm --filter @w3tech.io/vrpc-proxy start -- --upstream <url> --chain-id <id>`.

## Flags and environment variables

CLI flag wins over env var, env var wins over the default.

| Flag | Env var | Default | Description |
| ---- | ------- | ------- | ----------- |
| `--upstream` (required) | `VRPC_PROXY_UPSTREAM` | — | vRPC endpoint URL (e.g. `https://rpc.ankr.com/arbitrum_vrpc`), used verbatim for RPC; the attestation sub-route is derived from it (same single-URL model as the SDK) |
| `--chain-id` (required) | `VRPC_PROXY_CHAIN_ID` | — | Chain id (opaque string, validated at startup) |
| `--api-key` | `VRPC_PROXY_API_KEY` | — | Optional API key sent as `x-api-key` to both the upstream and the attestation endpoint; a client-supplied `x-api-key` header takes precedence |
| `--listen` | `VRPC_PROXY_LISTEN` | `127.0.0.1:8969` | Listen `host:port` |
| `--timeout` | `VRPC_PROXY_TIMEOUT` | `30000` | Upstream timeout, ms |
| `--replay-window` | `VRPC_PROXY_REPLAY_WINDOW` | core default (`60000`) | Replay window, ms |
| `--attestation-cache-ttl` | `VRPC_PROXY_ATTESTATION_CACHE_TTL` | core default (`3600000`) | How long a verified attestation (per signing pubkey) is reused before re-attestation, ms |
| `--log-level` | `VRPC_PROXY_LOG_LEVEL` | `error` | `silent` (nothing), `error` (fail-closed reasons only), or `debug` (per-request forward/verify trace) |
| `--max-body-bytes` | `VRPC_PROXY_MAX_BODY_BYTES` | `33554432` (32 MiB) | Request/response body cap |

## Failure semantics

The proxy fails closed: a response that cannot be verified is never relayed —
zero upstream body bytes reach the client. Every error path responds with a
typed JSON body:

```json
{ "error": { "kind": "...", "message": "...", "traceId": "..." } }
```

`traceId` is present only when the upstream answered with an `x-shark-trace-id`
header (the same value also appears as a `traceId` field in the `proxy.error`
log line) — use it to correlate a fail-closed error with the upstream's logs.

One row per `ProxyError` kind (source of truth: `src/errors.ts`):

| Error kind | HTTP status | Thrown when |
| ---------- | ----------- | ----------- |
| `Config` | — (startup: message on stderr, exit 1 before the socket binds) | Invalid or missing startup configuration |
| `BodyTooLarge` | `413` | Inbound request body exceeds the configured cap |
| `UpstreamTimeout` | `504` | Upstream did not answer within the configured timeout |
| `UpstreamConnect` | `502` | Upstream connection or dispatch failed (DNS, refused, reset, TLS, …) |
| `UpstreamBodyTooLarge` | `502` | Upstream response body exceeds the cap — cannot be safely verified |
| `UnsignedUpstream` | `502` | Upstream answered without vRPC signature headers — not a vRPC endpoint, or an unsigned gateway error |
| `DecodeFailed` | `502` | Upstream body failed to decode under its declared `Content-Encoding` (unknown coding or corrupt stream) — cannot verify |
| `Internal` | `502` | Unexpected internal failure — generic message, no details leaked |

Verification failures from core (`BadSignature`, `StaleTimestamp`, …) also
respond `502` with the same JSON shape, carrying core's `kind` discriminator.

Verified responses are relayed verbatim — body bytes, `Content-Encoding`, and
`vRPC-*` headers untouched.

## Example

See [`examples/04-proxy.ts`](../../examples/04-proxy.ts) at the repo root: the proxy spawned as a child
process and queried by a plain `fetch` client that imports zero SDK code —
verified result plus the passed-through `vRPC-*` headers printed. Run with
`pnpm example:04-proxy`.
