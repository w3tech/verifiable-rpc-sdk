# @w3tech.io/vrpc-proxy

Local verifying reverse proxy for vRPC endpoints. Point any plain HTTP client
at the proxy; it forwards every request verbatim to the configured upstream
vRPC endpoint, verifies every response with `@w3tech.io/vrpc-core`
(Ed25519 signature + attestation, fail-closed), and relays verified bytes
back unchanged. An unverified body is never returned to the client.

## Usage (repo run)

```sh
pnpm run proxy -- --upstream https://rpc.example.com/arbitrum_vrpc/KEY --chain arbitrum
```

(The root `proxy` script is wired in a follow-up commit; inside the package:
`pnpm --filter @w3tech.io/vrpc-proxy start -- --upstream <url> --chain <id>`.)

## Flags and environment variables

CLI flag wins over env var, env var wins over the default.

| Flag | Env var | Default | Description |
| ---- | ------- | ------- | ----------- |
| `--upstream` (required) | `VRPC_PROXY_UPSTREAM` | — | Upstream vRPC endpoint URL |
| `--chain` (required) | `VRPC_PROXY_CHAIN` | — | Chain id (opaque string, validated at startup) |
| `--attestation-url` | `VRPC_PROXY_ATTESTATION_URL` | derived from `--upstream` | Attestation endpoint override |
| `--attestation-header` (repeatable, `"Name: value"`) | `VRPC_PROXY_ATTESTATION_HEADER` (newline-separated pairs) | — | Extra headers for the attestation leg (e.g. `x-api-key`) |
| `--listen` | `VRPC_PROXY_LISTEN` | `127.0.0.1:8969` | Listen `host:port` |
| `--timeout` | `VRPC_PROXY_TIMEOUT` | `30000` | Upstream timeout, ms |
| `--replay-window` | `VRPC_PROXY_REPLAY_WINDOW` | core default (`60000`) | Replay window, ms |
| `--log-level` | `VRPC_PROXY_LOG_LEVEL` | `silent` | `silent` or `debug` |
| `--max-body-bytes` | `VRPC_PROXY_MAX_BODY_BYTES` | `33554432` (32 MiB) | Request/response body cap |

## Failure semantics

The proxy fails closed: a response that cannot be verified is never relayed.

- Verification failure, missing vRPC headers, unreachable upstream,
  undecodable/oversized upstream body → HTTP `502` with a typed JSON body
  `{"error":{"kind":"...","message":"..."}}` — zero upstream body bytes.
- Upstream timeout → HTTP `504`, same typed JSON shape.
- Request body over the cap → HTTP `413`.

Verified responses are relayed verbatim — body bytes, `Content-Encoding`, and
`vRPC-*` headers untouched. The one deviation: when the upstream's encoding is
not acceptable to the client, the already-verified decoded plaintext is served
instead (the signature covers the plaintext, so the fallback body remains
client-re-verifiable).

## Attestation URL note

By default the attestation URL is derived from the upstream URL
(`deriveVrpcUrls`). Derivation drops query parameters and the hash fragment —
if your upstream URL carries query parameters (e.g. an API key in the query),
pass `--attestation-url` explicitly.
