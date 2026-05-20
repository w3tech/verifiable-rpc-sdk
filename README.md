# @ankr/verifiable-rpc-client

> Client SDK for the [Verifiable RPC](https://w3tech.atlassian.net/wiki/spaces/AIQT/pages/1141244060) trust chain. Calls a TDX-attested sidecar and verifies every response.

TypeScript SDK that pairs with [`rpc-attest-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar). For every JSON-RPC call the SDK:

1. Sends the request to a sidecar URL (running inside a TDX confidential VM via Phala dstack).
2. Parses the three `vRPC-*` response headers (`vRPC-Signature`, `vRPC-Timestamp`, `vRPC-Pubkey`).
3. Reconstructs the SPEC-04 80-byte canonical pre-image (`chain_id (8B LE) || sha256(request_body) (32B) || sha256(response_body) (32B) || timestamp_ms (8B LE)`).
4. Verifies the Ed25519 signature against the pubkey — any failure becomes a typed error.
5. Enforces a client-side replay window on `vRPC-Timestamp` (default 60s per SPEC-07).

A `fetchAttestation(nonce)` helper hits the sidecar's `GET /attestation?nonce=<hex>` endpoint, parses the nested TDX quote wire format, and returns a structured `Attestation` object.

## Status

Milestone **v3.0 — TS verifier SDK (v3 entry)** (in progress, Jira: [SHARK-3283](https://w3tech.atlassian.net/browse/SHARK-3283)).

Pairs with sidecar [`v0.1.0`](https://github.com/w3tech/verifiable-rpc-sidecar/releases/tag/v0.1.0).

Note: real TDX hardware deploy is not done yet. The SDK is currently developed against a sidecar exercised by the Phala dstack simulator. Hardware deploy + compose-hash registry are sibling v3 tickets.

## v3 entry scope

| Area | Deliverable |
|------|-------------|
| Wire format | TypeScript types matching the post-Phase-13 nested attestation wire end-to-end |
| Signature verification | Ed25519 verify over the SPEC-04 80-byte pre-image, per-call |
| Replay window | Client-side rejection of stale `vRPC-Timestamp` (default 60s, configurable) |
| Attestation helper | `fetchAttestation(nonce)` returning structured `{ quote, pubkey, composeHash }` |
| Testing | Bun-based unit + integration tests; integration tests pair against a running sidecar |

Out of scope for the v3 entry ticket (separate sibling tickets):

- TDX quote → compose-hash registry verification (registry v1 = IMP-10, separate work)
- npm publish workflow + package release
- WebSocket transport (sidecar doesn't support it yet)
- LB integration + shark-monitor `/attestation` check
- TCB incident-response runbook + customer UX content

## License

TBD.