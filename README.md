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

## Defence in depth

Verifiable RPC signs the bytes returned by an enclave-bound binary; it does **not** prove the data on the node's persistent disk is current or untampered. Intel TDX and Phala dstack protect what is in CPU and RAM, not the `/data` LUKS2 volume that backs blockchain-node state — the disk has confidentiality only (no integrity, no freshness, no rollback protection, and is not measured into any RTMR). For **state reads** (`eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount`), the cryptographically stronger primitive is a Merkle proof against `block.stateRoot`: pair this SDK with a sync-committee light client ([a16z Helios](https://github.com/a16z/helios) or equivalent) and verify state reads via [`eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186). The SDK signature remains useful as defence-in-depth and as a latency-friendly path; it is the **only** practical primitive for methods Merkle cannot reach — `eth_call`, `eth_estimateGas`, `eth_getLogs`, `eth_gasPrice`, fee history, and mempool methods — which is exactly where the LayerZero / Kelp DAO 2026-04 binary-swap attack class lives and exactly where TEE attestation + compose-hash registry uniquely defeats it. The full per-method TEE-vs-Merkle composition table (including the "Neither — fundamental limit" row for data availability and censorship detection) is maintained in the workstream's `TRUST-MODEL.md` §Data-layer integrity; the disk-layer threat surface (rollback / silent corruption / pre-0.5.4 LUKS2 header swap) is catalogued in `PITFALL-MITIGATIONS.md` §C8.

## License

TBD.