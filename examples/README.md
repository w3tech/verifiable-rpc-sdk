# Examples

Three runnable examples for the verifiable-rpc-sdk. Run them with `tsx` via the
root scripts (`pnpm example:<name>` or `pnpm example:all`).

| # | Script | What it shows | Needs |
| - | ------ | ------------- | ----- |
| 01 | `01-ethers-client.ts` | Drop-in **ethers** provider (`VrpcProvider`) — create it and call `getBlock` / `getTransaction` / `getBalance`; every response is verified before ethers returns it. | env (skips cleanly without) |
| 02 | `02-viem-client.ts` | Drop-in **viem** transport (`vrpcHttp`) wired into `createPublicClient` — the same three calls, verified inside the transport. | env (skips cleanly without) |
| 03 | `03-vrpc-core-walkthrough.ts` | Step-by-step **`@ankr.com/vrpc-core`** verification: signed wire → `verifyResponse` → tamper→`BadSignature` → `fetchAttestation` + correlation → `VerifierClient` one-liner. | nothing — runs against the live node |

## Run

```sh
pnpm install
pnpm example:03-vrpc-core-walkthrough   # runs out of the box

# 01/02 target a shark-routed vRPC endpoint — supply your own:
VRPC_RPC_URL=https://rpc.ankr.com/arbitrum \
VRPC_API_KEY=<your Ankr API key> \
  pnpm example:01-ethers-client
```

Environment variables for 01/02 (both skip with a hint if `VRPC_RPC_URL` /
`VRPC_API_KEY` are unset, so `pnpm example:all` stays green in CI):

| Var | Meaning | Default |
| --- | ------- | ------- |
| `VRPC_RPC_URL` | Your vRPC endpoint, e.g. `https://rpc.ankr.com/arbitrum`. The SDK owns the `_vrpc` suffix + attestation sub-route. | — (required) |
| `VRPC_API_KEY` | Ankr API key, sent as `x-api-key`. | — (required) |
| `VRPC_CHAIN_ID` | EVM chain id bound into the signed pre-image. | `42161` (Arbitrum) |

## Routing note — adapters vs. core

The **adapters** (`VrpcProvider`, `vrpcHttp`) follow the shark routing
convention: you pass `https://host/<chain>` and the SDK derives the RPC leg
(`/<chain>_vrpc`) and the attestation leg (`/<chain>_vrpc/attestation`) from it.
That is why 01/02 target a shark endpoint.

The **core walkthrough** (03) talks to a direct TDX node — set via env, no
address is hardcoded:

```sh
VRPC_NODE_URL=http://<host>:<port> \
VRPC_NODE_CHAIN_ID=42161 \
VRPC_NODE_COMPOSE_HASH=<expected> \
  pnpm example:03-vrpc-core-walkthrough
```

A direct node serves RPC at `/` and attestation at `/attestation`, so 03 drives
`vrpc-core` directly (`verifyResponse` / `fetchAttestation` / `VerifierClient`).
Without `VRPC_NODE_URL` it skips with a hint.

## What is and isn't verified

- **Ed25519 response signature** — VERIFIED (every response, fail-closed).
- **Signing key ↔ TDX enclave correlation** — VERIFIED (step 4: attestation
  pubkey must equal the response signer).
- **TDX quote cryptographic verification (DCAP/RTMR)** — **MOCK in v6.0** (frozen
  contract); real verification lands in v7.0.
- **composeHash provenance** — hard-pinned in `shared.ts` (`PINNED_COMPOSE_HASH`);
  no on-chain registry yet (DEC-03). If the sidecar is redeployed, re-pin it.
- **Node disk-layer correctness** — NOT verified (the TEE boundary covers RAM).
