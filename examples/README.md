# Examples

Three runnable examples for the verifiable-rpc-sdk. All target Ankr's public
Arbitrum vRPC endpoint and need no API key.

| # | Script | What it shows |
| - | ------ | ------------- |
| 01 | `01-ethers-client.ts` | Drop-in **ethers** provider (`VrpcProvider`) — `getBlock` / `getBalance`, every response verified before ethers returns it. |
| 02 | `02-viem-client.ts` | Drop-in **viem** transport (`vrpcHttp`) wired into `createPublicClient` — the same calls, verified inside the transport. |
| 03 | `03-vrpc-core-walkthrough.ts` | Step-by-step **`@ankr.com/vrpc-core`**: signed wire → `verifyResponse` → tamper→`BadSignature` → `fetchAttestation` + correlation → `VerifierClient`. |

## Run

```sh
pnpm install
pnpm example:all
```

To point at a different chain, edit the URL (`https://rpc.ankr.com/<chain>/<key>`)
and chain id in the example. The adapters own the `_vrpc` suffix and attestation
sub-route; pass `https://host/<chain>/<key>` and the SDK derives the rest.

## What is and isn't verified

- **Ed25519 response signature** — VERIFIED (every response, fail-closed).
- **Signing key ↔ TDX enclave correlation** — VERIFIED (attestation pubkey must
  equal the response signer).
- **TDX quote cryptographic verification (DCAP/RTMR)** — **MOCK in v6.0** (frozen
  contract); real verification lands in v7.0.
- **Node disk-layer correctness** — NOT verified (the TEE boundary covers RAM).
