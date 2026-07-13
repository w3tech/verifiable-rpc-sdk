# Examples

Three runnable examples for the verifiable-rpc-sdk. All target Ankr's public
Arbitrum vRPC endpoint and need no API key.

| # | Script | What it shows |
| - | ------ | ------------- |
| 01 | `01-ethers-client.ts` | Drop-in **ethers** provider (`VrpcProvider`) — `getBlock` / `getBalance`, every response verified before ethers returns it. |
| 02 | `02-viem-client.ts` | Drop-in **viem** transport (`vrpcHttp`) wired into `createPublicClient` — the same calls, verified inside the transport. |
| 03 | `03-vrpc-core-walkthrough.ts` | Step-by-step **`@w3tech.io/vrpc-core`**: signed wire → `verifyResponse` → tamper→`BadSignature` → `fetchAttestation` + correlation → `TrustedVerifier`. |

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
- **TDX DCAP quote verdict** — VERIFIED by default. The SDK runs an always-on
  hardware verifier (`createCloudVerifier`, the Phala cloud verifier wired
  mandatory by `buildVerifyPolicy`), which asserts the DCAP verdict
  (`quote.verified === true`) and binds the quote to the response signer
  (`report_data == pubkey‖nonce`). Fail-closed (`CHK-P1`); point it at a
  self-hosted endpoint to avoid the public Phala egress.
- **Local DCAP replay, RTMR event-log replay, independent compose source, and
  TCB-status policy** — NOT yet implemented. The hardware verdict today comes
  from the remote cloud verifier, not local DCAP; full local quote verification
  and RTMR3 anchoring are future work (the SDK is evolving toward a full local
  chain of trust).
- **Node disk-layer correctness** — NOT verified (the TEE boundary covers RAM).
