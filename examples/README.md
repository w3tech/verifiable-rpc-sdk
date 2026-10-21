# Examples

Runnable examples for the verifiable-rpc-sdk. All target Ankr's public
Arbitrum vRPC endpoint.

| # | Script | What it shows |
| - | ------ | ------------- |
| 01 | `01-ethers-client.ts` | Drop-in **ethers** provider (`VrpcProvider`) — `getBlock` / `getBalance`, every response verified before ethers returns it. |
| 02 | `02-viem-client.ts` | Drop-in **viem** transport (`vrpcHttp`) wired into `createPublicClient` — the same calls, verified inside the transport. |
| 03 | `03-vrpc-core-walkthrough.ts` | Step-by-step **`@w3tech.io/vrpc-core`**: signed wire → `verifyResponse` → tamper→`BadSignature` → `fetchAttestation` → `TrustedVerifier`. |
| 04 | `04-proxy.ts` | Local verifying **proxy** (`@w3tech.io/vrpc-proxy`) spawned as a child process — a plain `fetch` client with zero SDK imports gets fail-closed-verified responses. |

## Run

```sh
pnpm install
ANKR_API_KEY=<your key> pnpm example:all   # key optional — see note below
```

Examples 01-03 send the key as an `x-api-key` header; 04 passes it to the proxy
with `--api-key`. Without `ANKR_API_KEY`, example 04 still runs end-to-end and
demonstrates the proxy's fail-closed refusal instead of a verified-success result.

To point at a different chain, edit the URL (`https://rpc.ankr.com/<chain>_vrpc`)
and chain id in the example. The URL is the explicit vRPC route, used verbatim
for RPC; the adapters derive only the `/attestation` sub-route from it.

## What is and isn't verified

- **Ed25519 response signature** — VERIFIED (every response, fail-closed).
- **Signing key ↔ TDX enclave correlation** — VERIFIED (attestation pubkey must
  equal the response signer).
- **TDX DCAP quote verdict** — VERIFIED by default. The SDK runs an always-on
  hardware verifier (`createCloudVerifier`, the Phala cloud verifier, wired by
  default), which asserts the DCAP verdict
  (`quote.verified === true`) and binds the quote to the response signer
  (`report_data == pubkey‖nonce`). Fail-closed: a rejected quote is
  `AttestationFailed` (`chkId` `CHK-P1`), a verifier outage is
  `AttestationUnavailable` (reason `verifier`). Point it at a self-hosted
  endpoint to avoid the public Phala egress.
- **Local DCAP replay, RTMR event-log replay, independent compose source, and
  TCB-status policy** — NOT yet implemented. The hardware verdict today comes
  from the remote cloud verifier, not local DCAP; full local quote verification
  and RTMR3 anchoring are future work (the SDK is evolving toward a full local
  chain of trust).
- **Node disk-layer correctness** — NOT verified (the TEE boundary covers RAM).
