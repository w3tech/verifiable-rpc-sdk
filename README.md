# Ankr Verifiable RPC SDK

**Verifiable RPC (vrpc)** returns cryptographically signed responses — each carrying proof that it came from an approved, unmodified blockchain node (running inside an Intel TDX hardware enclave) and was not falsified. This SDK connects to the vrpc API and verifies that proof on every response for you.

Embedding it is a one-line change: replace your ethers or viem client with the vrpc drop-in, and every call keeps working unchanged — now verified **fail-closed** over the exact node-signed bytes before you ever see the data.

```ts
// ethers — was:  new ethers.JsonRpcProvider(url)
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
const provider = new VrpcProvider(url, chainId);

// viem — was:  http(url)
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
import { arbitrum } from "viem/chains";
const client = createPublicClient({ chain: arbitrum, transport: vrpcHttp(url) });
```

Everything downstream — `getBalance`, `eth_call`, contract reads, `getLogs`, `getBlock`, `estimateGas`, … — works exactly as before, now verified.

**Start here:** the [Quickstart and how-it-works guide](./docs/quickstart.md) covers what vRPC proves, the attestation flow, and running the SDK. Building an AI agent? Point it at the [`explain-vrpc` skill](./.claude/skills/explain-vrpc/SKILL.md).

You pass **one** URL — the explicit vRPC route (e.g. `https://rpc.ankr.com/arbitrum_vrpc`). The SDK uses it verbatim for the RPC leg and derives only the `/attestation` sub-route for the attestation leg. There is **no** separate `attestationBaseUrl` / `chainSlug` to configure, and attestation correlation is **always-on**: the verifier is always used. The serving node id (`vRPC-NodeId`) is **optional** — it is included in the attestation fetch when the response carries it and omitted when absent (a gateway route that needs a `node_id` but receives none fails to route — fail-closed, never a silent pass).

> `chainId` is **optional** — omit it (`new VrpcProvider(url)` / `vrpcHttp(url)`) and the SDK derives it from a **signed** `eth_chainId` response on first use and **verifies that signature** self-consistently: the response's own `result` IS the chainId, so it only verifies if the node really signed for that chain — the derived chainId is cryptographically attested by the node. A tampered/forged/unsigned `eth_chainId` **fails fast** with a `VerificationError` (no unverified fallback). Passing `chainId` explicitly is still **strongly recommended**: it pins to **your expected chain**, catching a wrong-node / wrong-URL misconfig where you'd otherwise verify genuine data from the *wrong* chain (auto-derive trusts the node's self-reported chain), and it skips the bootstrap round-trip. See the [ethers](./packages/ethers/README.md) and [viem](./packages/viem/README.md) package docs.

The chain id bound into every signature is a **string** — the exact value the sidecar is configured with. The adapters accept `number | bigint | string` for ergonomics and normalize `number`/`bigint` args to the decimal string immediately (`42161` → `"42161"`); non-EVM chains pass the exact configured string (e.g. TON's global id `"-239"`, or Stellar's network id — the sha256 of its mainnet passphrase, a 64-char hex string). vRPC is not JSON-RPC-only: responses from path-based REST chains (e.g. TON's REST API, Stellar Horizon) reached via `https://rpc.ankr.com/rest/<chain>/<path>` carry the same `vRPC-*` headers signed over the same 104-byte pre-image, and are verifiable with `@w3tech.io/vrpc-core`'s transport-agnostic `verifyResponse` (hand it the exact request-body bytes — empty for a `GET`); the ethers/viem drop-ins remain JSON-RPC adapters. **Version gate:** SDK `>=0.3.0` pairs with sidecar `>=0.5.0` (string chain id, 104-byte pre-image); older sidecars sign the legacy format and verification fails closed.

## Packages

| Package | What it is | Docs |
|---------|-----------|------|
| **`@w3tech.io/vrpc-ethers`** | ethers v6 drop-in `JsonRpcProvider` that verifies every HTTP response in `_send`, fail-closed. | [packages/ethers/README.md](./packages/ethers/README.md) |
| **`@w3tech.io/vrpc-viem`** | Verifiable drop-in for viem's `http()` transport — verifies every response before parse. | [packages/viem/README.md](./packages/viem/README.md) |
| **`@w3tech.io/vrpc-core`** | Transport-agnostic Ed25519 verification engine both adapters build on (zero client-lib deps). | [packages/core/README.md](./packages/core/README.md) |
| **`@w3tech.io/vrpc-proxy`** | Local verifying reverse proxy — point any plain HTTP client at it; every response verified fail-closed. Runs standalone via `npx @w3tech.io/vrpc-proxy` or `docker run ghcr.io/w3tech/vrpc-proxy` (see the package README). | [packages/proxy/README.md](./packages/proxy/README.md) |

Install only what you use — the adapters declare `ethers` / `viem` as **peer dependencies**, so installing one never pulls the other:

```bash
pnpm add @w3tech.io/vrpc-ethers ethers     # ethers users
pnpm add @w3tech.io/vrpc-viem viem         # viem users
```

New to it? Start with the [**Migration guide**](./MIGRATION.md) — the one-line swap, the optional (but strongly recommended) `chainId`, and the caveats for both adapters. Runnable examples live in [`examples/`](./examples/): `01-ethers-client.ts`, `02-viem-client.ts`, `03-vrpc-core-walkthrough.ts`, `04-proxy.ts`. Run them with `pnpm example:01-ethers-client` (and `:02-viem-client`, `:03-vrpc-core-walkthrough`, `:04-proxy`).

## What is verified — and what is not

**Verified:** a response is **signed + untampered + fresh + correctly bound** to the chain you asked for, against a pinned signer key, replay-checked. If any of that fails, the call throws — verification is always fail-closed; no unverified data is ever returned.

> **Where this sits on Phala's attestation path:** the SDK implements the **minimal end-to-end verification** flow — nonce-bound quote fetch, the hardware-signature verdict (mandatory, always-on cloud verifier), and binding it to the response signer + compose hash — described in Phala's [verification guide](https://docs.phala.com/phala-cloud/attestation/verification-guide). It is evolving toward the **full [chain of trust](https://docs.phala.com/phala-cloud/attestation/chain-of-trust)** — local DCAP quote verification, RTMR replay, and TCB-status policy.

**Not verified — know the boundary:**
- This is **not yet** full *local* TDX attestation. On the default path the DCAP quote **is** verified: a **mandatory, always-on** cloud verifier (Phala by default, overridable to a self-hosted endpoint) checks the quote and binds it to the response signer pubkey, nonce, and compose hash — **fail-closed**, so a forged quote is rejected. Still deferred: verifying the quote **locally** against the Intel PCK root (the default verdict is delegated to a remote service), RTMR event-log replay, a **node-independent** compose-hash source (today's compose-hash check is self-consistency only), and TCB-status policy. The default Phala endpoint is public / no-SLA and publishes submitted quotes — point the verifier at a self-hosted endpoint to avoid that egress.
- **WebSocket push streams** (`eth_subscribe`) are unverified — the adapters are HTTP-only. HTTP event polling (`contract.on` / filters) stays on the verified path.
- **ENS off-chain reads** (CCIP, avatar, IPFS) resolve through arbitrary gateways outside the signed path and are unverified.

See [packages/core/README.md](./packages/core/README.md) for the verification details and the `verifyResponse` API if you want to verify responses yourself.

## Watch it work — opt-in debug logging

The SDK is **silent by default**. The easiest way to *see how vRPC verifies a response* is to inject a logger — at debug level it prints one line per verification step. Pass `logger: createConsoleLogger()` (from `@w3tech.io/vrpc-core`) through either adapter:

```ts
import { createConsoleLogger } from "@w3tech.io/vrpc-core";
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";

const provider = new VrpcProvider("https://rpc.ankr.com/eth_vrpc", 1, {
  logger: createConsoleLogger(),
});
// viem: vrpcHttp(url, { headers, logger: createConsoleLogger() })
```

You'll see the flow in order: `verify.start` → `preimage.computed` → `signature.checked` → `timestamp.checked` → `cache.lookup` → `attestation.fetch` → `attestation.correlation` → `attestation.received` → `attestation.fieldChecks` → `hardware.verify` → `cache.store` (first request runs the full attestation + hardware verify; later requests hit the pubkey cache). It is **observability only** — never throws-through, logs only `vrpc-*` headers (byte fields truncated), and never part of the verify decision. Full event table in [packages/core/README.md](./packages/core/README.md#debug-logging-opt-in--watch-vrpc-verify-a-response).

## Explaining vRPC (for AI assistants)

This repo ships a Claude Code skill at [`.claude/skills/explain-vrpc/`](./.claude/skills/explain-vrpc/SKILL.md) — an agent-readable knowledge doc that teaches an AI assistant to answer questions about vRPC: what it is, Intel TDX + Phala dstack, the attestation sidecar (`/attestation`), the trust model (why a client need not trust Ankr), and how a response is verified. Every claim is grounded in this code or a cited official source. Point your agent at it.

## Development

This is a [pnpm](https://pnpm.io) workspace monorepo.

```bash
pnpm install
pnpm -r test      # whole workspace (vitest)
pnpm -r typecheck
```

See [AGENTS.md](./AGENTS.md) for the pre-push gate and integration-test setup.

## License

Apache-2.0 © Web3 Technologies, Inc. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
