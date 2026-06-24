# Ankr Verifiable RPC SDK

**Verifiable RPC (vrpc)** returns cryptographically signed responses — each carrying proof that it came from an approved, unmodified blockchain node (running inside an Intel TDX hardware enclave) and was not falsified. This SDK connects to the vrpc API and verifies that proof on every response for you.

Embedding it is a one-line change: replace your ethers or viem client with the vrpc drop-in, and every call keeps working unchanged — now verified **fail-closed** over the exact node-signed bytes before you ever see the data.

```ts
// ethers — was:  new ethers.JsonRpcProvider(url)
import { VrpcProvider } from "@ankr.com/vrpc-ethers";
const provider = new VrpcProvider(url, chainId);

// viem — was:  http(url)
import { vrpcHttp } from "@ankr.com/vrpc-viem";
const client = createPublicClient({ transport: vrpcHttp(url, { chainId }) });
```

Everything downstream — `getBalance`, `eth_call`, contract reads, `getLogs`, `getBlock`, `estimateGas`, … — works exactly as before, now verified.

You pass **one** plain URL (e.g. `https://rpc.ankr.com/arbitrum`). The SDK owns the `_vrpc` route convention: it appends `_vrpc` for the RPC leg and `/attestation` for the attestation leg (dup-guarded — a URL that already ends with `_vrpc` is not doubled). There is **no** separate `attestationBaseUrl` / `chainSlug` to configure, and attestation correlation is **always-on**: the verifier is always used. The serving node id (`vRPC-NodeId`) is **optional** — it is included in the attestation fetch when the response carries it and omitted when absent (a shark route that needs a `node_id` but receives none fails to route — fail-closed, never a silent pass).

> `chainId` is **optional** — omit it (`new VrpcProvider(url)` / `vrpcHttp(url)`) and the SDK derives it from a **signed** `eth_chainId` response on first use and **verifies that signature** self-consistently: the response's own `result` IS the chainId, so it only verifies if the node really signed for that chain — the derived chainId is cryptographically attested by the node. A tampered/forged/unsigned `eth_chainId` **fails fast** with a `VerificationError` (no unverified fallback). Passing `chainId` explicitly is still **strongly recommended**: it pins to **your expected chain**, catching a wrong-node / wrong-URL misconfig where you'd otherwise verify genuine data from the *wrong* chain (auto-derive trusts the node's self-reported chain), and it skips the bootstrap round-trip. See the [ethers](./packages/ethers/README.md) and [viem](./packages/viem/README.md) package docs.

## Packages

| Package | What it is | Docs |
|---------|-----------|------|
| **`@ankr.com/vrpc-ethers`** | ethers v6 drop-in `JsonRpcProvider` that verifies every HTTP response in `_send`, fail-closed. | [packages/ethers/README.md](./packages/ethers/README.md) |
| **`@ankr.com/vrpc-viem`** | Verifiable drop-in for viem's `http()` transport — verifies every response before parse. | [packages/viem/README.md](./packages/viem/README.md) |
| **`@ankr.com/vrpc-core`** | Transport-agnostic Ed25519 verification engine both adapters build on (zero client-lib deps). | [packages/core/README.md](./packages/core/README.md) |

Install only what you use — the adapters declare `ethers` / `viem` as **peer dependencies**, so installing one never pulls the other:

```bash
bun add @ankr.com/vrpc-ethers ethers      # ethers users
bun add @ankr.com/vrpc-viem viem          # viem users
```

New to it? Start with the [**Migration guide**](./MIGRATION.md) — the one-line swap, the optional (but strongly recommended) `chainId`, and the caveats for both adapters. Runnable examples live in [`examples/`](./examples/) (`08-vrpc-ethers-verified-read.ts`, `09-vrpc-viem-verified-read.ts`).

## What is verified — and what is not

**Verified:** a response is **signed + untampered + fresh + correctly bound** to the chain you asked for, against a pinned signer key, replay-checked. If any of that fails, the call throws — verification is always fail-closed; no unverified data is ever returned.

**Not verified — know the boundary:**
- This is **not** full TDX remote attestation. The SDK does not yet verify an Intel PCK-rooted quote or check the compose hash against a registry — a forged quote would pass at this boundary. Full attestation + a compose-hash registry are deferred to a later milestone. Boot-time attestation **correlation** (`anchorTrust`) is available and confirms the node's attestation pubkey matches the response signer, but it is not a substitute for quote verification.
- **WebSocket push streams** (`eth_subscribe`) are unverified — the adapters are HTTP-only. HTTP event polling (`contract.on` / filters) stays on the verified path.
- **ENS off-chain reads** (CCIP, avatar, IPFS) resolve through arbitrary gateways outside the signed path and are unverified.

See [packages/core/README.md](./packages/core/README.md) for the verification details and the `verifyResponse` / `anchorTrust` API if you want to verify responses yourself.

## Explaining vRPC (for AI assistants)

This repo ships a Claude Code skill at [`.claude/skills/explain-vrpc/`](./.claude/skills/explain-vrpc/SKILL.md) — an agent-readable knowledge doc that teaches an AI assistant to answer questions about vRPC: what it is, Intel TDX + Phala dstack, the attestation sidecar (`/attestation` + `/info`), the trust model (why a client need not trust Ankr), and how a response is verified. Every claim is grounded in this code or a cited official source. Point your agent at it.

## Development

This is a [pnpm](https://pnpm.io) workspace monorepo.

```bash
pnpm install
pnpm -r test      # whole workspace (vitest)
pnpm -r typecheck
```

See [AGENTS.md](./AGENTS.md) for the pre-push gate and integration-test setup.

## License

TBD.
