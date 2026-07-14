# @w3tech.io/vrpc-ethers

Verifiable RPC drop-in for **ethers v6**. `VrpcProvider` is a `JsonRpcProvider`
subclass that Ed25519-verifies **every HTTP JSON-RPC response** — over its raw,
content-decoded bytes, before `JSON.parse` — inside the single `_send`
chokepoint. Swap one constructor call and every read your app already makes is
verified, fail-closed, with no other code changes.

```ts
// before
const provider = new ethers.JsonRpcProvider(url);
// after — one line. chainId is optional (auto-derived) but strongly recommended:
const provider = new VrpcProvider(url, chainId);
// or, bare-url (derives chainId from a SIGNED, self-consistently-verified eth_chainId):
const provider = new VrpcProvider(url);
```

Because the override is `JsonRpcApiProvider._send` — the one method every
JSON-RPC call funnels through — **all** of these are verified unchanged:
`getBalance`, `eth_call` (incl. `Contract` / `Interface` view reads),
`getLogs`, `getBlock`, `estimateGas`, `getTransactionReceipt`, raw-tx broadcast
(`eth_sendRawTransaction`), and ethers' HTTP event polling
(`eth_getLogs` / `eth_getFilterChanges`). A returned value **is** the proof the
bytes were verified; anything that fails verification throws instead of
returning.

## Trust boundary (read this first)

What you get for each **HTTP** response is: **signed + untampered + fresh +
bound against a pinned key** — i.e. *a key you correlated produced exactly these
bytes, recently, for the chain id you pinned*. That is **narrower** than full
remote attestation. Specifically:

- **Full TDX remote attestation is NOT performed.** The signing key is *not yet*
  proven to chain to an Intel PCK root, and there is no compose-hash registry
  check (both deferred). `TrustedVerifier` lazily correlates each new response
  signer against the serving node's attestation pubkey — it does not validate
  the TDX quote against an Intel PCK root locally.
- **WebSocket push is NOT verified.** `eth_subscribe` / WS push bypasses the HTTP
  signing chokepoint. Use HTTP polling for anything you need a signature on.
- **ENS off-chain reads are NOT verified.** CCIP-Read / avatar / IPFS resolution
  fetch from off-chain gateways outside the signed RPC path.

## Install

Published to npm as `@w3tech.io/vrpc-ethers` (inside this monorepo it resolves
via `workspace:*`):

```sh
pnpm add @w3tech.io/vrpc-ethers ethers
```

`ethers` is a **peerDependency** (`^6.16.0`) — supply a single instance from your
app; the adapter never bundles its own. All verification logic is reused from
`@w3tech.io/vrpc-core` (no crypto copied here).

## Quick usage

```ts
import { VrpcProvider, VerificationError } from "@w3tech.io/vrpc-ethers";
import { FetchRequest } from "ethers";

// Auth (x-api-key) rides on a FetchRequest — the same mechanism ethers uses for
// header injection. VrpcOptions extends JsonRpcApiProviderOptions, so a
// FetchRequest passes straight through to the underlying connection.
// Pass the plain URL — the SDK appends `_vrpc` (and derives `/attestation`).
const req = new FetchRequest("https://rpc.ankr.com/arbitrum");
req.setHeader("x-api-key", process.env.ANKR_API_KEY!);

const provider = new VrpcProvider(req, 42161); // chainId bound into the signature as "42161"

try {
  const balance = await provider.getBalance("0x0000000000000000000000000000000000000000");
  // balance is verified: it only reaches here AFTER in-_send Ed25519 verification.
  console.log(balance.toString());
} catch (err) {
  if (err instanceof VerificationError) {
    // tampered / unsigned / stale / wrong-chain → fail-closed, no value returned
    console.error("response failed verification:", err);
  } else {
    throw err; // ordinary ethers RPC / network error
  }
}
```

## API

### `class VrpcProvider extends JsonRpcProvider`

```ts
// single signature — chainId is an optional positional arg:
new VrpcProvider(url: string | FetchRequest, chainId?: number | bigint | string, options?: VrpcOptions)
```

- **`url`** — node/proxy URL or a `FetchRequest` (use the latter to attach
  `x-api-key` or other headers).
- **`chainId`** — `number | bigint | string`, **optional but strongly
  recommended**. The signed pre-image binds a chain-id **string** (the exact
  value the sidecar is configured with); `number`/`bigint` args normalize to the
  decimal string immediately (`42161` → `"42161"`, via `BigInt().toString(10)` —
  no `number` round-trip, so ids beyond `Number.MAX_SAFE_INTEGER` bind exactly).
  A string arg is validated (`InvalidChainId` at construction on empty /
  whitespace / >64 bytes / non-printable-ASCII) and bound verbatim — non-EVM
  chains pass the exact configured string (e.g. TON's global id `"-239"`).
  The chain-id string is hashed into the 104-byte pre-image; version gate: SDK
  `>=0.3.0` requires sidecar `>=0.5.0` (older sidecars sign the legacy
  pre-image and verification fails closed).
  - **Explicit (recommended)** — `new VrpcProvider(url, chainId)`. For an
    all-decimal id the constructor pins it as a static network
    (`staticNetwork: true`) so the provider issues **zero** `eth_chainId`
    round-trips; this only skips the round-trip and does not weaken the
    signature binding. It also pins to **your expected chain**, catching a
    wrong-node / wrong-URL misconfig where auto-derive (which trusts the node's
    self-reported chain) would happily verify *genuine* data from the *wrong*
    chain. A non-decimal (CAIP-2 style) id cannot be represented as an ethers
    network, so no network arg is pinned — the verifier still binds the exact
    string. To pass options without pinning a chain id, use
    `new VrpcProvider(url, undefined, { ... })`.
  - **Omitted (auto-derive)** — `new VrpcProvider(url)`. On first use the
    provider derives the chain id from a **signed `eth_chainId` response**,
    memoized so concurrent first calls share a single fetch, and **verifies that
    signature self-consistently**: the response's own `result` IS the chainId, so
    it only verifies if the node really signed for that chain — the derived
    chainId is **cryptographically attested by the node**. A tampered/forged
    (claims a chain ≠ the one it was signed for) / unsigned `eth_chainId` **fails
    fast** with a `VerificationError`; there is no unverified fallback. Prefer the
    explicit form to remove the round-trip and to pin your expected chain.

The constructor is **synchronous** and never performs I/O or verification —
verification (and the lazy, self-consistently-verified bootstrap, if any) happens
per-call inside `_send`.

### `interface VrpcOptions extends JsonRpcApiProviderOptions`

`VrpcOptions` is a **superset** of ethers' `JsonRpcApiProviderOptions`: every
stock knob (`batchMaxCount`, `batchStallTime`, `polling`, …) is preserved and
passed through to `super(...)` unchanged. The vRPC-specific fields:

| Field            | Type                                  | Default          | Meaning |
| ---------------- | ------------------------------------- | ---------------- | ------- |
| `replayWindowMs` | `number`                              | vrpc-core (60s)  | Freshness window forwarded to `verifyResponse`. Omit in production. Do **not** set `0` outside fixture tests — it always rejects on clock skew. |

Spread order is enforced so `staticNetwork` cannot be overridden away.

#### Lazy-attestation seam options (always-on)

> [!NOTE]
> Hardware attestation is **always-on and fail-closed**. By default
> `TrustedVerifier` wires the real Phala CloudVerifier (`createCloudVerifier()`,
> via vrpc-core's `buildVerifyPolicy`); it **cannot be disabled**. Override the
> internal `hardwareVerifier` option only to point at a self-hosted endpoint, a
> future local-DCAP verifier, or a no-network test mock. The `report_data →
> pubkey/nonce` binding check (CHK-A1) runs unconditionally; the compose-hash
> self-consistency check (CHK-A2) runs best-effort when the node returns both
> `app_compose` and `compose_hash`. Full local DCAP, RTMR3 event-log replay, an
> independent compose source, and TCB-status policy are still evolving (see root
> README) — today's hardware verdict comes from the Phala cloud verify API, not
> local DCAP.

The normal verify routes through `@w3tech.io/vrpc-core`'s `TrustedVerifier`,
which lazily fetches + correlates the serving node's TDX attestation on an
**unknown** signing pubkey and **caches** the verified pubkey (configurable TTL,
default 1h). This is **always-on**: the attestation endpoint is **derived from
the single URL** you pass (the SDK appends `_vrpc` and the `/attestation`
sub-route, dup-guarded), so there is **no** `attestationBaseUrl` / `chainSlug`
to set and no opt-out — verification is fail-closed. The chainId bootstrap
always stays on plain `verifyResponse`.

The serving node id (`vRPC-NodeId`) is **optional**: it is included in the
attestation fetch when the response carries it and omitted when absent. A gateway
route that requires a `node_id` but receives none fails to route — the fetch
errors and propagates (fail-closed).

| Field            | Type                         | Default          | Meaning |
| ---------------- | ---------------------------- | ---------------- | ------- |
| `pubkeyCacheTtlMs` | `number`                   | `3_600_000` (1h) | Verified-pubkey cache TTL (ms). A second read within TTL reuses the cache and skips the attestation fetch; past TTL the pubkey is re-attested (no stale trust). |

> Auth/headers: set them on the `FetchRequest` you pass as the URL
> (`req.setHeader("x-api-key", …)`) — those cover BOTH the RPC POST and the
> attestation fetch. (v6.0 removed the inert `allowlist`/`tcb`/`pccsUrl` options —
> they were trust-anchor knobs the verifier does not yet consume — and the
> redundant `headers` option; v7.0 reintroduces the trust-anchor options for
> local-DCAP verification.)

```ts
// Auth the idiomatic ethers way: set it on the FetchRequest. The SDK reuses
// those headers for BOTH the RPC POST and the internal attestation fetch — there
// is no separate apiKey option. Attestation is always-on, derived from the URL.
const req = new FetchRequest("https://rpc.ankr.com/arbitrum");
req.setHeader("x-api-key", process.env.ANKR_API_KEY); // covers both legs (never logged)
const provider = new VrpcProvider(req, 42161, {
  pubkeyCacheTtlMs: 3_600_000, // 1h (default)
});
// Ordinary reads. The first unknown pubkey triggers one attestation fetch +
// hardware verify + cache; subsequent reads within TTL skip the fetch.
await provider.getBalance("0x0000000000000000000000000000000000000000");
```

### Re-exported error family

For `instanceof` checks without importing core directly, the shared error family
is re-exported: `VerificationError` (base) and `BadSignature`, `MissingHeader`,
`MalformedHeader`, `StaleTimestamp`. This is the same family the viem adapter
reuses — one error family across both adapters.

## Batching

Native ethers batching is **preserved** — there is no `batchMaxCount=1` override.
When ethers coalesces concurrent calls into one array payload, the **entire body
is verified once** over the raw bytes, and ethers' drain loop correlates the
array results back to each caller by id. Set `batchMaxCount` / `batchStallTime`
exactly as you would on a stock `JsonRpcProvider`.

## Error handling

- **Tampered or wrong-chain response** → `BadSignature`.
- **Unsigned response** (missing required `vRPC-*` headers, or empty body) →
  `MissingHeader` — broadcast and poll paths are **not** exempt; nothing is
  special-cased around verification.
- **Stale signed timestamp** → `StaleTimestamp`.
- **Signed JSON-RPC `{error}`** (e.g. `execution reverted`) → the signature
  verifies first, then ethers surfaces an **ordinary RPC error** — it is *not*
  downgraded into or confused with a `VerificationError`.
- **HTTP 4xx/5xx** → ethers `SERVER_ERROR` (from `assertOk`), never a
  `VerificationError`.

Verification is always fail-closed: a `VerificationError` propagates out of
`_send` and no unverified value is ever returned. Non-`VerificationError`s
propagate too.

```ts
import { BadSignature, MissingHeader, VerificationError } from "@w3tech.io/vrpc-ethers";

try {
  await provider.getLogs({ address, fromBlock });
} catch (err) {
  if (err instanceof BadSignature) {/* bytes tampered / wrong chain */}
  else if (err instanceof MissingHeader) {/* response was unsigned */}
  else if (err instanceof VerificationError) {/* stale / malformed header */}
  else throw err; // ethers RPC or network error
}
```

## Caveats

- **HTTP-only verification.** WebSocket subscriptions (`eth_subscribe`) are
  unverified. Verification is over the raw node-signed bytes *before*
  `JSON.parse`; the WS push transport has no such chokepoint.
- **ENS off-chain reads** (CCIP-Read, avatar, IPFS) are unverified — they leave
  the signed RPC path.
- The lazy attestation correlation binds the signer to the node's attestation
  pubkey; it does **not** verify the TDX quote against an Intel PCK root or a
  compose-hash registry (deferred).

## Runnable example

[`examples/01-ethers-client.ts`](../../examples/01-ethers-client.ts) is the
drop-in `VrpcProvider` demo — a verified read against the public Arbitrum vRPC
endpoint (no API key required):

```sh
pnpm example:01-ethers-client
```

For the attestation-correlation flow end-to-end, see
[`examples/03-vrpc-core-walkthrough.ts`](../../examples/03-vrpc-core-walkthrough.ts):

```sh
pnpm example:03-vrpc-core-walkthrough
```
