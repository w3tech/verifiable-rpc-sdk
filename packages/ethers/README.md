# @ankr.com/vrpc-ethers

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
  check (both deferred). `anchorTrust` correlates the response signer against the
  serving node's attestation pubkey — it does not validate the TDX quote itself.
- **WebSocket push is NOT verified.** `eth_subscribe` / WS push bypasses the HTTP
  signing chokepoint. Use HTTP polling for anything you need a signature on.
- **ENS off-chain reads are NOT verified.** CCIP-Read / avatar / IPFS resolution
  fetch from off-chain gateways outside the signed RPC path.

## Install

Packages are private/unpublished today — consume via the workspace
(`workspace:*`). The intended public install once published:

```sh
bun add @ankr.com/vrpc-ethers ethers
```

`ethers` is a **peerDependency** (`^6.16.0`) — supply a single instance from your
app; the adapter never bundles its own. All verification logic is reused from
`@ankr.com/vrpc-core` (no crypto copied here).

## Quick usage

```ts
import { VrpcProvider, VerificationError } from "@ankr.com/vrpc-ethers";
import { FetchRequest } from "ethers";

// Auth (x-api-key) rides on a FetchRequest — the same mechanism ethers uses for
// header injection. VrpcOptions extends JsonRpcApiProviderOptions, so a
// FetchRequest passes straight through to the underlying connection.
// Pass the plain URL — the SDK appends `_vrpc` (and derives `/attestation`).
const req = new FetchRequest("https://rpc.ankr.com/arbitrum");
req.setHeader("x-api-key", process.env.ANKR_API_KEY!);

const provider = new VrpcProvider(req, 42161n); // chainId bound into the signature

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
new VrpcProvider(url: string | FetchRequest, chainId?: number | bigint, options?: VrpcOptions)
```

- **`url`** — node/proxy URL or a `FetchRequest` (use the latter to attach
  `x-api-key` or other headers).
- **`chainId`** — `number | bigint`, **optional but strongly recommended**.
  Bound into the signed pre-image. Coerced with `BigInt()` *without* a `number`
  round-trip, so chain ids beyond `Number.MAX_SAFE_INTEGER` (2^53−1) bind exactly
  — no precision loss, no false `BadSignature`.
  - **Explicit (recommended)** — `new VrpcProvider(url, chainId)`. The
    constructor pins this as a static network (`staticNetwork: true`) so the
    provider issues **zero** `eth_chainId` round-trips; this only skips the
    round-trip and does not weaken the signature binding. It also pins to **your
    expected chain**, catching a wrong-node / wrong-URL misconfig where
    auto-derive (which trusts the node's self-reported chain) would happily
    verify *genuine* data from the *wrong* chain. To pass options without pinning
    a chain id, use `new VrpcProvider(url, undefined, { ... })`.
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
| `chainId`        | `number \| bigint`                    | auto-derived     | Optional alternative to the positional 2nd arg. Strongly recommended — pins to **your expected chain** and skips the `eth_chainId` bootstrap. Omit → derived lazily from a **signed, self-consistently-verified** `eth_chainId` response on first use (tampered/forged/unsigned → fail-fast `VerificationError`, no unverified fallback). |
| `replayWindowMs` | `number`                              | vrpc-core (60s)  | Freshness window forwarded to `verifyResponse`. Omit in production. Do **not** set `0` outside fixture tests — it always rejects on clock skew. |

Spread order is enforced so `staticNetwork` cannot be overridden away.

#### Lazy-attestation seam options (always-on)

> [!WARNING]
> **v5.0 ships a MOCK attestation verifier — NO real attestation security until v6.0.**
> The v5.0 attestation check is a mock with `allowInsecureMock` **hard-set true**:
> it **bypasses all chain-of-trust checks** and prints a loud `console.warn` on
> every attestation. In the contract's own words: *"v5.0 provides NO real
> attestation security (real verification lands in v6.0)."* Real
> DCAP/RTMR/compose-hash verification arrives in v6.0; never rely on v5.0
> attestation for production trust.

The normal verify routes through `@ankr.com/vrpc-core`'s `TrustedVerifier`,
which lazily fetches + correlates the serving node's TDX attestation on an
**unknown** signing pubkey and **caches** the verified pubkey (configurable TTL,
default 1h). This is **always-on**: the attestation endpoint is **derived from
the single URL** you pass (the SDK appends `_vrpc` and the `/attestation`
sub-route, dup-guarded), so there is **no** `attestationBaseUrl` / `chainSlug`
to set and no opt-out — verification is fail-closed. The chainId bootstrap
always stays on plain `verifyResponse`.

The serving node id (`vRPC-NodeId`) is **optional**: it is included in the
attestation fetch when the response carries it and omitted when absent. A shark
route that requires a `node_id` but receives none fails to route — the fetch
errors and propagates (fail-closed).

| Field            | Type                         | Default          | Meaning |
| ---------------- | ---------------------------- | ---------------- | ------- |
| `pubkeyCacheTtlMs` | `number`                   | `3_600_000` (1h) | Verified-pubkey cache TTL (ms). A second read within TTL reuses the cache and skips the attestation fetch; past TTL the pubkey is re-attested (no stale trust). |
| `allowlist`      | `PinnedAllowlist`            | empty            | Pinned trust anchors for the attestation `VerifyPolicy`. The v5.0 mock does not inspect it; defaults to an empty allowlist. |
| `tcb`            | `TcbPolicy`                  | core default     | DCAP TCB acceptance policy forwarded to the attestation `VerifyPolicy`. |
| `pccsUrl`        | `string`                     | —                | Operational collateral source for dcap-qvl (NOT a trust dependency). |
| `headers`        | `Record<string, string>`     | —                | Override headers for the **attestation-leg** fetch only. Auth normally comes from the `FetchRequest` you pass as the URL (`req.setHeader("x-api-key", …)`), which already covers both the RPC POST and the attestation fetch; use `headers` only when the attestation leg needs a different/extra header. **SECRET — never logged.** |

```ts
// Auth the idiomatic ethers way: set it on the FetchRequest. The SDK reuses
// those headers for BOTH the RPC POST and the internal attestation fetch — there
// is no separate apiKey option. Attestation is always-on, derived from the URL.
const req = new FetchRequest("https://rpc.ankr.com/arbitrum");
req.setHeader("x-api-key", process.env.ANKR_API_KEY); // covers both legs (never logged)
const provider = new VrpcProvider(req, 42161n, {
  pubkeyCacheTtlMs: 3_600_000, // 1h (default)
});
// Ordinary reads. The first unknown pubkey triggers one attestation fetch +
// (MOCK) verify + cache; subsequent reads within TTL skip the fetch.
await provider.getBalance("0x0000000000000000000000000000000000000000");
```

### `anchorTrust(...)` — opt-in boot-time trust anchor (from `@ankr.com/vrpc-core`)

After constructing the provider, optionally call `anchorTrust` **once** at
startup to confirm the serving node's attestation pubkey == the response
signer's pubkey, end-to-end through shark. It is adapter-neutral, does **not**
alter the (sync) constructor, and **throws a `VerificationError`-family member on
failure** (fail-closed).

```ts
import { anchorTrust } from "@ankr.com/vrpc-core";

const anchor = await anchorTrust({
  sharkBase: "https://rpc.ankr.com",
  chain: "arbitrum",
  chainId: 42161n,
  headers: { "x-api-key": process.env.ANKR_API_KEY },
});
console.log(anchor.nodeId, anchor.pubkey); // pubkey: 0x + 64 hex
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
import { BadSignature, MissingHeader, VerificationError } from "@ankr.com/vrpc-ethers";

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
- `anchorTrust` correlates the signer against the node's attestation pubkey; it
  does **not** verify the TDX quote against an Intel PCK root or a compose-hash
  registry (deferred).

## Runnable example

[`examples/08-vrpc-ethers-verified-read.ts`](../../examples/08-vrpc-ethers-verified-read.ts)
does a real verified read + `anchorTrust` correlation through a stage shark
`arbitrum_vrpc` route. It is an operator step (needs live creds via env):

```sh
SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… \
  pnpm example:08-vrpc-ethers-verified-read
```

Both env vars are read **by name** only — their values are never printed or
logged.
