# @ankr.com/vrpc-viem

A **verifiable drop-in** for viem's `http(url)` transport. Swap one line and
every read your viem client already makes — `getBalance`, `readContract`,
`call`, `getLogs`, `getBlock`, `estimateGas`, `getTransactionReceipt`,
`sendRawTransaction`, … — arrives Ed25519-verified over its raw response bytes
before the value ever reaches your application code. Your action code does not
change.

`vrpcHttp` is a viem **custom transport** (built on `createTransport`) whose
`request` owns its own `fetch`, captures the raw content-decoded response bytes
**before `JSON.parse`**, and feeds them — with the exact request bytes it
POSTed — into `@ankr.com/vrpc-core`'s `verifyResponse`. Only after verification
passes is the body parsed and the result returned. Verification is
**fail-closed** by default (`strict`).

All verification logic is reused from `@ankr.com/vrpc-core` — none is copied
here, and there is no `ethers` import (manifest isolation). The error family is
re-exported from core, so it is the **same type identity** the ethers adapter
(`@ankr.com/vrpc-ethers`) re-exports: a caller cannot tell the two adapters
apart by error shape.

---

## Install

`viem` is a **peer dependency** (consumer-supplied, single instance):

```bash
bun add @ankr.com/vrpc-viem viem
```

> The `@ankr.com/vrpc-*` packages are currently `private` / unpublished while
> the API stabilises. Inside this monorepo they resolve via `workspace:*`;
> the public install name is `@ankr.com/vrpc-viem` (`peerDependency: viem ^2.52.2`).

---

## The one-line swap

```ts
// Before — plain http transport, no verification:
import { createPublicClient, http } from "viem";

const client = createPublicClient({
  transport: http("https://your-shark/arbitrum_vrpc"),
});

// After — pass the PLAIN route; the SDK appends `_vrpc` (and derives the
// `/attestation` sub-route) itself. The chain id comes from the viem client's
// `chain.id` — declare `chain` to pin YOUR chain and skip the bootstrap:
import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";
import { vrpcHttp } from "@ankr.com/vrpc-viem";

const client = createPublicClient({
  chain: arbitrum, // chain.id is bound into the signed pre-image (pins it)
  transport: vrpcHttp("https://your-shark/arbitrum", {
    headers: { "x-api-key": process.env.SHARK_API_KEY! },
  }),
});

// Or bare (no chain → derives chainId from a SIGNED, self-consistently-verified eth_chainId):
const bareClient = createPublicClient({
  transport: vrpcHttp("https://your-shark/arbitrum"),
});

// Unchanged action code — the returned value IS proof of verification.
const balance = await client.getBalance({ address: "0x0000000000000000000000000000000000000000" });
const block = await client.getBlockNumber();
```

The chain id comes from the **viem client's `chain.id`**. It is bound into the
canonical pre-image, so a wrong/substituted chain produces a different pre-image
and fails as `BadSignature`. Declaring `chain` on the client **pins YOUR
expected chain** and **skips the bootstrap** round-trip. When no `chain` is set,
the transport auto-derives the chain id from a **signed `eth_chainId` response**
on the first request, memoized so concurrent first calls share a single fetch,
and **verifies that signature self-consistently**: the response's own `result`
IS the chainId, so it only verifies if the node really signed for that chain —
the derived chainId is **cryptographically attested by the node**. A
tampered/forged (claims a chain ≠ the one it was signed for) / unsigned
`eth_chainId` **fails fast** with a `VerificationError`; there is no unverified
fallback. Declaring `chain` catches a wrong-node / wrong-URL misconfig where
auto-derive (which trusts the node's self-reported chain) would verify *genuine*
data from the *wrong* chain.

---

## Public API

```ts
export function vrpcHttp(url: string, opts?: VrpcHttpOptions): Transport<"vrpc-http">;

export interface VrpcHttpOptions { /* see table below */ }

// Shared vrpc-core error family — re-exported (SAME identity as @ankr.com/vrpc-ethers):
export { VerificationError, MissingHeader, MalformedHeader, BadSignature, StaleTimestamp };
```

### `VrpcHttpOptions`

> The pinned chain id is **not** an option — it comes from the viem client's
> `chain.id` (auto-derived from a signed `eth_chainId` when no `chain` is set).

| Option           | Type                                                          | Default                | Notes |
|------------------|---------------------------------------------------------------|------------------------|-------|
| `replayWindowMs` | `number`                                                      | vrpc-core default (60s)| Forwarded to `verifyResponse`. Omit in production. `0` only works in tests that inject `nowMs`; in production it always rejects on clock skew. |
| `headers`        | `Record<string, string>`                                      | —                      | Applied to BOTH the JSON-RPC POST and the internal attestation fetch (e.g. `x-api-key`, or the shark `chain_vrpc` route header) — a single auth set here covers both legs. `content-type: application/json` is always set by the transport. |
| `timeout`        | `number`                                                      | client-injected, else `10_000` | Per-request HTTP timeout (ms), applied to the own `fetch` as `AbortSignal.timeout` (parity with viem `http()`). |
| `fetchFn`        | `(url: string, init: RequestInit) => Promise<Response>`       | global `fetch`         | Injectable fetch seam (mirrors viem `http`'s `fetchFn`). Hook for a routing fetch wrapper or offline tests. |

#### Lazy-attestation seam options (always-on)

> [!WARNING]
> **v5.0 ships a MOCK attestation verifier — NO real attestation security until v6.0.**
> The v5.0 attestation check is a mock with `allowInsecureMock` **hard-set true**:
> it **bypasses all chain-of-trust checks** and resolves `void` **silently**
> (the SDK prints nothing) — an explicit opt-in past the hardware root of
> trust. In the contract's own words: *"v5.0 provides NO real
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
always stays on plain `verifyResponse`. The existing `headers` and `fetchFn` are
**reused** for the attestation-leg fetch (one verifier per transport — never per
call — so the pubkey cache lives for the transport lifetime).

The serving node id (`vRPC-NodeId`) is **optional**: it is included in the
attestation fetch when the response carries it and omitted when absent. A shark
route that requires a `node_id` but receives none fails to route — the fetch
errors and propagates (fail-closed).

| Option           | Type                     | Default          | Notes |
|------------------|--------------------------|------------------|-------|
| `pubkeyCacheTtlMs` | `number`               | `3_600_000` (1h) | Verified-pubkey cache TTL (ms). A second read within TTL reuses the cache and skips the attestation fetch; past TTL the pubkey is re-attested (no stale trust). |

> v6.0 removed the inert `allowlist`/`tcb`/`pccsUrl` options — the mock verifier
> ignores them. v7.0 reintroduces them for the real verifier. `headers` (above)
> stays — it covers both the RPC POST and the attestation fetch.

`fetchFn` (already documented above) feeds **both** legs — the RPC POST and the
attestation GET — which is also the offline test/example seam.

```ts
// Attestation is always-on, derived from the single URL — no attestationBaseUrl
// /chainSlug. Pass the plain route; the SDK appends `_vrpc` and `/attestation`.
const client = createPublicClient({
  chain: arbitrum, // chain.id pins the chain (skips the bootstrap)
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum", {
    headers: { "x-api-key": process.env.SHARK_API_KEY! }, // RPC + attestation auth
    pubkeyCacheTtlMs: 3_600_000,       // 1h (default)
  }),
});
// Ordinary reads. The first unknown pubkey triggers one attestation fetch +
// (MOCK) verify + cache; subsequent reads within TTL skip the fetch.
await client.getBalance({ address: "0x0000000000000000000000000000000000000000" });
```

---

## What is verified

For every HTTP JSON-RPC response that reaches your code, the transport enforces,
fail-closed, that the response is **signed + untampered + fresh + correctly
bound** against the chain id you pinned and the signing key that produced the
signature:

- **Signed** — a valid Ed25519 `vRPC-Signature`.
- **Untampered** — it verifies over the canonical 80-byte pre-image
  `chain_id ‖ sha256(request_body) ‖ sha256(response_body) ‖ timestamp_ms`; any
  mutation of request or response body fails as `BadSignature`.
- **Fresh** — `vRPC-Timestamp` inside the replay window (default 60s); a replayed
  old response is rejected as `StaleTimestamp`.
- **Correctly bound** — wrong/substituted chain id → different pre-image →
  `BadSignature`.

The transport reads `res.text()`, which transparently decodes gzip/br — the
sidecar signs the **content-decoded** body, so do not read `res.body` or pin
`Accept-Encoding: identity`.

### What is NOT verified

This is narrower than full TDX remote attestation, and the gap is intentional:

- **Full TDX quote attestation is NOT performed** here — the signature proves
  *a key you correlated* produced *exactly these bytes*, not *which enclave
  image* holds that key (Intel PCK quote verification + composeHash registry
  are deferred to the next milestone).
- **WebSocket push (`eth_subscribe`) is unverified** — the sidecar signs HTTP
  responses only; WS bypasses the signing chokepoint. Use HTTP for anything you
  need a signature on.
- **ENS off-chain reads are unverified** — CCIP-Read / avatar / IPFS fetch from
  off-chain gateways outside the signed RPC path.

---

## Error handling

> **Important caveat — recovering the typed error at the full-client level.**
> The transport hardcodes `retryCount: 0` and deliberately ignores viem's
> injected default. viem's `buildRequest` treats a thrown `VerificationError`
> as a codeless non-HTTP error and would otherwise **retry it 3×** and re-wrap
> it as an `UnknownRpcError`, masking the verify failure. With `retryCount: 0`
> the typed error propagates and a single failing action triggers exactly one
> fetch.
>
> At the **transport level** (`transport.config.request(...)`) the original
> `VerificationError` subclass is thrown directly. At the **full-client level**
> (`client.getBalance(...)`) `buildRequest` still wraps it, but preserves the
> original as `.cause`. Recover it with `err.walk`:

```ts
import { VerificationError, BadSignature } from "@ankr.com/vrpc-viem";

try {
  await client.getBalance({ address: "0x…" });
} catch (err: any) {
  // buildRequest wraps the typed error; the original is preserved as `.cause`.
  const typed =
    typeof err?.walk === "function"
      ? err.walk((e: unknown) => e instanceof VerificationError)
      : err;

  if (typed instanceof BadSignature) {
    // response body / headers / pubkey don't match the signature — fail closed.
  }
}
```

### Error mapping

| Outcome                                   | What the transport throws |
|-------------------------------------------|---------------------------|
| Tampered / forged signature               | `BadSignature` (a `VerificationError`) — fail-closed in `strict`. |
| Stripped `vRPC-*` headers (downgrade)     | `MissingHeader` (a `VerificationError`) — fail-closed. |
| Wrong chain id (signed for another chain) | `BadSignature`. |
| Signed JSON-RPC `{ error }` body          | viem's own `RpcRequestError` — **NOT** a `VerificationError` (verification passed; `buildRequest` maps it by code). |
| Unsigned non-2xx (gateway 502 / timeout)  | viem's `HttpRequestError` **before** verify — reads as a network error, not a verify attack. |
| Signed non-2xx with `{ error }` body      | still flows into verify; its signed error surfaces as an ordinary `RpcRequestError`. |

`MissingHeader`, `MalformedHeader`, `BadSignature`, and `StaleTimestamp` all
extend `VerificationError`, which extends `Error`. They are the identical
classes re-exported by `@ankr.com/vrpc-ethers` (cross-adapter parity).

### Fail-closed

Verification is always fail-closed: a `VerificationError` propagates out of the
transport `request` and no unverified data is ever returned. There is no
permissive / observe-but-not-block opt-in.

---

## Batching

Batching is **OFF by default**. Every action issues a single non-batched
`{ jsonrpc: "2.0", id: 1, method, params }` request that is verified as one
unit. Batched-as-one-unit verification is a deferred opt-in — consistent with
the ethers adapter's stance.

---

## Boot-time trust anchor (`anchorTrust`)

`anchorTrust` is an adapter-neutral, **opt-in** helper from
`@ankr.com/vrpc-core`. Call it **once at startup**, after constructing the
client. It does a fresh signed read through shark, fetches the serving node's
attestation by `vRPC-NodeId`, and correlates that attestation pubkey against
the response signer — fail-closed (throws a `VerificationError`-family member on
mismatch / stale node / missing header). It does **not** alter the transport,
and the ethers adapter calls the identical helper.

```ts
import { anchorTrust } from "@ankr.com/vrpc-core";

const anchor = await anchorTrust({
  sharkBase: "https://your-shark", // no trailing slash
  chain: "arbitrum",               // builds the <chain>_vrpc route
  chainId: 42161,
  headers: { "x-api-key": process.env.SHARK_API_KEY! },
});
// anchor.nodeId, anchor.pubkey (0x + 64 hex) — pubkey == attestation == response signer
```

---

## Runnable example

`examples/09-vrpc-viem-verified-read.ts` builds a `createPublicClient` with
`vrpcHttp`, does a real verified `getBalance` / `getBlockNumber` through a stage
shark `arbitrum_vrpc` route, then calls `anchorTrust`. It is an operator step —
the staging URL + x-api-key are supplied via env **by name only** (never
hardcoded or printed):

```sh
SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… \
  pnpm example:09-vrpc-viem-verified-read
```

See `packages/viem/test/transport.test.ts` for the full wiring suite (verified
read, tamper → `BadSignature`, unsigned → `MissingHeader`, `retryCount: 0`,
per-request batching default, cross-adapter parity).

---

## Companion

- `@ankr.com/vrpc-core` — verification primitives (`verifyResponse`,
  `VerifierClient`, `anchorTrust`, the `VerificationError` family).
- `@ankr.com/vrpc-ethers` — the same drop-in for ethers v6 (`VrpcProvider`).
- [`w3tech/verifiable-rpc-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar)
  — the Rust sidecar that produces the signed responses (wire contract `v0.2.0`).
