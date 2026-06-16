# Migration guide — drop-in verifiable RPC for ethers and viem

Both adapters are **one-line swaps**. You keep your existing ethers `Provider` /
viem `Client` API surface unchanged; every HTTP JSON-RPC response now arrives
Ed25519-verified over its raw content-decoded bytes before the value reaches
your code. In the default `strict` mode a verification failure is thrown, never
silently passed through.

Before you rely on the signature, read the README's
[What is verified / What is NOT verified](./README.md#what-is-verified--what-is-not-verified)
section — the trust boundary is **signed + untampered + fresh + correctly bound**,
NOT full TDX quote attestation.

---

## 1. The one-line swap

### ethers v6

```ts
// Before
import { JsonRpcProvider } from "ethers";
const provider = new JsonRpcProvider(url);

// After — chainId optional (auto-derived) but strongly recommended:
import { VrpcProvider } from "@ankr.com/vrpc-ethers";
const provider = new VrpcProvider(url, chainId);
// or bare-url (auto-derives chainId on first use):
const auto = new VrpcProvider(url);
```

`VrpcProvider extends JsonRpcProvider`. Everything downstream — `getBalance`,
`call`, `getBlock`, `getLogs`, `broadcastTransaction`, contract reads, polling —
is unchanged; the only override is the internal HTTP chokepoint (`_send`), which
verifies the raw response bytes before parsing.

### viem

```ts
// Before
import { http, createPublicClient } from "viem";
const client = createPublicClient({ transport: http(url) });

// After — chainId optional (auto-derived) but strongly recommended:
import { createPublicClient } from "viem";
import { vrpcHttp } from "@ankr.com/vrpc-viem";
const client = createPublicClient({ transport: vrpcHttp(url, { chainId }) });
// or bare-url (auto-derives chainId on first request):
const auto = createPublicClient({ transport: vrpcHttp(url) });
```

`vrpcHttp(url, opts)` is a custom `Transport` that substitutes for `http(url)`.
Every viem action (`getBalance`, `readContract` / `call`, `getLogs`, `getBlock`,
`estimateGas`, `getTransactionReceipt`, `sendRawTransaction`, …) funnels through
its single verifying `request`.

> Auth / shark routing: pass headers the normal way. For ethers, attach an
> `x-api-key` header via a `FetchRequest` and pass that as the URL argument
> (`VrpcOptions` extends `JsonRpcApiProviderOptions`, so it passes straight
> through). For viem, pass `headers: { "x-api-key": "…" }` in the `vrpcHttp`
> options. **Never hard-code the key** — read it from an env var by name (see the
> [examples](#runnable-examples) and the workspace secrets rule).

---

## 2. The `chainId` argument — optional but strongly recommended

`chainId` is **optional** on both adapters and is `number | bigint`:

- ethers: `new VrpcProvider(url, chainId, options?)` (positional) or
  `new VrpcProvider(url, { chainId, … })` (options) or `new VrpcProvider(url)`
  (auto-derive).
- viem: `vrpcHttp(url, { chainId, … })` (explicit) or `vrpcHttp(url)`
  (auto-derive).

**Why it is bound.** The chain id is bound into the signed canonical pre-image:

```
chain_id (8B LE) ‖ sha256(request_body) (32B) ‖ sha256(response_body) (32B) ‖ timestamp_ms (8B LE)
```

The sidecar signs over this pre-image, so the SDK must reconstruct it with the
**same** chain id to verify the signature. This is the chain id the sidecar was
configured with (`SIDECAR_CHAIN_ID`), not necessarily the node's reported
`eth_chainId`. A mismatch does **not** silently pass — it reconstructs a
different pre-image and surfaces as a clear `BadSignature` (a `VerificationError`
subclass).

Both adapters coerce via `BigInt(chainId)` **without** a `number` round-trip, so
chain ids above `Number.MAX_SAFE_INTEGER` (2^53−1) keep full `u64` precision and
do not produce false `BadSignature` rejections.

**Why pass it explicitly (recommended).** When `chainId` is omitted, each adapter
lazily derives it from a **signed `eth_chainId` response** on first use (memoized
so concurrent first calls share a single fetch) and **verifies that signature
self-consistently**: the response's own `result` IS the chainId, so the adapter
verifies the bootstrap with `{ chainId: result }`. The signature is over a
pre-image binding that chainId, so it only verifies if the node really signed for
that chain — the derived chainId is **cryptographically attested by the node**. A
tampered, forged (claims a chain ≠ the one it was signed for), or unsigned
`eth_chainId` **fails fast** at bootstrap with a `VerificationError`; there is no
unverified fallback. Passing `chainId` explicitly is still **strongly
recommended** because it:

- pins to **your expected chain** — catching a wrong-node / wrong-URL misconfig
  where you would otherwise verify *genuine* data from the *wrong* chain
  (auto-derive trusts the node's self-reported chain), and
- skips the bootstrap round-trip.

> ethers note: passing the chain id also pins the network (`staticNetwork`), so
> the provider issues **zero** `eth_chainId` round-trips. This only skips the
> round-trip; it does **not** weaken the signature binding. Omitting it routes
> the lazy `eth_chainId` bootstrap through `_detectNetwork` / `_send`'s shared
> resolver instead, where the signed `eth_chainId` response is verified
> self-consistently before its result is used.

---

## 3. Caveats — what changes vs. what does not

### Batching

- **ethers preserves native batching.** `VrpcProvider` does **not** pin
  `batchMaxCount=1`. A batch is POSTed as one body and verified **once** over the
  whole batch body (the pre-image binds the entire request/response bytes);
  ethers' drain loop then correlates the array results back to callers by id.
  Your existing batching behavior is unchanged.
- **viem is per-request by default.** `vrpcHttp` issues a single, non-batched
  `{ id: 1 }` request per action and verifies it as one unit (consistent with the
  ethers per-call decision). Batched-as-one-unit verification is a deferred
  opt-in for viem.

### WebSocket (`eth_subscribe`) — UNVERIFIED

The sidecar signs **HTTP** responses only. `eth_subscribe` / WS push streams
bypass the HTTP signing chokepoint and are **not verified**. Use an HTTP
transport for anything you need a signature on. (See the README trust-boundary
section.)

### ENS off-chain reads — UNVERIFIED

ENS **CCIP-Read**, **avatar**, and **IPFS** resolution fetch data from off-chain
gateways outside the signed RPC path. Those bytes are **unverified** even when
the on-chain RPC legs around them are signed.

---

## 4. Strict (default) vs permissive mode

Both adapters default to **`strict`** (fail-closed): a `VerificationError` from
`verifyResponse` propagates and no unverified data is ever returned.

**`permissive`** (opt-in) catches a `VerificationError`, fires the `logger`
**once**, and passes the parsed body through anyway. Use it only when you
explicitly want to observe-but-not-block (e.g. a staged rollout). Any
non-`VerificationError` (network error, ethers `SERVER_ERROR`, viem
`HttpRequestError`/`RpcRequestError`) always propagates in both modes.

```ts
// ethers
const provider = new VrpcProvider(url, chainId, {
  verification: "permissive",          // default: "strict"
  logger: (msg, err) => myLog.warn(msg, err),
});

// viem
const client = createPublicClient({
  transport: vrpcHttp(url, {
    chainId,
    verification: "permissive",        // default: "strict"
    logger: (msg, err) => myLog.warn(msg, err),
  }),
});
```

Other shared knobs: `replayWindowMs` (forwarded to `verifyResponse`; omit →
vrpc-core default 60s) and `logger`. viem additionally accepts `headers`,
`fetchFn`, and `timeout`.

---

## 5. How a verification failure surfaces

The failure type is the **same shared `VerificationError` family** across both
adapters (`MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp`,
`InvalidNonce`, `MalformedAttestationResponse` — each carries a discriminator
`kind`). What differs is only how you reach it from each library's error
plumbing.

### ethers — `instanceof`

In `strict` mode the `VerificationError` propagates straight out of the call.
Catch it and test with `instanceof`:

```ts
import { VerificationError } from "@ankr.com/vrpc-core";

try {
  const balance = await provider.getBalance(addr);
} catch (err) {
  if (err instanceof VerificationError) {
    // err.kind === "BadSignature" | "StaleTimestamp" | "MissingHeader" | …
  } else {
    throw err; // network / ethers SERVER_ERROR / etc.
  }
}
```

### viem — `retryCount: 0` + `err.walk(...)`

The transport hard-codes **`retryCount: 0`** (viem's injected default is ignored
on purpose): viem's `buildRequest` would otherwise treat a thrown
`VerificationError` as a codeless non-HTTP error, **retry it 3×**, and re-wrap it
as an `UnknownRpcError`, masking the failure. With `retryCount: 0` the typed
error propagates and `buildRequest` preserves it as the error `.cause`, so a
full-client caller recovers it by walking the cause chain:

```ts
import { VerificationError } from "@ankr.com/vrpc-viem"; // re-exported from the family

try {
  const balance = await client.getBalance({ address: addr });
} catch (err) {
  const verifyErr = (err as { walk?: (fn: (e: unknown) => boolean) => unknown })
    .walk?.((e) => e instanceof VerificationError);
  if (verifyErr instanceof VerificationError) {
    // verifyErr.kind === "BadSignature" | "StaleTimestamp" | …
  } else {
    throw err; // network / viem HttpRequestError / RpcRequestError / etc.
  }
}
```

> A signed JSON-RPC `{ error }` body is **not** a `VerificationError`: viem
> surfaces it as `RpcRequestError` (mapped by code), and ethers surfaces it as a
> normal JSON-RPC error — verification only gates the signature, not the RPC
> result semantics.

---

## Runnable examples

Two end-to-end scripts do a **real verified read** through a stage shark
`arbitrum_vrpc` route and then call the adapter-neutral boot-time trust anchor
(`anchorTrust`):

- [`examples/08-vrpc-ethers-verified-read.ts`](./examples/08-vrpc-ethers-verified-read.ts) — `VrpcProvider`
- [`examples/09-vrpc-viem-verified-read.ts`](./examples/09-vrpc-viem-verified-read.ts) — `vrpcHttp` + `createPublicClient`

Live execution is an operator step (it needs the staging URL + `x-api-key`,
supplied via env at runtime; CI/offline does not run them live). Both env vars
are referenced **by name only** — never hard-code or print the values:

| Env var                    | Purpose                              |
| -------------------------- | ------------------------------------ |
| `SHARK_STAGE_URL`          | Stage shark-proxy base URL           |
| `SHARK_STAGE_TDX_TEST_KEY` | `x-api-key` value for the vrpc route |

```sh
SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… bun run examples/08-vrpc-ethers-verified-read.ts
SHARK_STAGE_URL=… SHARK_STAGE_TDX_TEST_KEY=… bun run examples/09-vrpc-viem-verified-read.ts
```
