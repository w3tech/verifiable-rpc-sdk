# @w3tech.io/vrpc-viem

A **verifiable drop-in** for viem's `http(url)` transport. Swap one line and
every read your viem client already makes — `getBalance`, `readContract`,
`call`, `getLogs`, `getBlock`, `estimateGas`, `getTransactionReceipt`,
`sendRawTransaction`, … — arrives Ed25519-verified over its raw response bytes
before the value ever reaches your application code. Your action code does not
change.

`vrpcHttp` is a viem **custom transport** (built on `createTransport`) whose
`request` owns its own `fetch`, captures the raw content-decoded response bytes
**before `JSON.parse`**, and feeds them — with the exact request bytes it
POSTed — into `@w3tech.io/vrpc-core`'s `verifyResponse`. Only after verification
passes is the body parsed and the result returned. Verification is
**fail-closed** by default (`strict`).

All verification logic is reused from `@w3tech.io/vrpc-core` — none is copied
here, and there is no `ethers` import (manifest isolation). The error family is
re-exported from core, so it is the **same type identity** the ethers adapter
(`@w3tech.io/vrpc-ethers`) re-exports: a caller cannot tell the two adapters
apart by error shape.

---

## Install

`viem` is a **peer dependency** (consumer-supplied, single instance):

```bash
pnpm add @w3tech.io/vrpc-viem viem
```

> The `@w3tech.io/vrpc-*` packages are published to npm. Inside this monorepo
> they resolve via `workspace:*`; the public install name is
> `@w3tech.io/vrpc-viem` (`peerDependency: viem ^2.52.2`).

---

## The one-line swap

```ts
// Before — plain http transport, no verification:
import { createPublicClient, http } from "viem";

const client = createPublicClient({
  transport: http("https://rpc.ankr.com/arbitrum_vrpc"),
});

// After — pass the same vRPC route; the SDK uses it verbatim for RPC and
// derives the `/attestation` sub-route itself. The chain id comes from the
// viem client's `chain.id` — declare `chain` to pin YOUR chain and skip the
// bootstrap:
import { createPublicClient } from "viem";
import { arbitrum } from "viem/chains";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";

const client = createPublicClient({
  chain: arbitrum, // chain.id is bound into the signed pre-image (pins it)
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum_vrpc", {
    headers: { "x-api-key": process.env.ANKR_API_KEY! },
  }),
});

// Or bare (no chain → derives chainId from a SIGNED, self-consistently-verified eth_chainId):
const bareClient = createPublicClient({
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum_vrpc"),
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

// Shared vrpc-core error family — re-exported (SAME identity as @w3tech.io/vrpc-ethers):
export { VerificationError, MissingHeader, MalformedHeader, BadSignature, StaleTimestamp };
```

### `VrpcHttpOptions`

> The pinned chain id is **not** an option — it comes from the viem client's
> `chain.id` (auto-derived from a signed `eth_chainId` when no `chain` is set).

| Option           | Type                                                          | Default                | Notes |
|------------------|---------------------------------------------------------------|------------------------|-------|
| `replayWindowMs` | `number`                                                      | vrpc-core default (60s)| Forwarded to `verifyResponse`. Omit in production. `0` only works in tests that inject `nowMs`; in production it always rejects on clock skew. |
| `headers`        | `Record<string, string>`                                      | —                      | Applied to BOTH the JSON-RPC POST and the internal attestation fetch (e.g. `x-api-key`, or the gateway `chain_vrpc` route header) — a single auth set here covers both legs. `content-type: application/json` is always set by the transport. |
| `timeout`        | `number`                                                      | client-injected, else `10_000` | Per-request HTTP timeout (ms), applied to the own `fetch` as `AbortSignal.timeout` (parity with viem `http()`). |
| `fetchFn`        | `(url: string, init: RequestInit) => Promise<Response>`       | global `fetch`         | Injectable fetch seam (mirrors viem `http`'s `fetchFn`). Hook for a routing fetch wrapper or offline tests. |

#### Lazy-attestation seam options (always-on)

> [!IMPORTANT]
> **Hardware attestation verification is mandatory and always-on.** The viem
> transport routes verification through vrpc-core's `TrustedVerifier`, which
> wires a real hardware-signature verifier by default — the Phala
> `CloudVerifier` (remote DCAP quote verify + binding of `report_data` against
> the expected signing pubkey and nonce). It is **fail-closed and cannot be
> disabled**: a policy without a hardware verifier throws, and any verifier
> failure throws. Verification chain: **CHK-A1** (unconditional pubkey/nonce
> binding, always throws on mismatch) → **CHK-A2** (best-effort compose-hash
> self-consistency, dormant when `app_compose`/`compose_hash` are absent) →
> mandatory hardware-signature step (`CloudVerifier`).
>
> Still deferred (do not treat as trust anchors yet): independent compose
> sourcing, RTMR3 event-log replay, a local DCAP-verified Intel PCK-rooted
> quote, and TCB-status policy. Today's hardware verdict comes from the Phala
> CloudVerifier (a remote verify API), not local DCAP — the full chain of
> trust is still evolving toward those. CHK-A2 is self-consistency only (both
> `app_compose` and `compose_hash` are self-reported by the same node), so it
> guards against config drift, not a forging attacker. The default CloudVerifier
> endpoint is unauthenticated, best-effort/no-SLA, and publishes submitted
> quotes to a public registry — point `hardwareVerifier` at a self-hosted
> endpoint to avoid that egress.

The normal verify routes through `@w3tech.io/vrpc-core`'s `TrustedVerifier`,
which lazily fetches + correlates the serving node's TDX attestation on an
**unknown** signing pubkey and **caches** the verified pubkey (configurable TTL,
default 1h). This is **always-on**: the attestation endpoint is **derived from
the single URL** you pass (the SDK appends the `/attestation` sub-route), so
there is **no** `attestationBaseUrl` / `chainSlug` to set and no opt-out —
verification is fail-closed. The chainId bootstrap
always stays on plain `verifyResponse`. The existing `headers` and `fetchFn` are
**reused** for the attestation-leg fetch (one verifier per transport — never per
call — so the pubkey cache lives for the transport lifetime).

The serving node id (`vRPC-NodeId`) is **optional**: it is included in the
attestation fetch when the response carries it and omitted when absent. A gateway
route that requires a `node_id` but receives none fails to route — the fetch
errors and propagates (fail-closed).

| Option           | Type                     | Default          | Notes |
|------------------|--------------------------|------------------|-------|
| `pubkeyCacheTtlMs` | `number`               | `3_600_000` (1h) | Verified-pubkey cache TTL (ms). A second read within TTL reuses the cache and skips the attestation fetch; past TTL the pubkey is re-attested (no stale trust). |
| `hardwareVerifier` | `HardwareVerifier`     | Phala cloud verifier (vrpc-core) | Internal/advanced. Overrides the mandatory hardware-signature verifier. Point it at a self-hosted endpoint, a future local-DCAP verifier, or a no-network test mock. Hardware verification is always-on and cannot be disabled; omitting this keeps the cloud default. |
| `logger`         | `Logger`                 | no-op (silent)   | Internal/advanced. Opt-in debug logger forwarded to verification to narrate the verify flow at debug level. Use `createConsoleLogger()` from `@w3tech.io/vrpc-core`. Safe-wrapped (never throws-through) and redacts secrets — observability only, never part of the verify decision. |

> v6.0 removed the inert `allowlist`/`tcb`/`pccsUrl` options. v7.0 reintroduces
> them as consumer-pinned anchors once the verifier consumes them. `headers`
> (above) stays — it covers both the RPC POST and the attestation fetch.

`fetchFn` (already documented above) feeds **both** legs — the RPC POST and the
attestation GET — which is also the offline test/example seam.

```ts
// Attestation is always-on, derived from the single URL — no attestationBaseUrl
// /chainSlug. Pass the vRPC route; the SDK appends `/attestation`.
const client = createPublicClient({
  chain: arbitrum, // chain.id pins the chain (skips the bootstrap)
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum_vrpc", {
    headers: { "x-api-key": process.env.ANKR_API_KEY! }, // RPC + attestation auth
    pubkeyCacheTtlMs: 3_600_000,       // 1h (default)
  }),
});
// Ordinary reads. The first unknown pubkey triggers one attestation fetch +
// hardware verify + cache; subsequent reads within TTL skip the fetch.
await client.getBalance({ address: "0x0000000000000000000000000000000000000000" });
```

---

## What is verified

For every HTTP JSON-RPC response that reaches your code, the transport enforces,
fail-closed, that the response is **signed + untampered + fresh + correctly
bound** against the chain id you pinned and the signing key that produced the
signature:

- **Signed** — a valid Ed25519 `vRPC-Signature`.
- **Untampered** — it verifies over the canonical 104-byte pre-image
  `sha256(utf8(chain_id)) ‖ sha256(request_body) ‖ sha256(response_body) ‖ timestamp_ms`;
  any mutation of request or response body fails as `BadSignature`.
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
  are deferred).
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
import { VerificationError, BadSignature } from "@w3tech.io/vrpc-viem";

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

`MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp` and
`InvalidChainId` all extend `VerificationError`, which extends `Error`.
For Ankr Confidential RPC mode the package also re-exports the `VerificationError`
subclasses `AttestationFailed`, `MalformedAttestationResponse`,
`ConfidentialSignerMismatch`, `ConfidentialDecryptFailed`,
`MalformedConfidentialResponse`, `InvalidInnerRequest`; the `UnavailableError`
base with `AttestationUnavailable`, `RequestRejected`, `UnexpectedResponse`,
`TransportFailed`, `ConfidentialSealFailed`; and the types
`UnavailableErrorKind` and `ConfidentialInfo`. They are the identical classes
`@w3tech.io/vrpc-core` and `@w3tech.io/vrpc-ethers` export (cross-adapter
parity).

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

## Ankr Confidential RPC mode

What the gateway and the node can see, the limits and the errors are described in
the [core Ankr Confidential RPC mode section](../core/README.md#ankr-confidential-rpc-mode).

`vrpcHttp(url, { confidential: true })` sends every JSON-RPC call encrypted to
an attested node. The client must declare `chain`; without it
`createPublicClient` throws. One `vrpcHttp()` instance serves one chain.

**Turn off CCIP-Read.** CCIP-Read (EIP-3668) requests go to the gateway URL a
contract names, in plaintext and outside Ankr Confidential RPC: viem sends
`{ sender, data }` there for any `call` that reverts with `OffchainLookup`, and
it is on by default. The transport cannot change a client option; create the
client with `ccipRead: false` to keep every request encrypted.

```ts
const client = createPublicClient({
  chain: arbitrum,
  transport: vrpcHttp(url, { confidential: true }),
  ccipRead: false,
});
```

`await client.transport.ready()` attests up front;
`client.transport.getConfidentialInfo()` returns the pinned node. The first call
includes the attestation and counts against `timeout` (10 s by default), so call
`ready()` at start-up.

**Do not combine with a transport that is not in Ankr Confidential RPC mode.**
`fallback([vrpcHttp(url, { confidential: true }), http(otherUrl)])` sends a
failed call in plaintext to the next transport. `fallback` moves on for every
error except user rejections and reverts, a failed signature or attestation
check included.

**Retries.** Nothing in the SDK resends a call: a 429, a redirect or a gateway
error is thrown as a typed error. `fallback` retries the whole request
(`retryCount`, 3 by default): set `retryCount: 0` when you use it. A per-call
`retryCount` you pass to `client.request` is honoured and resends the call.
A `fetchFn` of your own must pass `init.redirect` (`"manual"`) through and must
not retry; otherwise it follows a redirect or resends the encrypted request and
the API key itself.

**Response size.** The transport stops reading an answer past 192 MiB and the
call fails with `TransportFailed`, with your `fetchFn` too. A response without a
web stream body (node-fetch, a fetch polyfill) is read in full first, so the
limit is checked only after the answer is in memory.

**Errors.**

- Core errors reach viem actions wrapped in viem's `UnknownRpcError`; find them
  with `err.walk()`.
- An inner `{ error }` answer becomes `RpcRequestError`, which viem maps by code
  exactly as with `http` (for example to `InternalRpcError`).
- An inner non-2xx answer is `HttpRequestError`, or `RpcRequestError` when its
  body is a JSON-RPC error.

Every error class with its `executed` value, the request and response size
limits and the timeouts are listed in the core section's
[Limits](../core/README.md#limits) and [Errors](../core/README.md#errors)
subsections.

**No batching.** `vrpcHttp` does not batch in Ankr Confidential RPC mode either:
each call is one JSON-RPC request sent as one encrypted request.

**Versions.** Install `@w3tech.io/vrpc-viem` and `@w3tech.io/vrpc-core` at the
same version, so an error class you import from core is the one the transport
throws.

---

## Runnable example

`examples/02-viem-client.ts` builds a `createPublicClient` with `vrpcHttp` and
does a real verified `getBalance` / `getBlockNumber` through an Ankr RPC
`arbitrum` route — every response is Ed25519- and attestation-verified inside
the transport before viem decodes it:

```sh
pnpm example:02-viem-client
```

See `packages/viem/test/transport.test.ts` for the full wiring suite (verified
read, tamper → `BadSignature`, unsigned → `MissingHeader`, `retryCount: 0`,
per-request batching default, cross-adapter parity).

---

## Companion

- `@w3tech.io/vrpc-core` — verification primitives (`TrustedVerifier`,
  `verifyResponse`, `fetchAttestation`, the `VerificationError` family).
- `@w3tech.io/vrpc-ethers` — the same drop-in for ethers v6 (`VrpcProvider`).
- [`w3tech/verifiable-rpc-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar)
  — the Rust sidecar that produces the signed responses (wire contract `v0.5.0`;
  SDK `>=0.3.0` requires sidecar `>=0.5.0` — older sidecars sign the legacy
  pre-image and verification fails closed).
