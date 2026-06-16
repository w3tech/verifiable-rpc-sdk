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

// After — same URL, every response now verified. chainId is optional (auto-
// derived) but strongly recommended:
import { createPublicClient } from "viem";
import { vrpcHttp } from "@ankr.com/vrpc-viem";

const client = createPublicClient({
  transport: vrpcHttp("https://your-shark/arbitrum_vrpc", {
    chainId: 42161, // bound into the signed pre-image (recommended — pins it)
    headers: { "x-api-key": process.env.SHARK_API_KEY! },
  }),
});

// Or bare (derives chainId from a SIGNED, self-consistently-verified eth_chainId):
const bareClient = createPublicClient({
  transport: vrpcHttp("https://your-shark/arbitrum_vrpc"),
});

// Unchanged action code — the returned value IS proof of verification.
const balance = await client.getBalance({ address: "0x0000000000000000000000000000000000000000" });
const block = await client.getBlockNumber();
```

`chainId` is **optional but strongly recommended**. It is bound into the
canonical pre-image, so a wrong/substituted chain produces a different pre-image
and fails as `BadSignature`. When omitted, the transport derives it from a
**signed `eth_chainId` response** on the first request, memoized so concurrent
first calls share a single fetch, and **verifies that signature
self-consistently**: the response's own `result` IS the chainId, so it only
verifies if the node really signed for that chain — the derived chainId is
**cryptographically attested by the node**. A tampered/forged (claims a chain ≠
the one it was signed for) / unsigned `eth_chainId` **fails fast** with a
`VerificationError`; there is no unverified fallback. Pass `chainId` explicitly
to pin to **your expected chain** — catching a wrong-node / wrong-URL misconfig
where auto-derive (which trusts the node's self-reported chain) would verify
*genuine* data from the *wrong* chain — and to skip the bootstrap round-trip.

---

## Public API

```ts
export function vrpcHttp(url: string, opts?: VrpcHttpOptions): Transport<"vrpc-http">;

export interface VrpcHttpOptions { /* see table below */ }
export type VrpcVerification = "strict" | "permissive";

// Shared vrpc-core error family — re-exported (SAME identity as @ankr.com/vrpc-ethers):
export { VerificationError, MissingHeader, MalformedHeader, BadSignature, StaleTimestamp };
```

### `VrpcHttpOptions`

| Option           | Type                                                          | Default                | Notes |
|------------------|---------------------------------------------------------------|------------------------|-------|
| `chainId`        | `number \| bigint`                                            | auto-derived           | **Optional but strongly recommended.** Bound into the canonical pre-image. Coerced via `BigInt()` with **no number round-trip** — chain ids may exceed `2^53−1`, so widening through `number` would lose precision and reject intact responses. Omit → derived lazily from a **signed, self-consistently-verified** `eth_chainId` response on first request (tampered/forged/unsigned → fail-fast `VerificationError`, no unverified fallback); pinning explicitly also pins to **your expected chain**. |
| `verification`   | `VrpcVerification` (`"strict" \| "permissive"`)               | `"strict"`             | `strict` = fail-closed (a `VerificationError` propagates). `permissive` = catch, log once, pass the parsed body through. Opt-in only. |
| `replayWindowMs` | `number`                                                      | vrpc-core default (60s)| Forwarded to `verifyResponse`. Omit in production. `0` only works in tests that inject `nowMs`; in production it always rejects on clock skew. |
| `headers`        | `Record<string, string>`                                      | —                      | Merged into every POST (e.g. `x-api-key`, or the shark `chain_vrpc` route header). `content-type: application/json` is always set by the transport. |
| `timeout`        | `number`                                                      | client-injected, else `10_000` | Per-request HTTP timeout (ms), applied to the own `fetch` as `AbortSignal.timeout` (parity with viem `http()`). |
| `fetchFn`        | `(url: string, init: RequestInit) => Promise<Response>`       | global `fetch`         | Injectable fetch seam (mirrors viem `http`'s `fetchFn`). Hook for a routing fetch wrapper or offline tests. |
| `logger`         | `(msg: string, err: unknown) => void`                         | `console.warn`         | Invoked once per downgraded verification in `permissive` mode. |

#### Lazy-attestation seam options (opt-in)

> [!WARNING]
> **v5.0 ships a MOCK attestation verifier — NO real attestation security until v6.0.**
> When the seam is engaged, the v5.0 attestation check is a mock with
> `allowInsecureMock` **hard-set true**: it **bypasses all chain-of-trust checks**
> and prints a loud `console.warn` on every attestation. In the contract's own
> words: *"v5.0 provides NO real attestation security (real verification lands in
> v6.0)."* Real DCAP/RTMR/compose-hash verification arrives in v6.0; never rely on
> v5.0 attestation for production trust.

These fields wire the normal verify through `@ankr.com/vrpc-core`'s
`TrustedVerifier`, which lazily fetches + correlates the serving node's TDX
attestation on an **unknown** signing pubkey and **caches** the verified pubkey
(configurable TTL, default 1h). Routing is **strictly opt-in**: it engages **only
when BOTH `sharkBase` and `chain` are set**. Omit either and the transport behaves
byte-identically to before (plain `verifyResponse`, no attestation leg). The
chainId bootstrap always stays on plain `verifyResponse`. The existing `headers`
and `fetchFn` are **reused** for the attestation-leg fetch (one verifier per
transport — never per call — so the pubkey cache lives for the transport lifetime).

| Option           | Type                     | Default          | Notes |
|------------------|--------------------------|------------------|-------|
| `sharkBase`      | `string`                 | — (off)          | Shark proxy base URL (no trailing slash), e.g. `https://rpc.ankr.com`. Set **with** `chain` to engage the seam; the attestation GET targets `<sharkBase>/<chain>_vrpc/attestation`. |
| `chain`          | `string`                 | — (off)          | Chain slug for the `<chain>_vrpc` attestation route, e.g. `arbitrum`. Opt-in pair with `sharkBase`. |
| `pubkeyCacheTtl` | `number`                 | `3_600_000` (1h) | Verified-pubkey cache TTL (ms). A second read within TTL reuses the cache and skips the attestation fetch; past TTL the pubkey is re-attested (no stale trust). |
| `allowlist`      | `PinnedAllowlist`        | empty            | Pinned trust anchors for the attestation `VerifyPolicy`. The v5.0 mock does not inspect it; defaults to an empty allowlist. |
| `tcb`            | `TcbPolicy`              | core default     | DCAP TCB acceptance forwarded to the attestation `VerifyPolicy`. |
| `pccsUrl`        | `string`                 | —                | Operational collateral source for dcap-qvl (NOT a trust dependency). |
| `apiKey`         | `string`                 | —                | Auth key sent as `x-api-key` on the attestation fetch (parity with the ethers half). `headers` may also carry `x-api-key` for the RPC leg. **SECRET — never logged.** |

`fetchFn` (already documented above) feeds **both** legs — the RPC POST and the
attestation GET — which is also the offline test/example seam.

```ts
const client = createPublicClient({
  transport: vrpcHttp("https://rpc.ankr.com/arbitrum_vrpc", {
    chainId: 42161,
    sharkBase: "https://rpc.ankr.com",
    chain: "arbitrum",
    apiKey: process.env.SHARK_API_KEY, // attestation-leg auth (never logged)
    pubkeyCacheTtl: 3_600_000,         // 1h (default)
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

### Strict vs permissive

- **`strict`** (default) — a `VerificationError` propagates; no unverified data
  is returned.
- **`permissive`** — a `VerificationError` is caught, the `logger` fires **once**,
  and the parsed body is returned anyway. If a downgraded body also fails
  `JSON.parse` (truncated / HTML error page), the parse failure is logged
  through the same `logger` and still thrown — fail-closed, no unverified data
  returned silently. Opt-in only.

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
  apiKey: process.env.SHARK_API_KEY!,
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
  bun run examples/09-vrpc-viem-verified-read.ts
```

See `packages/viem/test/transport.test.ts` for the full wiring suite (verified
read, tamper → `BadSignature`, unsigned → `MissingHeader`, permissive
passthrough, `retryCount: 0`, per-request batching default, cross-adapter
parity).

---

## Companion

- `@ankr.com/vrpc-core` — verification primitives (`verifyResponse`,
  `VerifierClient`, `anchorTrust`, the `VerificationError` family).
- `@ankr.com/vrpc-ethers` — the same drop-in for ethers v6 (`VrpcProvider`).
- [`w3tech/verifiable-rpc-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar)
  — the Rust sidecar that produces the signed responses (wire contract `v0.2.0`).
