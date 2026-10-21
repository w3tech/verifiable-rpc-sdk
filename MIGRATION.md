# Migration guide — drop-in verifiable RPC for ethers and viem

Both adapters are **one-line swaps**. You keep your existing ethers `Provider` /
viem `Client` API surface unchanged; every HTTP JSON-RPC response now arrives
Ed25519-verified over its raw content-decoded bytes before the value reaches
your code. A verification failure is always thrown, never silently passed
through.

Upgrading from 0.3.2? See [Upgrading from 0.3 to 0.4](#upgrading-from-03-to-04).

Before you rely on the signature, read the README's
[What is verified / What is NOT verified](./README.md#what-is-verified--and-what-is-not)
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
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";
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

// After — set `chain` on the client (chain id comes from `chain.id`); optional
// but strongly recommended:
import { createPublicClient } from "viem";
import { vrpcHttp } from "@w3tech.io/vrpc-viem";
const client = createPublicClient({ chain, transport: vrpcHttp(url) });
// or omit `chain` (auto-derives chainId on first request):
const auto = createPublicClient({ transport: vrpcHttp(url) });
```

`vrpcHttp(url, opts)` is a custom `Transport` that substitutes for `http(url)`.
Every viem action (`getBalance`, `readContract` / `call`, `getLogs`, `getBlock`,
`estimateGas`, `getTransactionReceipt`, `sendRawTransaction`, …) funnels through
its single verifying `request`.

> Auth / gateway routing: pass headers the normal way. For ethers, attach an
> `x-api-key` header via a `FetchRequest` and pass that as the URL argument
> (`VrpcOptions` extends `JsonRpcApiProviderOptions`, so it passes straight
> through). For viem, pass `headers: { "x-api-key": "…" }` in the `vrpcHttp`
> options. **Never hard-code the key** — read it from an env var by name (see the
> [examples](#runnable-examples) and the workspace secrets rule).

### One URL — you spell the vRPC route out

You pass a **single** URL — the explicit vRPC route (e.g.
`https://rpc.ankr.com/arbitrum_vrpc`). The SDK uses it verbatim for the
JSON-RPC leg and derives only the attestation leg from it:

- the JSON-RPC leg is the URL as-is → `https://rpc.ankr.com/arbitrum_vrpc`;
- the attestation leg appends `/attestation` →
  `https://rpc.ankr.com/arbitrum_vrpc/attestation`.

The SDK does **not** append `_vrpc` itself — pass the vRPC route explicitly.
There is **no** separate `attestationBaseUrl` / `chainSlug` to configure —
both were removed.

Attestation correlation is **always-on**: the verifier is always used (there is
no permissive / opt-out mode — verification is fail-closed). The serving node id
(`vRPC-NodeId`) is **optional**: it is included in the attestation fetch when the
response carries it and omitted when absent. A gateway route that requires a
`node_id` but receives none fails to route — the fetch errors and propagates
(fail-closed), never a silent pass.

The standalone attestation fetch is a **single** `fetchAttestation(opts)` —
`fetchAttestation({ attestationUrl, nonce, nodeId?, headers? })`. There
is no former via-gateway helper; the same helper covers the via-gateway path (pass
the gateway-derived `attestationUrl` and the captured `nodeId`).

---

## 2. The `chainId` argument — optional but strongly recommended

`chainId` is **optional** on both adapters and is `number | bigint | string`:

- ethers: `new VrpcProvider(url, chainId, options?)` (positional only) or
  `new VrpcProvider(url)` (auto-derive).
- viem: set `chain` on the client — `createPublicClient({ chain, transport:
  vrpcHttp(url) })` (chain id comes from `chain.id`) — or omit `chain` to
  auto-derive.

**Why it is bound.** The chain id is bound into the signed canonical pre-image
(104 bytes):

```
sha256(utf8(chain_id)) (32B) ‖ sha256(request_body) (32B) ‖ sha256(response_body) (32B) ‖ timestamp_ms (8B LE)
```

The sidecar signs over this pre-image, so the SDK must reconstruct it with the
**same** chain id string to verify the signature. This is the chain id the
sidecar was configured with (`SIDECAR_CHAIN_ID`), not necessarily the node's
reported `eth_chainId`. A mismatch does **not** silently pass — it reconstructs
a different pre-image and surfaces as a clear `BadSignature` (a
`VerificationError` subclass).

Both adapters normalize `number`/`bigint` args to the decimal string immediately
(`42161` → `"42161"`, via `BigInt().toString(10)` — no `number` round-trip, so
chain ids above `Number.MAX_SAFE_INTEGER` (2^53−1) bind exactly and do not
produce false `BadSignature` rejections). Non-EVM chains pass the exact
configured string (e.g. TON's global id `"-239"`, or Stellar's network id — the
sha256 of its passphrase, a 64-char hex string) — an invalid string throws
`InvalidOption` at construction.

**Why set it explicitly (recommended).** When the chain id is omitted (no
positional `chainId` for ethers, no `chain` on the viem client), each adapter
lazily derives it from a **signed `eth_chainId` response** on first use (memoized
so concurrent first calls share a single fetch) and **verifies that signature
self-consistently**: the response's own `result` IS the chainId, so the adapter
verifies the bootstrap with `{ chainId: result }`. The signature is over a
pre-image binding that chainId, so it only verifies if the node really signed for
that chain — the derived chainId is **cryptographically attested by the node**. A
tampered, forged (claims a chain ≠ the one it was signed for), or unsigned
`eth_chainId` **fails fast** at bootstrap with a `VerificationError`; there is no
unverified fallback. Setting the chain id explicitly (ethers: positional
`chainId`; viem: `chain` on the client) is still **strongly recommended**
because it:

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

## 4. Verification is always fail-closed

Both adapters are **fail-closed**: a `VerificationError` from `verifyResponse`
propagates and no unverified data is ever returned. There is no permissive /
observe-but-not-block opt-in — a failed verification always throws. Any
non-`VerificationError` (network error, ethers `SERVER_ERROR`, viem
`HttpRequestError`/`RpcRequestError`) propagates too.

Other shared knobs: `replayWindowMs` (forwarded to `verifyResponse`; omit →
vrpc-core default 60s). viem additionally accepts `headers`, `fetchFn`, and
`timeout`.

---

## 5. How a verification failure surfaces

The failure type is the **same shared `VerificationError` family** across both
adapters (`MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp`,
`InvalidNonce`, `AttestationFailed` — each carries a discriminator `kind`).
Attestation that cannot be fetched right now is `AttestationUnavailable`, an
`UnavailableError`. Every error carries `executed`; a retry is safe only when
`mayHaveExecuted(err)` returns `false`. What differs is only how you reach it
from each library's error plumbing.

### ethers — `instanceof`

The `VerificationError` propagates straight out of the call.
Catch it and test with `instanceof`:

```ts
import { VerificationError } from "@w3tech.io/vrpc-core";

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
import { VerificationError } from "@w3tech.io/vrpc-viem"; // re-exported from the family

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

## Upgrading from 0.3 to 0.4

Each entry is a change for code written against 0.3.2. Ankr Confidential RPC
was not part of 0.3.2; it is listed under [New in 0.4](#new-in-04).

### Node versions

- SDK (`vrpc-core`, `vrpc-ethers`, `vrpc-viem`, `dstack-verify`): Node 22.13 or
  later on 22, or Node 24 or later (0.3.2 documented Node 18).
- `@w3tech.io/vrpc-proxy`: Node 24 or later (was 22.19).

### @w3tech.io/vrpc-core

The error changes apply to the same classes re-exported by
`@w3tech.io/vrpc-core/errors`, `@w3tech.io/vrpc-ethers` and `@w3tech.io/vrpc-viem`.

| 0.3.2 | 0.4 | What to do |
| --- | --- | --- |
| `MalformedAttestationResponse` | `AttestationFailed` with `reason: "malformed"` (field path in `detail`) | Catch `AttestationFailed` |
| `AttestationCorrelationError` | `AttestationFailed` with `reason: "pubkey-mismatch"` | Catch `AttestationFailed` |
| `AttestationNodeNotFoundError` | `AttestationUnavailable` with `reason: "status"`, `status: 404` | Catch `AttestationUnavailable` |
| `new AttestationFailed(chkId, detail, { cause })`, `kind: "Attestation"`, `chkId: string` | `new AttestationFailed(reason, detail, { chkId, cause })`, `kind: "AttestationFailed"`, `reason: AttestationFailedReason`, `chkId` set only for `reason: "check"` | Match on `err.reason` |
| `VerificationErrorKind` has `"MalformedAttestationResponse"`, `"AttestationNodeNotFound"`, `"AttestationCorrelation"`, `"Attestation"` | One literal `"AttestationFailed"` | Update `switch (err.kind)` |
| `VerificationError extends Error` | `VerificationError extends VrpcError`, with `executed: "no" \| "unknown"` | Nothing; `instanceof VerificationError` still works |
| `verifyAttestationCorrelation` | Removed; `TrustedVerifier` checks the correlation | Use `TrustedVerifier` |
| `TrustedVerifierOptions.nonceSource`, `TrustedVerifierOptions.verifyAttestation` | Removed | Drop them; customise the attestation check with `hardwareVerifier` |
| `DEFAULT_PUBKEY_CACHE_MAX` | Removed; the `pubkeyCacheMax` default is still 1024 | Use the literal |
| `safeLogger`, `truncateHex` | Removed | Nothing; core still wraps an injected `Logger` so it cannot throw |
| `defaultLogger` | Removed | Omit `logger`; the SDK stays silent without one |
| `byteLen`, `pickVrpcHeaders` | Removed | Delete the references |
| `VrpcUrls` is `{ rpcUrl, attestationUrl }` | Also has `confidentialUrl` | Build it with `deriveVrpcUrls(url)` |

### @w3tech.io/dstack-verify

| 0.3.2 | 0.4 | What to do |
| --- | --- | --- |
| `VerifyPolicy` has `allowlist`, `tcb`, `pccsUrl`, `allowInsecureMock`, optional `hardwareVerifier` | `{ binding, hardwareVerifier, logger? }`; `hardwareVerifier` is required | `{ binding, hardwareVerifier: createCloudVerifier() }` |
| `AttestationBundle` is `{ quote: QuoteEnvelope, tcbInfo, pubkey, nonce, signature_chain, appId?, instanceId? }` | `{ quote, reportData, composeHash, appCompose }`, all strings, `""` means absent; pubkey and nonce come from `policy.binding` | In a custom `HardwareVerifier`, read `bundle.quote` and `bundle.composeHash` instead of `bundle.quote.quote` and `bundle.tcbInfo.compose_hash` |
| `EventLogEntry`, `QuoteEnvelope`, `TcbInfo`, `PinnedAllowlist`, `TcbPolicy`, `KeyProvider`, `EMPTY_ALLOWLIST` | Removed | Delete the references |
| `AttestationErrorKind` | Removed; `AttestationError.kind` is still `"Attestation"` | Use `AttestationError["kind"]` |
| `CHK`, `ChkEntry`, `ChkDisposition`, `ChkId` `"CHK-MOCK"` | Removed; `ChkId` keeps `CHK-A1..G3`, each documented with its meaning | Delete the references |

### @w3tech.io/vrpc-proxy

| 0.3.2 | 0.4 | What to do |
| --- | --- | --- |
| `createProxyServer(config, overrides?)`, type `ProxyTestOverrides` | `createProxyServer(config)` | Drop the second argument |
| `errorResponseBody`, `InternalProxyError` | Removed | Delete the references |
| `new UpstreamBodyTooLargeError(maxBodyBytes)` with `maxBodyBytes` | `new UpstreamBodyTooLargeError()`, no `maxBodyBytes` | Read the limit from your `ProxyConfig.maxBodyBytes` |

### Behaviour changes

Errors (core, ethers, viem, proxy):

- Every error has `executed: "no" | "unknown"` (was absent). A retry is safe
  only when `mayHaveExecuted(err)` returns `false`:
  `if (!mayHaveExecuted(err)) retry();`
- Bad options throw `InvalidOption { option, reason }` synchronously from
  `new VrpcProvider`, `vrpcHttp`, `new TrustedVerifier` and the proxy CLI. Before:
  `TypeError` for a bad URL, `RangeError` or `InvalidChainId` for a bad configured
  chain id, and `replayWindowMs` 0, negative, fractional, `NaN` or `Infinity`,
  `pubkeyCacheTtlMs` `NaN`, `Infinity` or fractional, and invalid headers were
  accepted. Catch `InvalidOption` where you build the client.
- `InvalidChainId` now means only a chain id that came from the node (the
  `eth_chainId` bootstrap) or the input of `verifyResponse` / `validateChainId`.
  An unparsable `eth_chainId` body is `InvalidChainId` (was `MalformedHeader`).
- Attestation that cannot be fetched or checked right now throws
  `AttestationUnavailable` (an `UnavailableError`, not a `VerificationError`):
  transport failure, any non-2xx including 404 and 3xx (redirects are not
  followed), the 60 s deadline, a response over 1 MiB, a Phala verifier outage.
  Before: raw `TypeError`, `MalformedAttestationResponse` or
  `AttestationNodeNotFoundError`. `catch (e instanceof VerificationError)` no
  longer catches these; treat `AttestationUnavailable` as transient and
  `AttestationFailed` as a hard failure.
- A custom `HardwareVerifier` that throws anything other than `AttestationError`
  gives `AttestationFailed` with `reason: "check"`, `chkId: "CHK-P1"` (was
  rethrown as is).
- `vRPC-Timestamp` longer than 20 digits or above 2^64−1 is `MalformedHeader`
  (was `RangeError`).
- A repeated `vRPC-*` header, or an empty `vRPC-NodeId`, is `MalformedHeader`
  (was accepted with the joined value).

ethers:

- A signed non-2xx response is verified before `SERVER_ERROR`; a forged signed
  4xx/5xx is `BadSignature` (was `SERVER_ERROR` with the unverified body).
- Invalid UTF-8 in a signed 2xx body is `TypeError` (was `INVALID_ARGUMENT`).

viem:

- A custom `fetchFn` receives `init.body` as a `Uint8Array` (the signed request
  bytes), not a string. Pass it to `fetch` unchanged.
- One transport serves one chain: the first client's `chain`, or the verified
  `eth_chainId` bootstrap. A client with another `chain.id` gets
  `InvalidOption("chainId")` and nothing is sent (was `BadSignature` or the other
  chain's data). Create one `vrpcHttp` per chain.
- A signed non-2xx without a JSON-RPC `error`, and a non-2xx bootstrap, are
  `HttpRequestError` (was `undefined`, the body's `result`, or
  `MalformedHeader`). `HttpRequestError.body` of an unsigned non-2xx is the full
  JSON-RPC payload (was `{ method, params }`).
- Invalid UTF-8 in a signed 2xx body is `TypeError` (was decoded to U+FFFD).

@w3tech.io/vrpc-proxy:

- `--timeout` also bounds the attestation GET and the Phala cloud verify; both go
  through the proxy's HTTP agent.
- Attestation errors: `AttestationUnavailable` is 503, 504 on timeout, 429 when
  the attestation endpoint returned 429 (was 502 `MalformedAttestationResponse`,
  `AttestationNodeNotFound`, `Attestation` or `Internal`). Attestation failure is
  502 `kind: "AttestationFailed"` (was `Attestation` or `AttestationCorrelation`).
- An overflowing `vRPC-Timestamp` is 502 `MalformedHeader` (was `Internal`); any
  other `UnavailableError` is 502 with its own `kind` (was `Internal`).
- Every error body from a `VrpcError` carries `executed`.
- Network error messages are fixed: `Upstream request failed`, `Upstream response
  body exceeds the size limit`. The original error code is only in the
  `proxy.error` log line. An invalid upstream header is 502 `UpstreamConnect`.
- A client disconnect aborts the upstream request.
- The upstream URL query is forwarded (was dropped).
- A bad `--chain-id` prints `Invalid chainId: <reason>` (the value is no longer
  echoed).
- `--log-level debug` writes core events as `[vrpc-proxy] debug <event> {json}`
  lines to stderr (was multi-line `console.debug` output on stdout).

@w3tech.io/dstack-verify:

- `createCloudVerifier`: a Phala outage (transport, timeout including the body
  read, 5xx, 429, 408, non-JSON 2xx) throws `AttestationError` with
  `unavailable: true`; core turns it into `AttestationUnavailable` with
  `reason: "verifier"` (was a `CHK-P1` failure). A well-formed rejection still
  fails closed.

### New in 0.4

- Ankr Confidential RPC: entry `@w3tech.io/vrpc-core/confidential`
  (`ConfidentialClient`, `ConfidentialInfo`), `LazyConfidentialClient` in the main
  entry. Their `fetch` option carries the attestation GET and the sealed requests
  too, not only the default hardware verifier's call.
- ethers: `new VrpcProvider(url, chainId, { confidential: true })`,
  `confidentialReady()`, `getConfidentialInfo()`.
- viem: `vrpcHttp(url, { confidential: true })`.
- Proxy: `--confidential` / `VRPC_PROXY_CONFIDENTIAL`, `ProxyConfig.confidential`,
  `UnsupportedMediaTypeError`, `code` on `DecodeFailedError` and
  `UpstreamBodyTooLargeError`.
- Errors: `VrpcError`, `UnavailableError` (`AttestationUnavailable`,
  `RequestRejected`, `UnexpectedResponse`, `TransportFailed`, `InternalError`),
  `InvalidOption`, `mayHaveExecuted`, the confidential error classes.
- ethers and viem re-export everything in `@w3tech.io/vrpc-core/errors`,
  including `InvalidNonce`, `BadSignatureContext`, `StaleTimestampContext`,
  `VerificationErrorKind` and `OptionName`.
- Core: `createOpenSession`, `checkOptions`, `fetchTransport`, `linkSignal`.
- dstack-verify: `AttestationError.unavailable`.

---

## Runnable examples

Runnable scripts live in `examples/`. All target Ankr's public Arbitrum
vRPC endpoint and need no API key (every response is verified before it is
returned):

- [`examples/01-ethers-client.ts`](./examples/01-ethers-client.ts) — drop-in ethers `VrpcProvider`
- [`examples/02-viem-client.ts`](./examples/02-viem-client.ts) — viem `vrpcHttp` transport + `createPublicClient`
- [`examples/03-vrpc-core-walkthrough.ts`](./examples/03-vrpc-core-walkthrough.ts) — `@w3tech.io/vrpc-core` walkthrough (signed wire → `verifyResponse` → tamper→`BadSignature` → `fetchAttestation` + `TrustedVerifier`)
- [`examples/04-proxy.ts`](./examples/04-proxy.ts) — spawns `vrpc-proxy` and calls it with a plain `fetch`

```sh
pnpm install
pnpm example:all   # or: pnpm example:01-ethers-client / example:02-viem-client / example:03-vrpc-core-walkthrough / example:04-proxy
```
