# @w3tech.io/vrpc-core

Transport-agnostic Ed25519 verification primitives for Ankr's verifiable RPC.

This is the verification **engine** — the layer both the ethers and viem
adapters build on. It owns the canonical 104-byte pre-image, the Ed25519
signature check, the replay window, the attestation fetch/correlation helpers,
and the typed `VerificationError` family. It has **no blockchain-client
dependency** — its runtime deps are `@noble/ed25519`, `@noble/hashes`,
`lru-cache` (pubkey cache), and the sibling `@w3tech.io/dstack-verify` (hardware
verifier). The `@w3tech.io/vrpc-core/confidential` entry also bundles its
encryption libraries (`@hpke/core`, `@hpke/dhkem-x25519`, `@hpke/common`,
`@noble/curves`, `bhttp-ts`, `quicvarint`) at fixed versions; they are not
installed as dependencies.
Pairs with the `verifiable-rpc-sidecar` `v0.5.0` wire contract.

**Version gate:** SDK `>=0.3.0` requires sidecar `>=0.5.0` (string chain id
hashed into the 104-byte pre-image). Older sidecars sign the legacy pre-image
and verification fails closed. Ankr Confidential RPC mode needs nodes whose
sidecar serves the encrypted endpoint (`verifiable-rpc-sidecar` `v0.5.2` or
later).

Use this package directly when you verify responses captured outside a normal
ethers/viem call path (an off-chain pipeline, a log archive, an audit script),
or when you are building your own adapter. If you just want verified contract
reads, use `@w3tech.io/vrpc-ethers` or `@w3tech.io/vrpc-viem` instead — they wrap
this engine behind a drop-in provider/transport.

---

## Install

Published to npm as `@w3tech.io/vrpc-core`:

```sh
pnpm add @w3tech.io/vrpc-core
```

Inside this monorepo the packages resolve via `workspace:*`.

Runtime requires a global `fetch`, `crypto.getRandomValues`, `TextEncoder`,
and `BigUint64` `DataView` support (Node 20.19 or later, Bun, modern browsers).

---

## What gets verified (trust boundary)

For each HTTP JSON-RPC response, the engine enforces — fail-closed — that the
response is:

- **Signed** — `vRPC-Signature` is a valid Ed25519 signature, and
- **Untampered** — it verifies over the canonical 104-byte pre-image
  `sha256(utf8(chain_id)) ‖ sha256(request_body) ‖ sha256(response_body) ‖ timestamp_ms`,
  so any mutation of request or response body fails as `BadSignature`, and
- **Fresh** — `vRPC-Timestamp` is inside the replay window (default 60s); a
  replayed old response is rejected as `StaleTimestamp`, and
- **Correctly bound** — against the **chain id you pinned** (a wrong/substituted
  chain binds a different pre-image → `BadSignature`) and the **signing key** in
  the response header. `TrustedVerifier` additionally correlates that key against
  the serving node's attestation pubkey.

**The boundary (honest gap):** the low-level `verifyResponse` seam is
signature-only — **signed + untampered + fresh + bound against a pinned key**. The
default `TrustedVerifier` path goes further: it runs a **mandatory, always-on**
hardware verifier (the Phala `CloudVerifier` by default, overridable) that verifies
the DCAP quote and binds it to the response pubkey, nonce, and compose hash,
**fail-closed** — so a forged quote is rejected, not passed. Still deferred:
verifying the quote **locally** against the Intel PCK root (the default verdict is
delegated to a remote service), RTMR event-log replay, a **node-independent**
compose-hash source (today's compose-hash check is self-consistency only), and
TCB-status policy. WebSocket push and ENS off-chain reads are outside the signed
HTTP path and unverified.

---

## Ankr Confidential RPC mode

In Ankr Confidential RPC mode every request and every answer is encrypted end to
end to one attested node. The client attests the node, encrypts the request to
the node's attested key, checks the node's signature on the answer and only then
decrypts it. ethers and viem users switch it on with one option (see the
[ethers](../ethers/README.md#ankr-confidential-rpc-mode) and
[viem](../viem/README.md#ankr-confidential-rpc-mode) sections); clients that
cannot use the SDK can run [`vrpc-proxy`](../proxy/README.md#ankr-confidential-rpc-mode).

### What the gateway and the node can see

The gateway still sees:

- that a call happened, and when;
- the API key;
- the chain;
- the node the client is pinned to;
- the request and response sizes;
- the HTTP status;
- timing.

The gateway cannot see the method, the parameters, the path, the query, the
inner headers or the body.

The node inside the TEE decrypts the request and sees it in plaintext.

There is no forward secrecy. The encryption key is the node's long-term attested
signing key, so whoever later obtains that key can decrypt recorded traffic.

An edge retry can resend an encrypted request to the same node, so a
state-changing call can run more than once.

### Use it

The client ships in its own entry, `@w3tech.io/vrpc-core/confidential`; the main
`@w3tech.io/vrpc-core` entry does not include it or its encryption libraries.

```ts
import { ConfidentialClient } from "@w3tech.io/vrpc-core/confidential";

const client = new ConfidentialClient({
  url: "https://rpc.ankr.com/arbitrum_vrpc",
  chainId: "42161",
  headers: { "x-api-key": apiKey },
});

await client.ready(); // attests and pins one node; optional, the first request does it too

const res = await client.request({
  method: "POST",
  path: "/",
  contentType: "application/json",
  accept: "application/json",
  body: new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
  ),
});
// res.status, res.contentType (absent when the node sent none), res.body (Uint8Array)

client.getConfidentialInfo(); // { nodeId, pubkey, composeHash, attestedAt }, or undefined when nothing is pinned
```

`ready()` and `request()` take an optional `{ signal }` second argument.

- `url`: the vRPC endpoint, used as given (the SDK does not append `_vrpc`);
  `/attestation` and `/confidential` are appended to it. Both forms work: the
  key in the path (`https://rpc.ankr.com/<chain>_vrpc/<key>`) or the header key
  (`https://rpc.ankr.com/<chain>_vrpc` with `x-api-key` in `headers`).
- `chainId`: required. The client never asks the node for `eth_chainId`, which
  would have to go out in clear.
- `headers`: sent on every outer request to the gateway, never inside the
  encrypted request; a `content-type` entry is ignored.
- `hardwareVerifier`: replaces the default hardware verifier that checks the
  node's TDX quote.
- `logger`: an opt-in `Logger`, as in open mode.
- `replayWindowMs`: the allowed clock skew of the node's signature timestamp
  (default 60 s). Finite positive integer milliseconds; anything else throws
  `InvalidOption`.
- `pubkeyCacheTtlMs`: how long a pin is kept (default 1 hour). Finite positive
  integer milliseconds; anything else, `Infinity` included, throws
  `InvalidOption`.
- `transport`: replaces `fetch` for both outer requests. It must send the bytes
  as given, never follow a redirect, never retry, honour the signal and return
  the content-decoded body. `fetchTransport(fetchFn)` from
  `@w3tech.io/vrpc-core` builds one over your own fetch; it is the default
  transport over the global fetch. A transport of your own reads the body with
  `readCappedBody(response, request.maxBytes)`, which stops at the request's
  `maxBytes` (1 MiB for the attestation GET, 192 MiB when unset) and then fails
  the call with `TransportFailed` (reason `too-large`).

The inner request is `{ method, path, contentType?, accept?, body? }`. A `GET`
without a body is allowed; a request body requires `contentType`. Only
`content-type` and `accept` travel inside the encrypted request, with the
method, path, query and body.

### Behaviour

- The first call attests the node (or `ready()` does) and pins it. Every later
  call is sealed to the pinned node.
- A failure after the request was sent drops the pin, and the next call attests
  again and may pin a different node. The pin is kept on an abort, on any
  failure before sending, on `TransportFailed`, `StaleTimestamp`, and on
  `RequestRejected` 413 or 429.
- Nothing retries, fails over or follows a redirect. Retrying is the caller's
  choice.
- Any inner status is returned, not thrown. This includes the node's own
  `application/problem+json` answers `{ type, title }`:

  | Inner status | `type` |
  | ------------ | ------ |
  | `400` | `urn:vrpc:error:bad-request` |
  | `413` | `urn:vrpc:error:batch-too-large` |
  | `415` | `urn:vrpc:error:unsupported-media-type` |
  | `500` | `urn:vrpc:error:internal` |
  | `502` | `urn:vrpc:error:upstream` |
  | `504` | `urn:vrpc:error:upstream-timeout` |

- An inner `204`, `205` or `304` is returned with that status and an empty
  body.
- A single call and a JSON-RPC batch are both one encrypted request.
- An aborted call rejects with the caller's `signal.reason` and carries no
  `executed` field.

### Limits

| Limit | Value | What the caller gets |
| ----- | ----- | -------------------- |
| Calls in one JSON-RPC batch | 1000 | Inner `413` `urn:vrpc:error:batch-too-large`; no call in the batch is run |
| Request body through the gateway | 5 MiB + 64 KiB | `RequestRejected` (`413`) |
| Request body at the node | 8 MiB | `RequestRejected` (`413`); the gateway limit is reached first |
| Response at the node | 128 MiB | Inner `502` `urn:vrpc:error:upstream` |
| Response through the gateway | 160 MiB | `UnexpectedResponse` (`502`) |
| Response read by the client | 192 MiB | `TransportFailed` (reason `too-large`) |
| Node upstream timeout | 25 s | Inner `504` `urn:vrpc:error:upstream-timeout` |
| Gateway timeout | 30 s | `UnexpectedResponse` (`502`) |
| Attestation deadline | 60 s | `AttestationUnavailable` (reason `timeout`) |
| Inner header section | 64 KiB | `InvalidInnerRequest` (reason `header`), nothing sent |
| Inner path | 65,534 bytes after URL serialization | `InvalidInnerRequest` (reason `path`), nothing sent |

The inner path must start with `/`, must not start with `//`, and must not
contain `#`, a dot segment, a backslash or non-ASCII characters. A query that
the URL serializer rewrites is sent normalized: a trailing `?` is dropped and
`'` becomes `%27`.

### Errors

A call that got no verifiable answer throws an `UnavailableError`; its
`executed` field says whether the call may have run:

- `"no"`: the gateway or node did not run this attempt; an edge retry may have
  run an earlier attempt of the same call. The answer is unsigned, so this is
  the gateway's word; a hostile gateway can as well replay the encrypted
  request itself.
- `"unknown"`: the call may or may not have run; check state before resending a
  state-changing call.

| Class | `kind` | `executed` | Thrown when |
| ----- | ------ | ---------- | ----------- |
| `AttestationUnavailable` | `"AttestationUnavailable"` | `"no"` | The node could not be attested, so the call was not sent. `.reason`: `status` (`.status`), `transport`, `too-large`, `node-id-missing`, `timeout`, `verifier` |
| `RequestRejected` | `"RequestRejected"` | `"no"` | A 4xx that is not an encrypted answer: the gateway or node refused this attempt. `.status/.nodeId/.contentType` |
| `UnexpectedResponse` | `"UnexpectedResponse"` | `"unknown"` | The endpoint answered with something other than an encrypted answer (not a 4xx). `.status/.nodeId/.contentType` |
| `TransportFailed` | `"TransportFailed"` | `"unknown"` | The request failed in transport, or the answer passed 192 MiB. `.reason`: `network`, `too-large`; `.nodeId` |
| `InternalError` | `"InternalError"` | `"no"` before sending, else `"unknown"` | An unexpected failure in the client or an injected seam. `.cause` |

Ankr Confidential RPC mode adds these errors (`InvalidInnerRequest` extends
`VrpcError`, the others `VerificationError`):

| Class | `kind` | Thrown when |
| ----- | ------ | ----------- |
| `ConfidentialSignerMismatch` | `"ConfidentialSignerMismatch"` | The answer was signed by a key other than the pinned node key. `.expectedPubkey/.actualPubkey` |
| `InvalidInnerRequest` | `"InvalidInnerRequest"` | The inner request cannot be sent; rejected before any network call. `.reason`: `method`, `path`, `header`, `content-type-required`, `encode-failed` |
| `ConfidentialDecryptFailed` | `"ConfidentialDecryptFailed"` | A validly signed answer could not be decrypted |
| `MalformedConfidentialResponse` | `"MalformedConfidentialResponse"` | A validly signed answer is too short to open or its inner response does not decode. `.reason`: `too-short`, `framing`, `informational`, `decode-failed` |

The open-mode classes `BadSignature`, `StaleTimestamp`, `MissingHeader`,
`MalformedHeader`, `AttestationFailed` and `InvalidChainId` apply too; see the open-mode Errors section below.

Rule of thumb: an `UnavailableError` means nothing was verified, and retrying is
the caller's choice. A `VerificationError` means a broken or hostile path, and
the pin is already dropped (except on `StaleTimestamp`). `InvalidInnerRequest`
and `InvalidOption` are caller input errors raised before anything is sent.

### Known behaviours

- An answer cut short in transit by the gateway arrives as a well-formed
  shorter message and is reported as `BadSignature`, although the node may have
  run the call.
- In browsers a REST node's redirect answer cannot be read (Fetch returns an
  opaque redirect) and is reported as `UnexpectedResponse`.
- A node whose sidecar does not serve the encrypted endpoint answers a signed
  `404` that is reported as `RequestRejected`.
- `fetch` implementations built on `XMLHttpRequest` (React Native,
  `whatwg-fetch`) follow redirects even with `redirect: "manual"`, so a
  redirect resends the encrypted request and the API key to its target.

### Runtimes and versions

- Node 20.19 or later.
- Browsers work as a runtime, but the public endpoint does not expose the
  `vRPC-*` headers to other origins: a page on another origin gets
  `AttestationUnavailable` (reason `node-id-missing`).
- Nodes need a sidecar that serves the encrypted endpoint
  (`verifiable-rpc-sidecar` `v0.5.2` or later).
- Keep `@w3tech.io/vrpc-core` and the adapters at the same version, so the
  error classes keep one identity and `instanceof` works.

---

## Quick usage

### Verify a request/response pair yourself

`verifyResponse` is the transport-agnostic seam: hand it the
**content-decoded** request bytes, the response bytes, and the response headers,
and it does header parse → 104-byte pre-image rebuild → Ed25519 verify → replay
check. It knows nothing about `fetch`, JSON-RPC envelopes, or `accept-encoding`.
Because it is byte-level, it verifies any signed HTTP exchange — JSON-RPC POSTs
and path-based REST responses (e.g. TON's REST API, Stellar Horizon) alike; for
a `GET` the request body is empty, so pass an empty `Uint8Array`.

```ts
import { verifyResponse, VerificationError } from "@w3tech.io/vrpc-core";

// You captured these bytes + headers however you like (your own fetch, a log).
const requestBytes = new TextEncoder().encode(
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
);
const responseBytes = /* Uint8Array of the exact response body bytes */;
const responseHeaders = resp.headers; // Headers | Record<string, string>

try {
  const pair = await verifyResponse(requestBytes, responseBytes, responseHeaders, {
    chainId: "1", // MUST match the exact string the sidecar signs with
  });
  // pair.responseBytes — verified bytes, exactly as signed
  // pair.nodeId        — serving node id (vRPC-NodeId), if present
  // pair.verification  — { signatureHex, pubkeyHex, timestampMs, preImageSha256 }
} catch (err) {
  if (err instanceof VerificationError) {
    console.error(err.kind, err.message); // typed, fail-closed
  }
  throw err;
}
```

---

## Debug logging (opt-in) — watch vRPC verify a response

The SDK is **silent by default** — nothing is emitted unless you inject a
`Logger`. Injecting one is the easiest way to **see exactly how vRPC works**: at
debug level it narrates every step the verifier takes on each response. Pass a
logger through the adapter `logger` option (the primary drop-in surface) or
directly into `TrustedVerifier`. `createConsoleLogger()` is a ready-made
`console.debug` sink prefixed with `[vrpc]`. The logger never throws-through (it
is safe-wrapped in core) and logs only `vrpc-*` headers (every other header is
dropped) plus truncated byte fields — so it is observability only and never part
of the verify decision.

```ts
import { createConsoleLogger } from "@w3tech.io/vrpc-core";
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";

// Inject through the ethers adapter (drop-in); omit `logger` to stay silent.
const provider = new VrpcProvider("https://rpc.ankr.com/eth_vrpc", 1, {
  logger: createConsoleLogger(),
});
// works the same on the viem transport: vrpcHttp(url, { logger: createConsoleLogger() })
```

You'll see one debug line per step, in order (events fire only on the verifying
provider — a plain ethers/viem provider stays silent):

| Event | What it shows |
| --- | --- |
| `verify.start` | truncated request/response bytes + the `vrpc-*` headers |
| `preimage.computed` | chainId, timestamp, the 104-byte pre-image hash |
| `signature.checked` | Ed25519 result, the signature + signing pubkey |
| `timestamp.checked` | clock skew vs the replay window |
| `cache.lookup` | is this pubkey already trusted? (hit → skip attestation) |
| `attestation.fetch` | attestation URL + fresh nonce (only on a cache miss) |
| `attestation.correlation` | the signing pubkey matches the attested pubkey |
| `attestation.received` | compose hash, pubkey, a few quote bytes |
| `attestation.fieldChecks` | CHK-A1 (reportData binding) + CHK-A2 (compose hash) |
| `hardware.verify` | the TDX quote is checked by the hardware/cloud verifier |
| `cache.store` | the verified pubkey is cached with its TTL |

The first request on a new node runs the full attestation + hardware verify;
later requests hit the pubkey cache and skip straight to per-response signature
verification.

---

## Public API

### `verifyResponse(requestBytes, rawResponseBytes, responseHeaders, opts)`

```ts
function verifyResponse(
  requestBytes: Uint8Array,
  rawResponseBytes: Uint8Array,
  responseHeaders: ResponseHeaders,      // Headers | Record<string, string>
  opts: VerifyResponseOptions,
): Promise<VerifiedPair>;
```

Steps performed: (4) header parse — missing `vRPC-Signature` / `vRPC-Pubkey` /
`vRPC-Timestamp` → `MissingHeader`; (5) shape validate → `MalformedHeader`;
(6) rebuild the canonical 104-byte pre-image via `buildPreImage`; (7) hex →
bytes; (8) Ed25519 `verifyAsync` → `BadSignature` on failure (tampered bytes or
wrong `chainId`); (9) replay-window check, run **after** signature verify →
`StaleTimestamp`. Header lookup is case-insensitive over both `Headers` and
plain records. `vRPC-NodeId` is optional (older proxies omit it).

**`VerifyResponseOptions`**

| Option           | Type      | Default            | Notes                                                         |
| ---------------- | --------- | ------------------ | ------------------------------------------------------------- |
| `chainId`        | `string`  | — (required)       | Validated (`validateChainId`) then hashed into the pre-image. Invalid → `InvalidChainId`; mismatch → `BadSignature`. |
| `replayWindowMs` | `number`  | `60_000`           | Allowed clock skew. `0` requires an exact-ms match (tests only). |
| `nowMs`          | `bigint`  | `BigInt(Date.now())` | Injected wall clock for deterministic tests.                |

**`VerifiedPair`** → `{ responseBytes, nodeId?, verification }` where
`verification = { signatureHex, pubkeyHex, timestampMs, preImageSha256 }`.
The default `replayWindowMs` is `60_000` (1 minute).

### Pre-image and compose-hash

```ts
buildPreImage(chainId: string, requestBody: Uint8Array, responseBody: Uint8Array, timestampMs: bigint): Uint8Array; // 104 bytes
```

**`computeComposeHash`** (Layer A — "is the measured code the code I expect?"):
`sha256(utf8(app_compose))` as bare lowercase hex, matching dstack's rule (raw
bytes, no canonicalization). It is **not** exported by `@w3tech.io/vrpc-core` —
it lives in the sibling `@w3tech.io/dstack-verify`
(`import { computeComposeHash } from "@w3tech.io/dstack-verify";`). The SDK's
CHK-A2 self-consistency check uses it to confirm a node's self-reported
`app_compose` — served verbatim in the `/attestation` body next to `composeHash`
— hashes to its `composeHash`.

**Self-reported, NOT a trust anchor:** `app_compose` and `compose_hash` both come
from the same node, so a match proves only internal consistency (forgeable). The
real Layer A anchor (an external, node-independent compose registry) is deferred.

### Attestation (unsigned route)

```ts
fetchAttestation(opts: FetchAttestationOptions): Promise<Attestation>;
```

`fetchAttestation` (the single attestation-fetch entry point) calls
`GET <attestationUrl>?nonce=<bare-hex>`, appending `&node_id=<id>` **only when**
`opts.nodeId` is present. `FetchAttestationOptions` =
`{ attestationUrl, nonce, nodeId?, headers?, fetch? }`. Redirects are not
followed; a transport failure, any non-2xx (including `404`) or a body over
1 MiB throws `AttestationUnavailable`. The nonce must be exactly 32 bytes or
`InvalidNonce` is thrown **before** any network call. This route is unsigned by
contract — no `vRPC-*` verification runs, and a malformed body throws
`AttestationFailed` (reason `malformed`). `TrustedVerifier` calls it lazily for
every new pubkey and checks that `attestation.pubkey` equals the response's
`vRPC-Pubkey` (`AttestationFailed`, reason `pubkey-mismatch`).

`Attestation` = `{ quote: GetQuoteResponse, pubkey, composeHash, app_compose }`,
where `app_compose` is a required field carrying the raw verbatim app-compose text
used for the CHK-A2 self-consistency check (defaults to `""` on older
sidecars/simulator, in which case CHK-A2 dormant-skips);
`GetQuoteResponse` = `{ quote, event_log, report_data, vm_config }` (bare-hex
fields; some empty under the dstack simulator).

### Additional exports

| Export | Kind | Notes |
| ------ | ---- | ----- |
| `TrustedVerifier` | class | Verifier that fetches the signing pubkey via per-call attestation (lazy attestation seam, see `fetchAttestation` below) and caches it. |
| `TrustedVerifierOptions` | type | Options for `TrustedVerifier`. |
| `DEFAULT_PUBKEY_CACHE_TTL_MS` | const | Default TTL for the `TrustedVerifier` pubkey cache. |
| `deriveVrpcUrls(...)` | function | Derives the vRPC endpoint URL set from a base. |
| `VrpcUrls` | type | Shape returned by `deriveVrpcUrls`. |
| `parseChainId(...)` | function | Decodes a decimal-string chainId (e.g. `"42161"`) from the raw bytes of a signed `eth_chainId` response (the auto-derive bootstrap used by the ethers/viem adapters); throws `InvalidChainId` on invalid JSON, a non-0x-hex `result` or a decimal id over 64 bytes. |
| `validateChainId(...)` | function | Validates a chain id string (sidecar-identical rules: non-empty, ≤64 bytes, printable ASCII, no inner whitespace) and returns the trimmed value; throws `InvalidChainId`. Client options are checked with the same rules and throw `InvalidOption`. |
| `isSignedVrpcResponse(...)` | function | Predicate: whether a response carries the `vRPC-*` signing headers. |
| `fetchTransport(fetchFn?)` | function | A confidential `transport` over `fetchFn` (the global fetch when omitted): no redirect, no retry, body capped at 192 MiB, errors without the URL. |
| `readCappedBody(response, maxBytes?)` | function | Reads a fetch `Response` body for a custom confidential `transport`, rejecting past `maxBytes` (default 192 MiB); the client reports that as `TransportFailed` (reason `too-large`). |

---

## Errors

Every verification failure throws a subclass of the abstract `VerificationError`
(extends `VrpcError`). Narrow with `instanceof` or the `kind` discriminator. An
attestation that cannot be fetched or checked right now throws
`AttestationUnavailable` (an `UnavailableError`), and invalid client options
throw `InvalidOption`; neither is a `VerificationError`.

| Class                          | `kind`                          | Thrown when                                                       |
| ------------------------------ | ------------------------------- | ----------------------------------------------------------------- |
| `MissingHeader`                | `"MissingHeader"`               | A required `vRPC-*` header is absent. `.headerName`               |
| `MalformedHeader`              | `"MalformedHeader"`             | Header present but fails shape validation. `.headerName/.value/.reason` |
| `BadSignature`                 | `"BadSignature"`                | Ed25519 verify failed (tampered bytes or wrong chainId). `.signatureHex/.pubkeyHex/.preImageSha256` |
| `StaleTimestamp`               | `"StaleTimestamp"`              | Valid signature but timestamp outside replay window. `.observedMs/.nowMs/.skewMs/.allowedWindowMs` |
| `InvalidNonce`                 | `"InvalidNonce"`                | Attestation nonce not exactly 32 bytes. `.reason`                |
| `InvalidChainId`               | `"InvalidChainId"`              | A chain id from the node (`eth_chainId` bootstrap) or passed to `verifyResponse` / `validateChainId` fails validation. `.chainId/.reason` |
| `AttestationFailed`            | `"AttestationFailed"`           | The attestation is malformed, its pubkey is not the response signer, or a check failed. `.reason`: `malformed`, `pubkey-mismatch`, `check` (`.chkId`); `.detail` |

```ts
import { VerificationError, BadSignature, TrustedVerifier } from "@w3tech.io/vrpc-core";

const tv = new TrustedVerifier({
  chainId: "1",
  attestationUrl: "https://rpc.ankr.com/eth_vrpc/attestation",
});

try {
  await tv.verify(requestBytes, responseBytes, res.headers);
} catch (err) {
  if (err instanceof BadSignature) {
    // err.signatureHex / err.pubkeyHex / err.preImageSha256 — safe to log (all public)
  } else if (err instanceof VerificationError && err.kind === "StaleTimestamp") {
    // clock skew or replay
  }
}
```

The error context fields (`signatureHex`, `pubkeyHex`, pre-image digest) are all
public values (emitted in headers / bound into the attestation), so logging them
to Sentry etc. is safe. The adapters re-use this exact family — a `BadSignature`
from the ethers provider is the same class you catch here.

---

## Caveats

- **Byte-exact pre-image.** `buildPreImage` mirrors the sidecar's
  `build_pre_image` byte-for-byte (`sha256(utf8(chain_id))` / `sha256(request)` /
  `sha256(response)` / `timestamp_ms` LE = 104 bytes). Any drift makes intact
  responses fail as `BadSignature`. Pinned by `packages/core/tests/preimage.test.ts`.
- **`chainId` is load-bearing.** A wrong/substituted chain id binds a different
  pre-image and surfaces as `BadSignature` even on a genuine response.
- **Bytes must be content-decoded.** `verifyResponse` hashes whatever bytes you
  give it — feed it the decoded body, not gzip wire bytes, matching what the
  sidecar signs (`v0.2.0` signs the content-decoded body).
- **Replay window is a clock contract.** Large client/server skew → `StaleTimestamp`.
- **No JSON-RPC re-implementation.** The SDK ships no JSON-RPC client —
  `TrustedVerifier`/`verifyResponse` are transport-agnostic and verify the bytes
  you hand them; batching, retries, and error envelopes are the consumer's job.

---

## Example

See `examples/03-vrpc-core-walkthrough.ts` at the repo root: signed wire →
`verifyResponse` → tamper → `BadSignature` → `fetchAttestation` →
`TrustedVerifier`. Run with
`pnpm example:03-vrpc-core-walkthrough`.
