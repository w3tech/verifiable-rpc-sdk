# @w3tech.io/vrpc-core

Transport-agnostic Ed25519 verification primitives for Ankr's verifiable RPC.

This is the verification **engine** — the layer both the ethers and viem
adapters build on. It owns the canonical 104-byte pre-image, the Ed25519
signature check, the replay window, the attestation fetch/correlation helpers,
and the typed `VerificationError` family. It has **no blockchain-client
dependency** — its runtime deps are `@noble/ed25519`, `@noble/hashes`,
`lru-cache` (pubkey cache), and the sibling `@w3tech.io/dstack-verify` (hardware
verifier).
Pairs with the `verifiable-rpc-sidecar` `v0.5.0` wire contract.

**Version gate:** SDK `>=0.3.0` requires sidecar `>=0.5.0` (string chain id
hashed into the 104-byte pre-image). Older sidecars sign the legacy pre-image
and verification fails closed.

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
and `BigUint64` `DataView` support (Node 18+, Bun, modern browsers).

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
  the response header. `verifyAttestationCorrelation`
  additionally correlates that key against the serving node's attestation pubkey.

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
const provider = new VrpcProvider("https://rpc.ankr.com/eth", 1, {
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
verifyAttestationCorrelation(attestation: Attestation, signerPubkeyHex: string, logger?: Logger): void;
```

`fetchAttestation` (the single attestation-fetch entry point) calls
`GET <attestationUrl>?nonce=<bare-hex>`, appending `&node_id=<id>` **only when**
`opts.nodeId` is present. `FetchAttestationOptions` =
`{ attestationUrl, nonce, nodeId?, headers?, fetch? }`. A `404` →
`AttestationNodeNotFoundError`, terminal — no retry/fallback. The nonce must be
exactly 32 bytes or `InvalidNonce` is thrown **before** any network call. This
route is unsigned by contract — no `vRPC-*` verification runs, and a malformed
body throws `MalformedAttestationResponse`. `fetchAttestation` is called lazily
per request by `TrustedVerifier` as its attestation seam, and is available
standalone for direct use.
`verifyAttestationCorrelation` asserts `attestation.pubkey === signerPubkeyHex`
(the `vRPC-Pubkey` of the verified response, lowercase `0x`-hex), throwing
`AttestationCorrelationError` on mismatch. It is called by `TrustedVerifier`'s
lazy attestation leg.

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
| `parseChainId(...)` | function | Decodes a decimal-string chainId (e.g. `"42161"`) from the raw bytes of a signed `eth_chainId` response (the auto-derive bootstrap used by the ethers/viem adapters); throws `MalformedHeader` on invalid JSON or a non-0x-hex `result`. |
| `validateChainId(...)` | function | Validates a chain id string (sidecar-identical rules: non-empty, ≤64 bytes, printable ASCII, no inner whitespace) and returns the trimmed value; throws `InvalidChainId`. |
| `isSignedVrpcResponse(...)` | function | Predicate: whether a response carries the `vRPC-*` signing headers. |

---

## Errors

Every verification failure throws a subclass of the abstract `VerificationError`
(extends `Error`). Narrow with `instanceof` or the `kind` discriminator.

| Class                          | `kind`                          | Thrown when                                                       |
| ------------------------------ | ------------------------------- | ----------------------------------------------------------------- |
| `MissingHeader`                | `"MissingHeader"`               | A required `vRPC-*` header is absent. `.headerName`               |
| `MalformedHeader`              | `"MalformedHeader"`             | Header present but fails shape validation. `.headerName/.value/.reason` |
| `BadSignature`                 | `"BadSignature"`                | Ed25519 verify failed (tampered bytes or wrong chainId). `.signatureHex/.pubkeyHex/.preImageSha256` |
| `StaleTimestamp`               | `"StaleTimestamp"`              | Valid signature but timestamp outside replay window. `.observedMs/.nowMs/.skewMs/.allowedWindowMs` |
| `InvalidNonce`                 | `"InvalidNonce"`                | Attestation nonce not exactly 32 bytes. `.reason`                |
| `InvalidChainId`               | `"InvalidChainId"`              | Chain id string fails `validateChainId` (empty, >64 bytes, non-printable-ASCII or whitespace). Thrown at construction / verify entry. `.chainId/.reason` |
| `MalformedAttestationResponse` | `"MalformedAttestationResponse"`| `/attestation` body off-contract. `.reason`                      |
| `AttestationNodeNotFoundError` | `"AttestationNodeNotFound"`     | The RPC gateway returned 404 for the targeted `node_id`. `.nodeId` |
| `AttestationCorrelationError`  | `"AttestationCorrelation"`      | Attestation pubkey ≠ response signer. `.expectedPubkey/.actualPubkey` |

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
`verifyResponse` → tamper → `BadSignature` → `fetchAttestation` + correlation via
`verifyAttestationCorrelation` → `TrustedVerifier`. Run with
`pnpm example:03-vrpc-core-walkthrough`.
