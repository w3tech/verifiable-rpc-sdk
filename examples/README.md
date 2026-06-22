# `@ankr/verifiable-rpc-client` — live examples

These scripts drive the SDK against a live Arbitrum-One node running geth-nitro
inside an Intel TDX confidential VM (scripts 06–09 route through stage
shark-proxy). They are smoke tests and copy-paste references — not production
code. **Script 10 is the exception: it runs fully OFFLINE** (injected mock fetch,
no env, no network) and exits 0 in CI — it demonstrates the v5.0
lazy-attestation flow against the MOCK verifier.

> [!WARNING]
> **v5.0 attestation is a MOCK — NO real attestation security until v6.0.** Example
> 10 exercises the lazy-attestation FLOW + pubkey cache against the v5.0 mock
> verifier (`allowInsecureMock` hard-set true, loud `console.warn` per attestation):
> *"v5.0 provides NO real attestation security (real verification lands in v6.0)."*
> Real DCAP/RTMR/compose-hash verification arrives in v6.0.

## Live target

| Field           | Value                                                                |
| --------------- | -------------------------------------------------------------------- |
| URL             | `http://40.160.13.104:15269`                                         |
| Chain           | Arbitrum One (`chainId 0xa4b1` / 42161)                              |
| Node client     | `nitro/v3.10.1-d7f07be/linux-amd64/go1.25.10`                        |
| Sidecar pubkey  | `0x27c6308b5bdb7d8ad6d727c9e749947059e59fc2b3b9a47d443ba34838d393ac` |
| Compose hash    | `287a19287bb1d6c798e8cc80aacf0e33d7f1c6982ba28c6135bf4aa3e4b1024e`   |
| Sidecar version | `v0.2.0-rc.1` (compression-aware signing — signs content-decoded body) |
| Captured        | 2026-06-10                                                           |

If the sidecar is redeployed, the pubkey and compose-hash above WILL change
and scripts 03 + 04 will fail loudly. Update `PINNED_COMPOSE_HASH` in
`examples/shared.ts` and re-run.

## Run

```sh
pnpm install
pnpm example:01-signed-call
pnpm example:02-batch-and-replay
pnpm example:03-fetch-attestation
pnpm example:04-end-to-end
pnpm example:05-gzip-transport
pnpm example:06-via-shark              # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
pnpm example:07-attestation-via-shark  # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
pnpm example:08-vrpc-ethers-verified-read  # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
pnpm example:09-vrpc-viem-verified-read    # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
pnpm example:10-vrpc-lazy-attestation      # OFFLINE — no env, no network; exits 0 in CI
# Or:
pnpm example:all
```

Each script prints its checks line-by-line and ends with `PASS — …` (exit 0)
or `FAIL — …` (exit 1).

## What each script proves

| #  | File                          | Proves                                                                                                                                |
| -- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 01 | `01-signed-call.ts`           | The SDK speaks the wire contract: signed `eth_blockNumber`, Ed25519 verifies, all `VerifiedResponse` fields are well-formed.          |
| 02 | `02-batch-and-replay.ts`      | Four sequential calls succeed, the pubkey is stable across them, and the sidecar's `vRPC-Timestamp` stays inside the replay window.   |
| 03 | `03-fetch-attestation.ts`     | `report_data == pubkey ‖ nonce` byte binding (SPEC-04), and the inner `event_log compose-hash` agrees with the top-level `composeHash`. |
| 04 | `04-end-to-end.ts`            | Fetch attestation → anchor trust in the returned pubkey → signed call → require the signature pubkey matches the attested pubkey.     |
| 05 | `05-gzip-transport.ts`       | Sidecar v0.2.0 signs the content-DECODED body: a `Accept-Encoding: gzip` response with `content-encoding: gzip` on the wire is gunzipped and the Ed25519 signature verifies over the decoded plaintext. Negative control — verifying over the compressed wire bytes FAILS — proves the signature covers decoded, not compressed, bytes. |
| 06 | `06-via-shark.ts`           | Proves the SDK verifies a signed call routed THROUGH stage shark-proxy (vrpc passthrough): byte-exact request/response (signature verifies), vrpc headers survive shark, and the via-shark pubkey matches the direct node /attestation pubkey. On FAIL it raw-fetches both legs to localize the break (headers stripped vs body mutated). |
| 07 | `07-attestation-via-shark.ts` | Full trustless loop entirely through shark: signed `.call()` → capture `nodeId` (`vRPC-NodeId`) → `fetchAttestation({ attestationUrl, nodeId, nonce })` (the attestation URL is derived from the plain shark route via `deriveVrpcUrls`) with a fresh 32B nonce → `verifyAttestationCorrelation` (attestation pubkey == `vRPC-Pubkey`). Negative path: a bogus `node_id` surfaces the typed `AttestationNodeNotFoundError` (404, no retry, no fallback). |
| 08 | `08-vrpc-ethers-verified-read.ts` | Drop-in ethers `VrpcProvider` verified read + `anchorTrust` correlation through a stage shark `arbitrum_vrpc` route (operator step — live creds via env). |
| 09 | `09-vrpc-viem-verified-read.ts` | Drop-in viem `vrpcHttp` + `createPublicClient` verified read + `anchorTrust` correlation (symmetric with 08; operator step — live creds via env). |
| 10 | `10-vrpc-lazy-attestation.ts` | **OFFLINE** (injected mock fetch, no env, no network — exits 0 in CI): the v5.0 lazy-attestation flow through **both** adapters, now **always-on** (derived from the single URL — no `attestationBaseUrl`/`chainSlug` opt-in). An unknown signing pubkey triggers one attestation fetch + (MOCK) verify + cache; the second read within TTL reuses the cache (asserts the attestation GET is hit exactly once per adapter). Demonstrates the FLOW, **not real attestation** — the v5.0 verifier is a mock (see the banner above). |

## Via shark (vrpc routing)

Examples 06 and 07 route the same signed call through stage shark-proxy instead
of hitting the node directly. Shark recognises a **`_vrpc` chain suffix** as a
verifiable-RPC route that must pass request/response bytes through unmodified.
You pass the SDK **one** plain URL (`<shark-url>/arbitrum`) and it owns the
route suffix: `deriveVrpcUrls` appends `_vrpc` for the RPC leg
(`<shark-url>/arbitrum_vrpc`) and `/attestation` for the attestation leg
(`<shark-url>/arbitrum_vrpc/attestation`), dup-guarded so a URL that already
ends with `_vrpc` is not doubled. Auth is the **`x-api-key` header** (06 sends
it via the SDK's `headers` opt; 07 uses the cleaner first-class `apiKey`
option). A passing signed `.call()` through shark IS the cryptographic proof of
byte-exact passthrough: the 80-byte pre-image binds request_hash +
response_hash, so any mutation in either direction surfaces as `BadSignature`.

Stage shark (running `v0.26.21-rc.vrpc.1`) now serves the targeted attestation
route `GET <shark-url>/arbitrum_vrpc/attestation?nonce=<hex>&node_id=<id>`, so
example 07 closes the entire trustless loop **through shark**: signed call →
capture `nodeId` → `fetchAttestation({ attestationUrl, nodeId, nonce })` (one
`fetchAttestation` — there is no separate `fetchAttestationViaShark`) → pubkey
correlation. `node_id` is included when present and omitted when absent
(shark-without-node_id then fails to route, fail-closed). A bogus `node_id`
returns `404` as the typed `AttestationNodeNotFoundError` with no retry or
fallback.

Two env vars are required (referenced **by name only** — their values are
secrets and are never printed, logged, or committed; the example fails clearly
if either is unset):

| Env var                    | Purpose                                  |
| -------------------------- | ---------------------------------------- |
| `SHARK_STAGE_URL`          | Stage shark-proxy base URL               |
| `SHARK_STAGE_TDX_TEST_KEY` | `x-api-key` value for the vrpc route     |

Example 06's pubkey cross-check fetches the attestation DIRECT from the node
(`http://40.160.13.104:15269/attestation`); example 07 fetches it THROUGH shark
by `node_id` (the stage shark now serves the targeted attestation route) and is
the recommended shark-only integration path.

## What is NOT verified by these examples

This matters because it is exactly the surface someone wiring a real
integration needs to think about.

1. **Ed25519 response signature — VERIFIED, on either transport encoding.**
   The SDK enforces this on every `.call()` and throws a typed
   `VerificationError` subclass on any failure. As of sidecar v0.2.0 the
   signature covers the content-DECODED (plaintext) body, so a standard
   auto-decoding HTTP client verifies whether it requested `gzip` or
   `identity` (script 05 proves this on the live gzip path). `VerifierClient`
   still pins `accept-encoding: identity` as defense-in-depth — it keeps the
   hashed bytes byte-identical to the wire bytes and avoids relying on the
   proxy's re-encoding — but correctness no longer depends on it.

2. **TDX quote vs Intel PCK root — NOT VERIFIED.** The quote is fetched and
   surfaced (`Attestation.quote.quote` is the raw TD report + PCK cert chain),
   but verifying it cryptographically against an Intel root and decoding
   MRTD / RTMR / TCB level is out of scope for this milestone. That is the
   registry-v1 follow-up; see `.planning/workstreams/vrpc/` and the open
   decision DEC-03.

3. **`composeHash` provenance — HARD-PINNED.** We hard-code the current
   sidecar's compose-hash. There is no registry yet. If the sidecar is
   redeployed with a new compose, scripts 03 + 04 will fail and you must
   re-pin manually. The plan for the registry lives in
   `.planning/workstreams/vrpc/seeds/freshness-anchor.md` and the
   v3.0 PRD reframe in Phase 22.

4. **Disk-layer correctness of the underlying nitro node — NOT VERIFIED.**
   The TEE boundary covers RAM and the signing pre-image. It does NOT cover
   silent on-disk state corruption. See
   `.planning/workstreams/vrpc/deliberations/disk-trust-boundary.md` and
   `.planning/workstreams/vrpc/research/geth-disk-integrity-deep-dive.md`
   for the full analysis (Phase 22 + Phase 23).

5. **v5.0 lazy attestation (example 10) is a MOCK — NOT real attestation.**
   The seam wiring (lazy fetch → correlate → verify → cache) is real and proven
   offline, but the attestation verifier in v5.0 is a mock with
   `allowInsecureMock` hard-set true that **bypasses all chain-of-trust checks**
   and warns on every call: *"v5.0 provides NO real attestation security (real
   verification lands in v6.0)."* Example 10 demonstrates the FLOW + pubkey
   cache, not real TDX attestation. Real DCAP/RTMR/compose-hash verification is
   the v6.0 follow-up.

## Captured live output

The output of the first successful live run lives in
`.planning/workstreams/vrpc/phases/24-sdk-live-examples-vs-tdx-node-examples-package-on-verifiable/output/`
as proof-of-life. Newer runs are not committed automatically.
