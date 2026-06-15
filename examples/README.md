# `@ankr/verifiable-rpc-client` — live examples

These seven scripts drive the SDK against a live Arbitrum-One node running
geth-nitro inside an Intel TDX confidential VM (scripts 06 and 07 route through
stage shark-proxy). They are smoke tests and copy-paste references — not
production code.

## Live target

| Field           | Value                                                                |
| --------------- | -------------------------------------------------------------------- |
| URL             | `http://40.160.13.104:15269`                                         |
| Chain           | Arbitrum One (`chainId 0xa4b1` / 42161)                              |
| Node client     | `nitro/v3.10.1-d7f07be/linux-amd64/go1.25.10`                        |
| Sidecar pubkey  | `0x27c6308b5bdb7d8ad6d727c9e749947059e59fc2b3b9a47d443ba34838d393ac` |
| Compose hash    | `69166ce46dfc031ee6c55ebc6e7758a56aab514c74d847f24b4dda0448513301`   |
| Sidecar version | `v0.2.0-rc.1` (compression-aware signing — signs content-decoded body) |
| Captured        | 2026-06-10                                                           |

If the sidecar is redeployed, the pubkey and compose-hash above WILL change
and scripts 03 + 04 will fail loudly. Update `PINNED_COMPOSE_HASH` in
`examples/shared.ts` and re-run.

## Run

```sh
bun install
bun run example:01-signed-call
bun run example:02-batch-and-replay
bun run example:03-fetch-attestation
bun run example:04-end-to-end
bun run example:05-gzip-transport
bun run example:06-via-shark              # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
bun run example:07-attestation-via-shark  # requires SHARK_STAGE_URL + SHARK_STAGE_TDX_TEST_KEY (see below)
# Or:
bun run example:all
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
| 07 | `07-attestation-via-shark.ts` | Full trustless loop entirely through shark: signed `.call()` → capture `nodeId` (`vRPC-NodeId`) → `fetchAttestationViaShark` by that node_id with a fresh 32B nonce → `verifyAttestationCorrelation` (attestation pubkey == `vRPC-Pubkey`). Negative path: a bogus `node_id` surfaces the typed `AttestationNodeNotFoundError` (404, no retry, no fallback). |

## Via shark (vrpc routing)

Examples 06 and 07 route the same signed call through stage shark-proxy instead
of hitting the node directly. Shark recognises a **`_vrpc` chain suffix** as a
verifiable-RPC route that must pass request/response bytes through unmodified —
so the vrpc route URL is `<shark-url>/arbitrum_vrpc`. Auth is the **`x-api-key`
header** (06 sends it via the SDK's `headers` opt; 07 uses the cleaner
first-class `apiKey` option). A passing signed `.call()` through shark IS the
cryptographic proof of byte-exact passthrough: the 80-byte pre-image binds
request_hash + response_hash, so any mutation in either direction surfaces as
`BadSignature`.

Stage shark (running `v0.26.21-rc.vrpc.1`) now serves the targeted attestation
route `GET <shark-url>/arbitrum_vrpc/attestation?nonce=<hex>&node_id=<id>`, so
example 07 closes the entire trustless loop **through shark**: signed call →
capture `nodeId` → `fetchAttestationViaShark` by that node_id → pubkey
correlation. A bogus `node_id` returns `404` as the typed
`AttestationNodeNotFoundError` with no retry or fallback.

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

## Captured live output

The output of the first successful live run lives in
`.planning/workstreams/vrpc/phases/24-sdk-live-examples-vs-tdx-node-examples-package-on-verifiable/output/`
as proof-of-life. Newer runs are not committed automatically.
