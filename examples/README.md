# `@ankr/verifiable-rpc-client` — live examples

These four scripts drive the SDK against a live Arbitrum-One node running
geth-nitro inside an Intel TDX confidential VM. They are smoke tests and
copy-paste references — not production code.

## Live target

| Field           | Value                                                                |
| --------------- | -------------------------------------------------------------------- |
| URL             | `http://40.160.13.104:15269`                                         |
| Chain           | Arbitrum One (`chainId 0xa4b1` / 42161)                              |
| Node client     | `nitro/v3.10.1-d7f07be/linux-amd64/go1.25.10`                        |
| Sidecar pubkey  | `0x27c6308b5bdb7d8ad6d727c9e749947059e59fc2b3b9a47d443ba34838d393ac` |
| Compose hash    | `4643c3697f443c256e0d86f7a6270cc31d7c8a5c9bb56c1209ac7ab3837a935c`   |
| Captured        | 2026-05-26                                                           |

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

## What is NOT verified by these examples

This matters because it is exactly the surface someone wiring a real
integration needs to think about.

1. **Ed25519 response signature — VERIFIED.** The SDK enforces this on every
   `.call()` and throws a typed `VerificationError` subclass on any failure.

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
