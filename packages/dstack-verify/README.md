# @ankr.com/dstack-verify

Frozen contract for dstack / Intel TDX attestation verification.

> ## ⚠️ v5.0 ships a MOCK verifier — NO real attestation security until v6.0
>
> `verifyDstackAttestation` in v5.0 is a **mock**. Real DCAP/RTMR/compose-hash
> verification only arrives in v6.0. Setting `allowInsecureMock: true` **bypasses
> all chain-of-trust checks** — it is a deliberate escape hatch that prints a
> loud `console.warn` on EVERY call and is removed entirely in v6.0.
> Never rely on v5.0 for production attestation security.

## What this is

This package freezes the full, **v6.0-complete** public surface of the
dstack/TDX attestation verifier. v6.0 (real DCAP verification) fills in the
function/helper bodies **without changing a single exported type or signature** —
the entire A/B split lives inside this package.

## Contract

### `verifyDstackAttestation(bundle, policy): Promise<void>`

Fail-closed by contract:

- **throws** `AttestationError` on verification failure,
- **resolves void** on success.

Callers never inspect a boolean — they catch `AttestationError`.

v5.0 mock semantics:

- `policy.allowInsecureMock !== true` (absent or `false`) → **throws**
  `AttestationError("CHK-MOCK", ...)` (default-deny).
- `policy.allowInsecureMock === true` → resolves void + prints a loud
  `console.warn` banner stating attestation was NOT verified — on EVERY call
  (not memoized).

### Types

- `AttestationBundle` — full v6.0 field set: `quote` (`QuoteEnvelope`),
  `tcbInfo` (`TcbInfo` + `EventLogEntry[]`), `pubkey`, `nonce`, mandatory
  `signature_chain` (unused in v5.0/3a, frozen for the 3b cross-repo ticket),
  optional `appId`/`instanceId`.
- `VerifyPolicy` — pinned trust anchors (`PinnedAllowlist`), reportData→pubkey
  binding (`ReportDataBinding`), DCAP TCB acceptance (`TcbPolicy`), optional
  `pccsUrl`, and the v5.0 escape hatch `allowInsecureMock: boolean`.

### `AttestationError`

`extends VerificationError` (the shared abstract base from `@ankr.com/vrpc-core`).
Carries `chkId: ChkId` (which `CHK-*` failed) + `detail: string`. Discriminant
`kind === "Attestation"`. Narrow via `instanceof AttestationError`. The base
union in core is NOT edited.

### Verified-pubkey cache TTL (configurable)

This package only verifies attestation — the orchestration (lazy fetch + pubkey
cache) lives in `@ankr.com/vrpc-core`'s `TrustedVerifier`. After a successful
(in v5.0 — mock) verification the signing pubkey is cached for a configurable
TTL (`pubkeyCacheTtlMs`, default `DEFAULT_PUBKEY_CACHE_TTL_MS` = 1h): a repeat read
within the TTL skips the attestation fetch; after the TTL the pubkey is
re-attested (no stale trust). The adapters (`@ankr.com/vrpc-ethers`,
`@ankr.com/vrpc-viem`) forward `pubkeyCacheTtlMs` into the seam. Remember: in v5.0
the cached result is from the **mock** check — see the banner above.

### `CHK-*` checklist

`CHK` is a frozen const record enumerating the full chain-of-trust checklist
`CHK-A1..G3` (verbatim meaning + v6.0 disposition: `implement` / `mock` /
`pinned` / `out`) plus the synthetic `CHK-MOCK` (`mock-deny`) for the v5.0
fail-closed path. It is a queryable audit dictionary — v6.0 fills in the bodies
without changing this set.

### v6.0 helper signatures (v5.0 — throwing stubs)

Frozen now, bodies filled in v6.0. In v5.0 each throws
`Error("... not implemented in v5.0 (filled in v6.0)")`:

- `replayRtmr(events): string` — CHK-A4/P3 (RTMR replay, SHA-384 chain).
- `computeComposeHash(appCompose): string` — CHK-A2 (raw-verbatim `sha256`).
- `parseReportData(reportDataHex): ReportDataBinding` — CHK-A1 (pubkey ‖ nonce).
- `extractKeyProvider(events): KeyProvider` — CHK-P7 (key-provider identity).

## Tests

```bash
pnpm --filter '@ankr.com/dstack-verify' test
```

- `tests/contract.test.ts` — exports, `AttestationError extends VerificationError`,
  completeness of `CHK-A1..G3`.
- `tests/mock.test.ts` — fail-closed mock (throws without the flag, resolves with
  it, warns on every call).
- `tests/helpers.test.ts` — helper stubs throw "not implemented in v5.0".
