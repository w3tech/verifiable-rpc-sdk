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

### Trust boundary — what verification actually proves (v6.2)

`verifyDstackAttestation` runs two **local, collateral-free** checks before the
mock gate. They establish **"signed + bound + fresh + self-consistent"** — they
do **NOT** establish **"attested to genuine Intel TDX hardware"**. A fabricated
quote can carry arbitrary `report_data` / `compose_hash`, so these checks are
only meaningful in combination with the **deferred** DCAP signature verification
(v7.0). They raise the bar (swapped-key MITM, replay, config drift) without
claiming a hardware root of trust.

- **CHK-A1 — report_data → pubkey/nonce binding (HARD).** Shape-gates
  `report_data` to 64 bytes, then asserts `report_data[0:32] == expectedPubkey`
  (the Ed25519 key the SDK verifies `vRPC-Signature` against — swapped-key /
  wrong-node defence) and `report_data[32:64] == expectedNonce` (freshness /
  anti-replay). A mismatch **always** throws `AttestationError("CHK-A1")` —
  **regardless of `allowInsecureMock`**.

- **CHK-A2 — compose-hash self-consistency (BEST-EFFORT, dormant by default).**
  When `tcbInfo.app_compose` is non-empty **and** `tcbInfo.compose_hash` is
  present + non-empty, asserts `sha256(utf8(app_compose)) == compose_hash` (raw
  bytes, **no canonicalization**); mismatch throws `AttestationError("CHK-A2")`
  (it precedes the mock gate, so it throws even under `allowInsecureMock`). When
  either side is empty/absent (nodes that don't yet serve `app_compose`, or the
  dstack simulator's empty `compose_hash`) it **skips silently — not an error**.

  > ⚠️ **CHK-A2 is self-consistency ONLY — it is NOT a trust anchor.**
  > `app_compose` and `compose_hash` both come from the **same node** (its own
  > `GET /info` + `/attestation`). A pass proves only that the node is internally
  > consistent. A malicious node simply reports an `app_compose` that hashes to
  > its own forged `compose_hash` and passes A2 trivially — **A2 is
  > attacker-forgeable**. Turning A2 into a real trust anchor requires all of:
  > (a) an **independent** compose source the node cannot forge (a pinned/signed
  > registry), (b) the `compose_hash` **anchored into RTMR3** via event-log
  > replay, and (c) a **DCAP-verified** quote. All three land in **v7.0**.

### `allowInsecureMock` — partial-verification semantics

`allowInsecureMock` gates **only** the not-yet-built layers (DCAP
quote-signature + RTMR3 replay), **never** CHK-A1 or CHK-A2:

- **absent / `false`** → after A1+A2 pass, throws `AttestationError("CHK-MOCK")`
  (fail-closed). Only the literal boolean `true` opens the hatch; any other
  truthy value (`1`, `"true"`, `{}`, …) still throws.
- **`true`** → after A1+A2 pass, resolves `void` and prints a loud `console.warn`
  partial-verification banner on **every** call (not memoized). It signals that
  CHK-A1/A2 ran but the hardware root of trust did **not** — proving
  "signed + bound + fresh", **not** "attested to hardware".

The contract stays `Promise<void>`; there is no separate status surface —
partial verification is signalled by the warning banner alone.

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
