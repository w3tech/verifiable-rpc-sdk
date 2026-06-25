# @ankr.com/dstack-verify

Frozen contract for dstack / Intel TDX attestation verification.

> ## ⚠️ This release ships a MOCK verifier — NO real attestation security yet
>
> `verifyDstackAttestation` is currently a **mock**. Real DCAP/RTMR/compose-hash
> verification arrives in a future release. Setting `allowInsecureMock: true` **bypasses
> all chain-of-trust checks** — it is a deliberate escape hatch that resolves
> `void` silently (the SDK prints nothing) and is removed once real
> verification lands. Never rely on the mock for production attestation security.

## What this is

This package freezes the full, **complete** public surface of the
dstack/TDX attestation verifier. A future release (real DCAP verification) fills in the
function/helper bodies **without changing a single exported type or signature** —
the entire A/B split lives inside this package.

## Contract

### `verifyDstackAttestation(bundle, policy): Promise<void>`

Fail-closed by contract:

- **throws** `AttestationError` on verification failure,
- **resolves void** on success.

Callers never inspect a boolean — they catch `AttestationError`.

Mock semantics:

- `policy.allowInsecureMock !== true` (absent or `false`) → **throws**
  `AttestationError("CHK-MOCK", ...)` (default-deny).
- `policy.allowInsecureMock === true` → resolves `void` **silently** (the SDK
  prints nothing). It bypasses the hardware root of trust as an explicit caller
  opt-in (fail-closed by default).

### Types

- `AttestationBundle` — full field set: `quote` (`QuoteEnvelope`),
  `tcbInfo` (`TcbInfo` + `EventLogEntry[]`), `pubkey`, `nonce`, mandatory
  `signature_chain` (currently unused, frozen for the cross-repo ticket),
  optional `appId`/`instanceId`.
- `VerifyPolicy` — pinned trust anchors (`PinnedAllowlist`), reportData→pubkey
  binding (`ReportDataBinding`), DCAP TCB acceptance (`TcbPolicy`), optional
  `pccsUrl`, and the escape hatch `allowInsecureMock: boolean`.

### `AttestationError`

`extends VerificationError` (the shared abstract base from `@ankr.com/vrpc-core`).
Carries `chkId: ChkId` (which `CHK-*` failed) + `detail: string`. Discriminant
`kind === "Attestation"`. Narrow via `instanceof AttestationError`. The base
union in core is NOT edited.

### Verified-pubkey cache TTL (configurable)

This package only verifies attestation — the orchestration (lazy fetch + pubkey
cache) lives in `@ankr.com/vrpc-core`'s `TrustedVerifier`. After a successful
(currently mock) verification the signing pubkey is cached for a configurable
TTL (`pubkeyCacheTtlMs`, default `DEFAULT_PUBKEY_CACHE_TTL_MS` = 1h): a repeat read
within the TTL skips the attestation fetch; after the TTL the pubkey is
re-attested (no stale trust). The adapters (`@ankr.com/vrpc-ethers`,
`@ankr.com/vrpc-viem`) forward `pubkeyCacheTtlMs` into the seam. Remember: while
the verifier is a mock the cached result is from the **mock** check — see the banner above.

### Trust boundary — what verification actually proves

`verifyDstackAttestation` runs two **local, collateral-free** checks before the
mock gate. They establish **"signed + bound + fresh + self-consistent"** — they
do **NOT** establish **"attested to genuine Intel TDX hardware"**. A fabricated
quote can carry arbitrary `report_data` / `compose_hash`, so these checks are
only meaningful in combination with the **deferred** DCAP signature verification
(a future release). They raise the bar (swapped-key MITM, replay, config drift) without
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
  > replay, and (c) a **DCAP-verified** quote. All three are future work.

### `allowInsecureMock` — partial-verification semantics

`allowInsecureMock` gates **only** the not-yet-built layers (DCAP
quote-signature + RTMR3 replay), **never** CHK-A1 or CHK-A2:

- **absent / `false`** → after A1+A2 pass, throws `AttestationError("CHK-MOCK")`
  (fail-closed). Only the literal boolean `true` opens the hatch; any other
  truthy value (`1`, `"true"`, `{}`, …) still throws.
- **`true`** → after A1+A2 pass, resolves `void` **silently** (the SDK prints
  nothing). CHK-A1/A2 ran but the hardware root of trust did **not** — proving
  "signed + bound + fresh", **not** "attested to hardware". Bypassing the
  hardware root of trust is an explicit caller opt-in (fail-closed by default).

The contract stays `Promise<void>`; there is no separate status surface —
partial verification carries no signal beyond the silent resolve.

### Pluggable hardware verifier — `HardwareVerifier` + `createCloudVerifier`

A pluggable **step-4 hardware-signature** seam (→ CHK-P1) runs **after CHK-A2**
and, when configured, **bypasses the CHK-MOCK gate** on success. It is **opt-in**:

```ts
import { createCloudVerifier, verifyDstackAttestation } from "@ankr.com/dstack-verify";

await verifyDstackAttestation(bundle, {
  binding: { expectedPubkey, expectedNonce },
  allowlist,
  tcb,
  hardwareVerifier: createCloudVerifier(), // ← opt-in
});
```

- **Opt-in.** When `policy.hardwareVerifier` is **unset**, behavior is
  **unchanged** — the CHK-MOCK gate / `allowInsecureMock` governs exactly as
  before. Setting it makes the verifier the hardware root of trust for the call.
- **Configurable.** `createCloudVerifier({ endpoint?, timeoutMs?, fetch? })` —
  the `endpoint` defaults to the Phala URL, `timeoutMs` bounds the request
  (`AbortController`), and `fetch` is injectable (tests; default
  `globalThis.fetch` — no new runtime dependency).
- ⚠️ **Unauthenticated, best-effort / no-SLA.** The default Phala cloud endpoint
  is a public, **unauthenticated** service provided **"AS IS"** with no SLA.
- ⚠️ **Publishes the quote to a PUBLIC registry.** Every quote POSTed to the
  cloud endpoint is stored permanently and is **publicly** readable by checksum
  (`/attestations/view/{checksum}`). This is a privacy / data-egress caveat;
  callers opting in accept it. Point `endpoint` at a self-hosted verifier to
  avoid the egress.
- **Trust shifts to Phala's hosted verifier** (vs the local-DCAP, no-egress path
  planned for a later release).
- **B+ binding — `verified` alone is not trusted.** Because the node is
  untrusted, the SDK does not accept `result.quote.verified === true` on its own:
  it also binds the cloud-extracted `reportdata` to the **expected
  pubkey ‖ nonce** and requires the `composeHash` to be measured into
  `mr_config_id`. A real-but-foreign quote (genuine, but for a different
  key/node) therefore **fails closed**.

### `CHK-*` checklist

`CHK` is a frozen const record enumerating the full chain-of-trust checklist
`CHK-A1..G3` (verbatim meaning + disposition: `implement` / `mock` /
`pinned` / `out`) plus the synthetic `CHK-MOCK` (`mock-deny`) for the
fail-closed path. It is a queryable audit dictionary — a future release fills in the bodies
without changing this set.

### Helper signatures (throwing stubs)

Frozen now, bodies filled in a future release. Each currently throws
`Error("... not implemented yet")`:

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
- `tests/mock.test.ts` — fail-closed mock (throws without the flag, resolves
  silently with it).
- `tests/helpers.test.ts` — helper stubs throw "not implemented".
