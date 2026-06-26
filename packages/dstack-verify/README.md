# @w3tech.io/dstack-verify

Frozen contract for dstack / Intel TDX attestation verification.

> ## Attestation verification: mandatory hardware verifier
>
> `verifyDstackAttestation` enforces a **mandatory** step-4 hardware-signature
> verifier as its root of trust. If `policy.hardwareVerifier` is absent the call
> fails closed with `AttestationError("CHK-P1")`. The live SDK path (vrpc-core's
> `buildVerifyPolicy` / `TrustedVerifier`) always wires the **Phala
> CloudVerifier**, which POSTs the DCAP quote to a hosted verify endpoint,
> asserts the verdict, and binds report_data → pubkey‖nonce and compose_hash →
> `mr_config_id` (B+). It runs after the unconditional CHK-A1 (pubkey/nonce
> binding) and best-effort CHK-A2 (compose self-consistency) local checks.
>
> The legacy `allowInsecureMock` / `CHK-MOCK` escape hatch is **superseded and
> now unused** — the mandatory verifier replaces it; there is no mock-resolve
> path in the primary flow.
>
> **Still deferred to a future release:** local-DCAP (no-egress) quote
> verification, RTMR3 event-log replay, an independent (non-node-forgeable)
> compose source, and TCB-status policy. Today the hardware verdict comes from
> the Phala CloudVerifier (a remote verify API), not local DCAP.

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

Fail-closed gate:

- After CHK-A1/CHK-A2, the **mandatory** step-4 `hardwareVerifier` runs.
  `policy.hardwareVerifier` absent → **throws** `AttestationError("CHK-P1", ...)`
  (an unattested response never passes).
- A configured verifier **resolves `void`** on success and **throws** on
  failure. The live SDK path always wires the Phala CloudVerifier by default.
- `policy.allowInsecureMock` / `CHK-MOCK` is a **legacy field that is accepted
  but ignored** — it no longer gates anything.

### Types

- `AttestationBundle` — full field set: `quote` (`QuoteEnvelope`),
  `tcbInfo` (`TcbInfo` + `EventLogEntry[]`), `pubkey`, `nonce`, mandatory
  `signature_chain` (currently unused, frozen for the cross-repo ticket),
  optional `appId`/`instanceId`.
- `VerifyPolicy` — pinned trust anchors (`PinnedAllowlist`), reportData→pubkey
  binding (`ReportDataBinding`), DCAP TCB acceptance (`TcbPolicy`), optional
  `pccsUrl`, the mandatory `hardwareVerifier` (hardware root of trust), and the
  legacy, now-inert `allowInsecureMock: boolean` (accepted but ignored). An optional
  opt-in `logger` reaches `verifyDstackAttestation` here — core threads the
  verifier's injected logger in via the policy (see vrpc-core's
  "Debug logging (opt-in)"); absent → silent.

### `AttestationError`

A standalone `Error` — it deliberately does NOT extend core's `VerificationError`,
keeping this package a dependency-free leaf. Carries `chkId: ChkId` (which `CHK-*`
failed) + `detail: string`. Discriminant `kind === "Attestation"`. Narrow via
`instanceof AttestationError`. `@w3tech.io/vrpc-core` catches it at the
`verifyDstackAttestation` boundary and re-wraps it into its `VerificationError`
family (kind `"Attestation"`, original kept as `cause`), so SDK callers still
catch a single `VerificationError`.

### Verified-pubkey cache TTL (configurable)

This package only verifies attestation — the orchestration (lazy fetch + pubkey
cache) lives in `@w3tech.io/vrpc-core`'s `TrustedVerifier`. After a successful
verification the signing pubkey is cached for a configurable
TTL (`pubkeyCacheTtlMs`, default `DEFAULT_PUBKEY_CACHE_TTL_MS` = 1h): a repeat read
within the TTL skips the attestation fetch; after the TTL the pubkey is
re-attested (no stale trust). The adapters (`@w3tech.io/vrpc-ethers`,
`@w3tech.io/vrpc-viem`) forward `pubkeyCacheTtlMs` into the seam.

### Trust boundary — what verification actually proves

`verifyDstackAttestation` runs two **local, collateral-free** checks (CHK-A1,
CHK-A2) and then the **mandatory** step-4 hardware verifier. The local checks
alone establish only **"signed + bound + fresh + self-consistent"** — on their
own they do **NOT** establish **"attested to genuine Intel TDX hardware"**. The
hardware root of trust is the step-4 verifier: the live SDK default wires the
Phala CloudVerifier, which performs a hosted DCAP-quote verification plus B+
binding. With no verifier configured the call fails closed with
`AttestationError("CHK-P1")`. Local-DCAP (no-egress) verification and RTMR3
event-log replay remain deferred to a future release.

- **CHK-A1 — report_data → pubkey/nonce binding (HARD).** Shape-gates
  `report_data` to 64 bytes, then asserts `report_data[0:32] == expectedPubkey`
  (the Ed25519 key the SDK verifies `vRPC-Signature` against — swapped-key /
  wrong-node defence) and `report_data[32:64] == expectedNonce` (freshness /
  anti-replay). A mismatch **always** throws `AttestationError("CHK-A1")` — it
  is unconditional and fail-closed.

- **CHK-A2 — compose-hash self-consistency (BEST-EFFORT, dormant by default).**
  When `tcbInfo.app_compose` is non-empty **and** `tcbInfo.compose_hash` is
  present + non-empty, asserts `sha256(utf8(app_compose)) == compose_hash` (raw
  bytes, **no canonicalization**); mismatch throws `AttestationError("CHK-A2")`
  (it runs before the step-4 hardware verifier). When
  either side is empty/absent (nodes that don't yet serve `app_compose`, or the
  dstack simulator's empty `compose_hash`) it **skips silently — not an error**.

  > ⚠️ **CHK-A2 is self-consistency ONLY — it is NOT a trust anchor.**
  > `app_compose` and `compose_hash` both come from the **same node** (its own
  > `/attestation` response). A pass proves only that the node is internally
  > consistent. A malicious node simply reports an `app_compose` that hashes to
  > its own forged `compose_hash` and passes A2 trivially — **A2 is
  > attacker-forgeable**. Turning A2 into a real trust anchor requires all of:
  > (a) an **independent** compose source the node cannot forge (a pinned/signed
  > registry), (b) the `compose_hash` **anchored into RTMR3** via event-log
  > replay, and (c) a **DCAP-verified** quote. All three are future work.

### `allowInsecureMock` — legacy, inert

`allowInsecureMock` (and its `CHK-MOCK` gate) is a **superseded, now-unused**
legacy `VerifyPolicy` field — the mandatory step-4 hardware verifier replaces
it. `verify.ts` never reads it and never throws `CHK-MOCK`; whether the call
resolves or throws depends solely on `policy.hardwareVerifier` (absent → throws
`CHK-P1`; present + ok → resolves; present + fails → throws). The field is
accepted for backward compatibility but has no effect on control flow.

The contract stays `Promise<void>`; success resolves silently, failure throws
`AttestationError`.

### Pluggable hardware verifier — `HardwareVerifier` + `createCloudVerifier`

A pluggable **step-4 hardware-signature** seam (→ CHK-P1) runs **after CHK-A2**
and is the **mandatory** hardware root of trust for the call:

```ts
import { createCloudVerifier, verifyDstackAttestation } from "@w3tech.io/dstack-verify";

await verifyDstackAttestation(bundle, {
  binding: { expectedPubkey, expectedNonce },
  allowlist,
  tcb,
  hardwareVerifier: createCloudVerifier(), // hardware root of trust
});
```

- **Required (fail-closed).** A hardware verifier is mandatory. When
  `policy.hardwareVerifier` is **unset**, `verifyDstackAttestation` throws
  `AttestationError("CHK-P1", …)` after CHK-A1/A2 — an unattested response never
  passes. The legacy CHK-MOCK gate / `allowInsecureMock` is superseded and no
  longer governs. In the live SDK path, core's `buildVerifyPolicy` /
  `TrustedVerifier` always wires the Phala `CloudVerifier` by default, so the
  verifier is the hardware root of trust for every call; only its
  endpoint/implementation is overridable.
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

### Helper signatures

Exported from the public barrel and **implemented** (back the active CHK-A1 /
CHK-A2 checks):

- `computeComposeHash(appCompose): string` — CHK-A2 (raw-verbatim
  `sha256(utf8(appCompose))`, bare lowercase hex, no canonicalization).
- `parseReportData(reportDataHex): ReportDataBinding` — CHK-A1 (splits 64-byte
  report_data into pubkey ‖ nonce; throws `AttestationError` on malformed input).

Internal throwing stubs (**NOT** exported from the package barrel; importable
only from `./verify-steps`; each currently throws
`Error("... not implemented yet")` until the real DCAP layers land):

- `replayRtmr(events): string` — CHK-A4/P3 (RTMR replay, SHA-384 chain).
- `extractKeyProvider(events): KeyProvider` — CHK-P7 (key-provider identity).

The contract test (`tests/contract.test.ts`) explicitly asserts `replayRtmr` and
`extractKeyProvider` are absent from the public barrel.

## Tests

```bash
pnpm --filter '@w3tech.io/dstack-verify' test
```

- `tests/contract.test.ts` — exports, `AttestationError` is a standalone `Error`
  (not a core `VerificationError`), completeness of `CHK-A1..G3`.
- `tests/verify.test.ts` — end-to-end verify flow incl. the fail-closed gate
  (throws `CHK-P1` without a `hardwareVerifier`, resolves with a configured one;
  CHK-A1/A2 binding + compose-hash checks).
- `tests/cloud-verifier.test.ts` — cloud verifier client behavior.
- `tests/compose-hash.test.ts` — compose-hash computation.
- `tests/helpers.test.ts` — asserts the remaining throwing stubs (`replayRtmr`,
  `extractKeyProvider`) throw "not implemented", and that the implemented
  `parseReportData` throws `AttestationError(CHK-A1)` on malformed input
  (`computeComposeHash` / `parseReportData` happy paths are covered in
  `compose-hash.test.ts` / `verify.test.ts`).
