# @ankr.com/dstack-verify

Frozen contract for dstack / Intel TDX attestation verification.

> ## ⚠️ v5.0 ships a MOCK verifier — NO real attestation security until v6.0
>
> `verifyDstackAttestation` в v5.0 — это **mock**. Реальная DCAP/RTMR/compose-hash
> верификация appears только в v6.0. Setting `allowInsecureMock: true` **bypasses
> all chain-of-trust checks** — это осознанная escape-hatch, которая печатает
> громкий `console.warn` на КАЖДЫЙ вызов и полностью удаляется в v6.0.
> Никогда не полагайтесь на v5.0 для production attestation security.

## Что это

Пакет замораживает полную, **v6.0-complete** публичную поверхность верификатора
dstack/TDX-attestation. v6.0 (реальная DCAP-верификация) заполняет тела
функций/хелперов **не меняя ни одного экспортируемого типа или сигнатуры** —
весь A/B-split живёт внутри этого пакета.

## Контракт

### `verifyDstackAttestation(bundle, policy): Promise<void>`

Fail-closed по контракту:

- **бросает** `AttestationError` при провале верификации,
- **резолвится void** при успехе.

Callers никогда не инспектируют boolean — они ловят `AttestationError`.

v5.0 mock-семантика:

- `policy.allowInsecureMock !== true` (отсутствует или `false`) → **throws**
  `AttestationError("CHK-MOCK", ...)` (default-deny).
- `policy.allowInsecureMock === true` → резолвится void + печатает громкий
  `console.warn` баннер о том, что attestation НЕ верифицирована — на КАЖДЫЙ
  вызов (не мемоизировано).

### Types

- `AttestationBundle` — полный v6.0 field-set: `quote` (`QuoteEnvelope`),
  `tcbInfo` (`TcbInfo` + `EventLogEntry[]`), `pubkey`, `nonce`, обязательный
  `signature_chain` (unused в v5.0/3a, заморожен под 3b cross-repo ticket),
  опциональные `appId`/`instanceId`.
- `VerifyPolicy` — pinned trust anchors (`PinnedAllowlist`), reportData→pubkey
  binding (`ReportDataBinding`), DCAP TCB acceptance (`TcbPolicy`), опциональный
  `pccsUrl`, и v5.0 escape-hatch `allowInsecureMock: boolean`.

### `AttestationError`

`extends VerificationError` (shared abstract base из `@ankr.com/vrpc-core`).
Несёт `chk: ChkId` (какой `CHK-*` провалился) + `detail: string`. Discriminant
`kind === "Attestation"`. Narrow через `instanceof AttestationError`. Базовый
union в core НЕ редактируется.

### Verified-pubkey cache TTL (configurable)

Этот пакет only верифицирует attestation — orchestration (lazy fetch + pubkey
cache) живёт в `@ankr.com/vrpc-core` `TrustedVerifier`. После успешной (в v5.0 —
mock) верификации signing-pubkey кешируется на configurable TTL
(`pubkeyCacheTtl`, default `DEFAULT_PUBKEY_CACHE_TTL_MS` = 1h): повторный read в
пределах TTL skip'ает attestation fetch, после TTL — pubkey ре-аттестуется (no
stale trust). Adapters (`@ankr.com/vrpc-ethers`, `@ankr.com/vrpc-viem`) пробрасывают
`pubkeyCacheTtl` в seam. Помните: в v5.0 кешируется результат **mock** проверки —
см. баннер выше.

### `CHK-*` checklist

`CHK` — frozen const record, перечисляющий полный chain-of-trust checklist
`CHK-A1..G3` (verbatim meaning + v6.0 disposition: `implement` / `mock` /
`pinned` / `out`) плюс синтетический `CHK-MOCK` (`mock-deny`) для v5.0
fail-closed пути. Это queryable audit-словарь — v6.0 заполняет тела не меняя
этот набор.

### v6.0 helper signatures (v5.0 — throwing stubs)

Заморожены сейчас, тела заполняются в v6.0. В v5.0 каждый бросает
`Error("... not implemented in v5.0 (filled in v6.0)")`:

- `replayRtmr(events): string` — CHK-A4/P3 (RTMR replay, SHA-384 chain).
- `computeComposeHash(appCompose): string` — CHK-A2 (raw-verbatim `sha256`).
- `parseReportData(reportDataHex): ReportDataBinding` — CHK-A1 (pubkey ‖ nonce).
- `extractKeyProvider(events): KeyProvider` — CHK-P7 (key-provider identity).

## Тесты

```bash
bun test packages/dstack-verify
```

- `tests/contract.test.ts` — экспорты, `AttestationError extends VerificationError`,
  полнота `CHK-A1..G3`.
- `tests/mock.test.ts` — fail-closed mock (throws без флага, resolves с флагом,
  warn на каждый вызов).
- `tests/helpers.test.ts` — helper-стабы бросают «not implemented in v5.0».
