# verifiable-rpc-sdk

TypeScript verifier client for Ankr's verifiable RPC sidecar
(`verifiable-rpc-sidecar`). Verifies Ed25519-signed JSON-RPC responses and
fetches TDX attestation quotes from the sidecar. Pairs with sidecar `v0.5.0`
wire contract — string chain id hashed into a 104-byte pre-image; the signature
covers the content-DECODED body, so it verifies on either transport encoding
(gzip or identity). ESM-first, vitest-tested, chain-agnostic.

**Version gate:** SDK `>=0.3.0` requires sidecar `>=0.5.0` (string chain id,
104-byte pre-image). Older sidecars sign the legacy format and verification
fails closed. Coordinated release — deployed nodes keep their image until the
compose bump.

## Commands

| Action           | Command                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Install          | `pnpm install`                                                                                       |
| Test (whole workspace) | `pnpm -r test` (from repo root)                                                                |
| Unit test only   | per-package: `cd packages/core && pnpm run test:unit` (or `pnpm --filter '@w3tech.io/vrpc-core' test:unit`) |
| Integration test | per-package: `cd packages/core && DSTACK_SIMULATOR_BIN=… DSTACK_SIMULATOR_FIXTURES_DIR=… SIDECAR_BIN=… pnpm run test:integration` (or via `pnpm --filter '@w3tech.io/vrpc-core' test:integration`) |
| Lint             | `pnpm run lint`                                                                                      |
| Format check     | `pnpm run format:check`                                                                              |
| Format fix       | `pnpm run format`                                                                                    |
| Typecheck        | `pnpm -r typecheck` (root fans out: `pnpm -r typecheck`; per-package leaf is `tsc --noEmit`) |
| Docker build     | `docker build -t vrpc-proxy .` (root `Dockerfile`; amd64 production image). The docker-only bundle step alone: `pnpm --filter '@w3tech.io/vrpc-proxy' run build:docker` |

## Pre-push gate (mandatory)

**Before every `git push`** run all four in order. CI runs the same set — fix
locally rather than letting CI fail.

```sh
pnpm run format:check   # exit 0 — no diff
pnpm run lint           # exit 0
pnpm -r typecheck       # exit 0 (tsc --noEmit)
pnpm -r test            # all green
```

If `pnpm run format:check` fails: run `pnpm run format`, commit the diff as a
SEPARATE commit, do not amend the offending commit.

The pre-push gate is a contract — there is no git hook enforcing it (a hook is
deferred to a later ops cycle).

## Integration tests

End-to-end tests under `packages/core/tests/integration/` spawn a real sidecar binary backed
by Phala's dstack simulator and an in-process mock JSON-RPC upstream. They
prove the SDK matches the live wire contract — the unit tests pin the crypto
with real Ed25519 keys; the integration tests pin the bytes that flow over the
network. The two suites complement each other and intentionally do not overlap.

**Required env vars (any unset → integration suite skips cleanly):**

| Var                             | Default on dev box                                                            |
| ------------------------------- | ----------------------------------------------------------------------------- |
| `DSTACK_SIMULATOR_BIN`          | `/private/tmp/dstack-sim-test/dstack-simulator`                               |
| `DSTACK_SIMULATOR_FIXTURES_DIR` | `/private/tmp/dstack-sim-test`                                                |
| `SIDECAR_BIN`                   | `../verifiable-rpc-sidecar/target/debug/rpc-attest-sidecar` (sibling repo)    |

Build the sidecar with `cargo build` in the sibling `verifiable-rpc-sidecar`
repo before running integration tests. The debug binary is fine — release is
not required.

**Local invocation:**

```sh
DSTACK_SIMULATOR_BIN=/private/tmp/dstack-sim-test/dstack-simulator \
DSTACK_SIMULATOR_FIXTURES_DIR=/private/tmp/dstack-sim-test \
SIDECAR_BIN=../verifiable-rpc-sidecar/target/debug/rpc-attest-sidecar \
  pnpm --filter '@w3tech.io/vrpc-core' test:integration
```

`pnpm -r test` (no env vars) runs the unit suite only and emits a one-line skip
message at module load. `pnpm -r test` with all three env vars set runs the unit
suite plus the integration suite.

**Tamper and replay are unit-only.** Both code paths are already covered at
the unit level with real Ed25519 sign+verify
(`tamperedResponseBodyThrowsBadSignature` and the replay-window edge tests) —
adding integration-level versions would exercise the same logic against a
slower harness without catching anything new. Integration tests focus on the
value adds: happy-path call, cross-endpoint pubkey consistency, and a
real-wire canonical attestation fixture (`packages/core/tests/fixtures/attestation-v0.1.0.json`).

**CI deferral:** CI runs the unit suite only. A dedicated integration matrix
with the simulator binary on the runner is tracked separately.

## Architecture

- Monorepo: pnpm workspaces under `packages/*` — `core` (`@w3tech.io/vrpc-core`,
  the verification primitives), `ethers` (`@w3tech.io/vrpc-ethers`), `viem`
  (`@w3tech.io/vrpc-viem`), `dstack-verify` (`@w3tech.io/dstack-verify`), and
  `proxy` (`@w3tech.io/vrpc-proxy`, local verifying reverse proxy + `vrpc-proxy` CLI).
- Public surface re-exported through `packages/core/src/index.ts`; implementation
  lives in `packages/core/src/trusted-verifier.ts`, `packages/core/src/verify.ts`,
  `packages/core/src/attestation.ts`,
  `packages/core/src/errors.ts`, `packages/core/src/preimage.ts` (plus
  `utils.ts`, `vrpc-url.ts`, `logger.ts`, `log-redact.ts`). Compose-hash
  logic lives outside core: `computeComposeHash` is in
  `packages/dstack-verify/src/verify-steps.ts` (exported via
  `@w3tech.io/dstack-verify`).
- SDK is a thin verifier wrapping `fetch` — no JSON-RPC re-implementation, no
  batching, no method-specific decoders.
- Pairs with `verifiable-rpc-sidecar` `v0.5.0`. Wire contract = the 104-byte
  canonical pre-image (`sha256(utf8(chain_id))` ‖ `sha256(req)` ‖ `sha256(resp)`
  ‖ `timestamp_ms` u64 LE) + `vRPC-Signature` / `vRPC-Timestamp` / `vRPC-Pubkey`
  headers + `/attestation?nonce=<hex>` JSON shape. Version gate: SDK `>=0.3.0`
  requires sidecar `>=0.5.0` — older sidecars sign the legacy pre-image and
  verification fails closed. As of sidecar v0.2.0 the signature covers the
  content-DECODED (plaintext) body, so it verifies whether the client requested
  gzip or identity. The `03-vrpc-core-walkthrough.ts` example and
  `packages/core/README.md` describe the content-decoded-body signing introduced
  in v0.2.0.
- **Content encoding is not a correctness concern.** Since v0.2.0 the sidecar
  signs the content-decoded body, so a standard auto-decoding `fetch` (which
  gunzips a `content-encoding: gzip` response before `arrayBuffer()`) hashes the
  same bytes the sidecar signed and verifies fine on either transport encoding.

## Source layout

| File                          | Responsibility                                                                                                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/core/src/index.ts`  | Public barrel re-exporting `TrustedVerifier`, `verifyResponse`/`isSignedVrpcResponse`, `fetchAttestation`/`verifyAttestationCorrelation`, the `VerificationError` family, `buildPreImage`, `parseChainId`, and `deriveVrpcUrls`. |
| `packages/dstack-verify/src/verify-steps.ts`| `computeComposeHash` (`sha256(utf8(app_compose))` bare-hex, used by CHK-A2) + `parseReportData` (CHK-A1). Lives here — compose-hash is a dstack/TDX concept. |
| `packages/proxy/src/pipeline.ts` | Buffering verifying-proxy pipeline: forward request verbatim, decode a throwaway response copy, `TrustedVerifier.verify` fail-closed, relay original bytes. CLI entry: `packages/proxy/src/cli.ts` (`vrpc-proxy` bin). |
| `tsconfig.base.json`          | Strict TS config (target ESNext, moduleResolution bundler, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`). Root `tsconfig.json` only `extends` it with `files: []`; each package's `tsconfig.json` extends it too.        |
| `biome.json`                  | Biome lint + formatter config (root).                                                                                                                                                     |
| `.github/workflows/ci.yml`    | CI workflow — lint + format:check + typecheck + test on push/PR.                                                                                                                          |
| `Dockerfile`                  | Root multi-stage image (node:24-slim builder → distroless nodejs24 runtime, amd64, single self-contained `cli.js`). Publishes `ghcr.io/w3tech/vrpc-proxy`.                               |
| `packages/proxy/tsup.docker.config.ts` | Docker-only tsup config — bundles EVERYTHING (`noExternal`) into one `cli.js` for the distroless stage. Never published to npm (excluded from `files`).                        |
| `.github/workflows/docker-test-build.yml` | On push: build + in-container smoke, gha layer cache, no GHCR push. Pre-tag validation.                                                                                     |
| `.github/workflows/docker-publish.yml`    | On `v*` tag: hermetic (`no-cache`) build + GHCR push, cosign keyless sign, double `attest-build-provenance` (image digest + bundle file).                                    |

## Where to look first

| Task                                          | Start here                       |
| --------------------------------------------- | -------------------------------- |
| Add a field to the public surface             | `packages/core/src/index.ts`     |
| Adjust lint or format rules                   | `biome.json` (Biome 2.x schema)  |
| Adjust CI pipeline                            | `.github/workflows/ci.yml`       |
| Build/publish the proxy container image       | `Dockerfile`, `.github/workflows/docker-test-build.yml` (push) + `docker-publish.yml` (tag) |
| Release runbook (npm + docker, user gates)    | `docs/PUBLISHING.md`             |
| Change strict-mode TS flags                   | `tsconfig.base.json`             |
| Explain vRPC / the trust model to a user      | `.claude/skills/explain-vrpc/SKILL.md` |

## Conventions

- **Branch/PR:** work on `main` + short-lived feature branches; one PR per
  logical change. Never push to `main` directly, never self-merge.
- **Atomic commits:** one logical chunk per commit.
- **ESM-first, `type: "module"`** in `package.json`. No CJS in v3 entry.
- **No JSON-RPC re-impl** — the verify seam is byte-level and returns a typed
  `VerifiedPair`. Consumers handle batching, retries.
- **Byte-exact 104-byte pre-image** — pinned by a unit test mirroring
  `pre_image_layout_is_byte_exact` from the sidecar; any drift is a hard bug.
- **Typed errors at every boundary** — `VerificationError` subclasses for
  `MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp`,
  `InvalidNonce`, `InvalidChainId`, `MalformedAttestationResponse`.
- **No throw-from-async-constructor** — synchronous fail-fast for config errors
  (e.g. `new TrustedVerifier(opts)` / `validateChainId`); runtime verification
  errors from call sites only.
- **Worktree rule** from parent `../AGENTS.md` applies: create a git worktree
  off `main` for feature work; never switch the checked-out branch in place.
