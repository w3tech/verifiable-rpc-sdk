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
| Integration test | per-package: `cd packages/core && DSTACK_SIMULATOR_BIN=… DSTACK_SIMULATOR_FIXTURES_DIR=… SIDECAR_BIN=… pnpm run test:integration` (or via `pnpm --filter '@w3tech.io/vrpc-core' test:integration`); `@w3tech.io/vrpc-ethers`, `@w3tech.io/vrpc-viem` and `@w3tech.io/vrpc-proxy` have the same `test:integration` script |
| Lint             | `pnpm run lint`                                                                                      |
| Format check     | `pnpm run format:check`                                                                              |
| Format fix       | `pnpm run format`                                                                                    |
| Typecheck        | `pnpm -r typecheck` (root fans out: `pnpm -r typecheck`; per-package leaf is `tsc --noEmit`) |
| Static checks    | `pnpm run check` (runs every `check:*` script; after `pnpm -r build`; `check:deps` needs Node 22 or 24, dependency-cruiser does not run on Node 25); update the API reports: `pnpm run api:update`; coverage: `pnpm run test:coverage` |
| Docker build     | `docker build -t vrpc-proxy .` (root `Dockerfile`; amd64 production image). The docker-only bundle step alone: `pnpm --filter '@w3tech.io/vrpc-proxy' run build:docker` |

## Pre-push gate (mandatory)

**Before every `git push`** run all of these in order. CI runs the same set — fix
locally rather than letting CI fail.

```sh
pnpm run format:check   # exit 0 — no diff
pnpm run lint           # exit 0
pnpm -r typecheck       # exit 0 (tsc --noEmit)
pnpm -r build
pnpm run check
pnpm -r test            # all green
```

If the public API changed, run `pnpm run api:update` and commit
`packages/*/etc/*.api.md`; `check:api` fails on a stale report.

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
The Ankr Confidential RPC suites (`packages/core/tests/integration/confidential.test.ts`,
`packages/ethers/test/integration/confidential.test.ts`,
`packages/viem/test/integration/confidential.test.ts`,
`packages/proxy/tests/integration/confidential.test.ts`) share the Node-only stack in
`packages/test-support/src/interop.ts`. Its loopback relay adds `vRPC-NodeId` (a sidecar
reached directly does not send it) and blanks `app_compose` in attestation answers (the
simulator fixtures are not self-consistent); it is test code only.

**Required env vars (any unset → integration suite skips cleanly):**

| Var                             | Example                                                         |
| ------------------------------- | --------------------------------------------------------------- |
| `DSTACK_SIMULATOR_BIN`          | `/path/to/dstack-simulator`                                     |
| `DSTACK_SIMULATOR_FIXTURES_DIR` | `/path/to/dstack/sdk/simulator`                                 |
| `SIDECAR_BIN`                   | `/path/to/verifiable-rpc-sidecar/target/debug/rpc-attest-sidecar` |

The simulator of the dstack TEE (trusted execution environment) is built from the public
`Dstack-TEE/dstack` repo at commit `9c50e19` (`git checkout 9c50e19 && cargo build --release -p dstack-guest-agent-simulator`); its fixtures
are that commit's `sdk/simulator` directory, the source of `attestation-v0.1.0.json` (below).

Build the sidecar with `cargo build` in the sibling `verifiable-rpc-sidecar`
repo before running integration tests. The debug binary is fine — release is
not required.

**Local invocation:**

```sh
DSTACK_SIMULATOR_BIN=/path/to/dstack-simulator \
DSTACK_SIMULATOR_FIXTURES_DIR=/path/to/dstack/sdk/simulator \
SIDECAR_BIN=/path/to/verifiable-rpc-sidecar/target/debug/rpc-attest-sidecar \
  pnpm --filter @w3tech.io/vrpc-core --filter @w3tech.io/vrpc-ethers --filter @w3tech.io/vrpc-viem --filter @w3tech.io/vrpc-proxy test:integration
```

`pnpm -r test` (no env vars) runs the unit suite only and logs a one-line skip
message (visible with `--reporter=verbose`). `pnpm -r test` with all three env vars set runs the unit
suite plus the integration suite.

The open-mode integration suites cover the happy path and the canonical attestation
fixture (`packages/core/tests/fixtures/attestation-v0.1.0.json`); the Ankr Confidential
RPC suites also cover tampering, replay and the batch limit against the real sidecar.

**CI:** CI runs the unit suites only; the integration suites run locally with the three
variables set.

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
| `Dockerfile`                  | Root multi-stage image (node:24-slim builder → distroless nodejs24 runtime, amd64, single self-contained `cli.js`). Publishes to GHCR (GitHub Container Registry) as `ghcr.io/w3tech/vrpc-proxy`.                               |
| `packages/proxy/tsup.docker.config.ts` | Docker-only tsup config — bundles everything (`noExternal`) into one `cli.js` for the distroless stage. Kept out of the npm package (not in the `files` whitelist).                        |
| `.github/workflows/docker-test-build.yml` | On push: build + in-container smoke, gha layer cache, no registry push. Pre-tag validation.                                                                                     |
| `.github/workflows/publish.yml` (`docker` job) | On `v*` tag: hermetic (`no-cache`) build + GHCR push, cosign keyless sign, double `attest-build-provenance` (image digest + bundle file). Parallel to the `npm` job. |

## Where to look first

| Task                                          | Start here                       |
| --------------------------------------------- | -------------------------------- |
| Add a field to the public surface             | `packages/core/src/index.ts`     |
| Adjust lint or format rules                   | `biome.json` (Biome 2.x schema)  |
| Adjust CI pipeline                            | `.github/workflows/ci.yml`       |
| Build/publish the proxy container image       | `Dockerfile`, `.github/workflows/docker-test-build.yml` (push) + `publish.yml` `docker` job (tag) |
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
