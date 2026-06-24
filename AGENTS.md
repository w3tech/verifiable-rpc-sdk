# verifiable-rpc-sdk

TypeScript verifier client for Ankr's verifiable RPC sidecar
(`verifiable-rpc-sidecar`). Verifies Ed25519-signed JSON-RPC responses and
fetches TDX attestation quotes from the sidecar. Pairs with sidecar `v0.2.0`
wire contract — the signature covers the content-DECODED body, so it verifies
on either transport encoding (gzip or identity). ESM-first, vitest-tested,
chain-agnostic.

## Commands

| Action           | Command                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Install          | `pnpm install`                                                                                       |
| Test (whole workspace) | `pnpm -r test` (from repo root)                                                                |
| Unit test only   | per-package: `cd packages/core && pnpm run test:unit` (or `pnpm --filter '@ankr.com/vrpc-core' test:unit`) |
| Integration test | per-package: `cd packages/core && DSTACK_SIMULATOR_BIN=… DSTACK_SIMULATOR_FIXTURES_DIR=… SIDECAR_BIN=… pnpm run test:integration` (or via `pnpm --filter '@ankr.com/vrpc-core' test:integration`) |
| Lint             | `pnpm run lint`                                                                                      |
| Format check     | `pnpm run format:check`                                                                              |
| Format fix       | `pnpm run format`                                                                                    |
| Typecheck        | `pnpm -r typecheck` (root fans out: `pnpm -r typecheck`; per-package leaf is `tsc --noEmit`) |

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
  pnpm --filter '@ankr.com/vrpc-core' test:integration
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

- Monorepo: pnpm workspaces under `packages/*` — `core` (`@ankr.com/vrpc-core`,
  the verification primitives), `ethers` (`@ankr.com/vrpc-ethers`), `viem`
  (`@ankr.com/vrpc-viem`), and `dstack-verify` (`@ankr.com/dstack-verify`).
- Public surface re-exported through `packages/core/src/index.ts`; implementation
  lives in `packages/core/src/verifier.ts`, `packages/core/src/verify.ts`,
  `packages/core/src/attestation.ts`, `packages/core/src/compose.ts`,
  `packages/core/src/errors.ts`, `packages/core/src/preimage.ts` (plus
  `anchor.ts`, `trusted-verifier.ts`, `utils.ts`, `vrpc-url.ts`).
- SDK is a thin verifier wrapping `fetch` — no JSON-RPC re-implementation, no
  batching, no method-specific decoders.
- Pairs with `verifiable-rpc-sidecar` `v0.2.0`. Wire contract = the 80-byte
  canonical pre-image + `vRPC-Signature` / `vRPC-Timestamp` / `vRPC-Pubkey`
  headers + `/attestation?nonce=<hex>` JSON shape. As of v0.2.0 the signature
  covers the content-DECODED (plaintext) body, so it verifies whether the
  client requested gzip or identity (the `v0.1.0` contract is forward-compatible
  on the identity path). `examples/05-gzip-transport.ts` proves this on the live
  gzip path.
- **`call()` pins `accept-encoding: identity` as defense-in-depth — no longer a
  correctness requirement.** Since v0.2.0 signs the content-decoded body, a
  standard auto-decoding `fetch` (which gunzips a `content-encoding: gzip`
  response before `arrayBuffer()`) hashes the same bytes the sidecar signed and
  verifies fine. Pinning identity is retained because it keeps the hashed bytes
  byte-identical to the wire bytes and avoids relying on the proxy's
  re-encoding, but correctness does not depend on it.

## Source layout

| File                          | Responsibility                                                                                                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/core/src/index.ts`  | Public barrel re-exporting `VerifierClient`, `verifyResponse`/`isSignedVrpcResponse`, `fetchAttestation`/`verifyAttestationCorrelation`, `anchorTrust`, `TrustedVerifier`, the `ComposeSource` family (`InfoEndpointComposeSource`, `RegistryComposeSource`, `computeComposeHash`), the `VerificationError` family, `buildPreImage`, `parseChainId`, and `deriveVrpcUrls`. |
| `packages/core/src/compose.ts`| `ComposeSource` abstraction for Layer A: `InfoEndpointComposeSource` (dev-only, `/info` self-report — NOT a trust anchor) + `RegistryComposeSource` (future external/GitHub anchor, DEC-03) + `computeComposeHash`. |
| `tsconfig.base.json`          | Strict TS config (target ESNext, moduleResolution bundler, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`). Root `tsconfig.json` only `extends` it with `include: []`; each package's `tsconfig.json` extends it too.        |
| `biome.json`                  | Biome lint + formatter config (root).                                                                                                                                                     |
| `.github/workflows/ci.yml`    | CI workflow — lint + format:check + typecheck + test on push/PR.                                                                                                                          |

## Where to look first

| Task                                          | Start here                       |
| --------------------------------------------- | -------------------------------- |
| Add a field to the public surface             | `packages/core/src/index.ts`     |
| Adjust lint or format rules                   | `biome.json` (Biome 2.x schema)  |
| Adjust CI pipeline                            | `.github/workflows/ci.yml`       |
| Change strict-mode TS flags                   | `tsconfig.base.json`             |
| Explain vRPC / the trust model to a user      | `.claude/skills/explain-vrpc/SKILL.md` |

## Conventions

- **Commit prefix:** `SHARK-XXXX: ...` using the relevant Jira key.
- **Branch/PR:** work on `main` + short-lived feature branches; one PR per
  logical change. Never push to `main` directly, never self-merge.
- **Atomic commits:** one logical chunk per commit.
- **ESM-first, `type: "module"`** in `package.json`. No CJS in v3 entry.
- **No JSON-RPC re-impl** — SDK wraps `fetch`, returns typed
  `VerifiedResponse<T>`. Consumers handle batching, retries.
- **Byte-exact 80-byte pre-image** — pinned by a unit test mirroring
  `pre_image_layout_is_byte_exact` from the sidecar; any drift is a hard bug.
- **Typed errors at every boundary** — `VerificationError` subclasses for
  `MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp`,
  `InvalidNonce`, `MalformedAttestationResponse`.
- **No throw-from-async-constructor** — synchronous fail-fast in
  `new VerifierClient(url, opts)` for config errors; runtime verification
  errors from call sites only.
- **Worktree rule** from parent `../AGENTS.md` applies: create a git worktree
  off `main` for feature work; never switch the checked-out branch in place.
