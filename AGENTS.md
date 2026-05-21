# verifiable-rpc-sdk

TypeScript verifier client for Ankr's verifiable RPC sidecar
(`verifiable-rpc-sidecar`). Verifies Ed25519-signed JSON-RPC responses and
fetches TDX attestation quotes from the sidecar. Pairs with sidecar `v0.1.0`
wire contract. ESM-first, Bun-tested, chain-agnostic.

## Commands

| Action           | Command                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Install          | `bun install`                                                                                        |
| Test             | `bun test`                                                                                           |
| Unit test only   | `bun run test:unit`                                                                                  |
| Integration test | `DSTACK_SIMULATOR_BIN=… DSTACK_SIMULATOR_FIXTURES_DIR=… SIDECAR_BIN=… bun run test:integration`      |
| Lint             | `bun run lint`                                                                                       |
| Format check     | `bun run format:check`                                                                               |
| Format fix       | `bun run format`                                                                                     |
| Typecheck        | `bun run typecheck`                                                                                  |
| Build            | `bun run build` (no-op for now — bundling deferred)                                                  |

## Pre-push gate (mandatory)

**Before every `git push`** run all four in order. CI runs the same set — fix
locally rather than letting CI fail.

```sh
bun run format:check    # exit 0 — no diff
bun run lint            # exit 0
bun run typecheck       # exit 0 (tsc --noEmit)
bun test                # all green
```

If `bun run format:check` fails: run `bun run format`, commit the diff as a
SEPARATE commit, do not amend the offending commit.

The pre-push gate is a contract — there is no git hook enforcing it (a hook is
deferred to a later ops cycle).

## Integration tests

End-to-end tests under `tests/integration/` spawn a real sidecar binary backed
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
  bun run test:integration
```

`bun test` (no env vars) runs the unit suite only and emits a one-line skip
message at module load. `bun test` with all three env vars set runs the unit
suite plus the integration suite.

**Tamper and replay are unit-only.** Both code paths are already covered at
the unit level with real Ed25519 sign+verify
(`tamperedResponseBodyThrowsBadSignature` and the replay-window edge tests) —
adding integration-level versions would exercise the same logic against a
slower harness without catching anything new. Integration tests focus on the
value adds: happy-path call, cross-endpoint pubkey consistency, and a
real-wire canonical attestation fixture (`tests/fixtures/attestation-v0.1.0.json`).

**CI deferral:** CI runs the unit suite only. A dedicated integration matrix
with the simulator binary on the runner is tracked separately.

## Architecture

- Public surface re-exported through `src/index.ts`; implementation lives in
  `src/verifier.ts`, `src/attestation.ts`, `src/errors.ts`, `src/preimage.ts`.
- SDK is a thin verifier wrapping `fetch` — no JSON-RPC re-implementation, no
  batching, no method-specific decoders.
- Pairs with `verifiable-rpc-sidecar` `v0.1.0`. Wire contract = the 80-byte
  canonical pre-image + `vRPC-Signature` / `vRPC-Timestamp` / `vRPC-Pubkey`
  headers + `/attestation?nonce=<hex>` JSON shape.

## Source layout

| File                          | Responsibility                                                                                                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/index.ts`                | Public barrel re-exporting `VerifierClient`, `fetchAttestation`, the `VerificationError` family, and `buildPreImage`.                                                                                                  |
| `tsconfig.json`               | Strict TS config (target ESNext, moduleResolution bundler, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`).                                                                     |
| `biome.json`                  | Biome lint + formatter config.                                                                                                                                                            |
| `.github/workflows/ci.yml`    | CI workflow — lint + format:check + typecheck + test on push/PR.                                                                                                                          |

## Where to look first

| Task                                          | Start here                       |
| --------------------------------------------- | -------------------------------- |
| Add a placeholder field to the public surface | `src/index.ts`                   |
| Adjust lint or format rules                   | `biome.json` (Biome 2.x schema)  |
| Adjust CI pipeline                            | `.github/workflows/ci.yml`       |
| Change strict-mode TS flags                   | `tsconfig.json`                  |

## Conventions

- **Commit prefix:** `SHARK-3283: ...` on the v3-entry branch; future phases
  follow their own Jira keys.
- **Branch:** `SHARK-3283-verifier-sdk-v3`; one big PR carries the entire entry
  (convention carried from the sidecar PR stack).
- **Atomic commits:** one logical chunk per commit (e.g. `package.json +
  tsconfig`, then `biome.json`, then `src/index.ts`, then
  `AGENTS.md + CLAUDE.md`, then `ci.yml`).
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
- **Worktree rule** from parent `../AGENTS.md` applies in general; the current
  branch is already checked out in the main checkout, so the work continues
  there.
