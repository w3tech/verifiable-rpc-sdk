# verifiable-rpc-sdk

TypeScript verifier client for Ankr's verifiable RPC sidecar
(`verifiable-rpc-sidecar`). Verifies Ed25519-signed JSON-RPC responses and
fetches TDX attestation quotes from the sidecar. Pairs with sidecar `v0.1.0`
wire contract. ESM-first, Bun-tested, chain-agnostic.

## Commands

| Action       | Command                                  |
| ------------ | ---------------------------------------- |
| Install      | `bun install`                            |
| Test         | `bun test`                               |
| Lint         | `bun run lint`                           |
| Format check | `bun run format:check`                   |
| Format fix   | `bun run format`                         |
| Typecheck    | `bun run typecheck`                      |
| Build        | `bun run build` (no-op in Phase 18)      |

## Pre-push gate (mandatory)

**Before every `git push`** run all four in order. CI runs the same set — fix
locally rather than letting CI fail.

```sh
bun run format:check    # exit 0 — no diff
bun run lint            # exit 0
bun run typecheck       # exit 0 (tsc --noEmit)
bun test                # all green (empty suite OK in Phase 18)
```

If `bun run format:check` fails: run `bun run format`, commit the diff as a
SEPARATE commit, do not amend the offending commit.

The pre-push gate is a contract — there is no git hook enforcing it in Phase 18
(deferred to a v3 ops phase per CONTEXT.md).

## Architecture

- Single-file surface in `src/index.ts` (placeholder `VerifierClient` class +
  type stubs). Phase 19 fills `call()`, Phase 20 fills `fetchAttestation()`.
- SDK is a thin verifier wrapping `fetch` — no JSON-RPC re-implementation, no
  batching, no method-specific decoders (per v3 architecture principle in
  REQUIREMENTS.md).
- Pairs with `verifiable-rpc-sidecar` `v0.1.0`. Wire contract = SPEC-04 80-byte
  pre-image + `vRPC-Signature` / `vRPC-Timestamp` / `vRPC-Pubkey` headers +
  `/attestation?nonce=<hex>` JSON shape.

## Source layout

| File                          | Responsibility                                                                                                                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/index.ts`                | Placeholder `VerifierClient` class + type stubs (`VerifierClientOptions`, `Attestation`, `GetQuoteResponse`, `VerifiedResponse<T>`, `VerificationError`). Phase 19 fills `call()`, Phase 20 fills `fetchAttestation()`. |
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
- **Branch:** `SHARK-3283-verifier-sdk-v3` for the v3 entry; one big PR carries
  Phases 18-21 (convention carried from v2 sidecar PR stack).
- **Atomic commits within a phase:** one logical chunk per commit
  (`package.json + tsconfig`, then `biome.json`, then `src/index.ts`, then
  `AGENTS.md + CLAUDE.md`, then `ci.yml` — Phase 18 example).
- **ESM-first, `type: "module"`** in `package.json`. No CJS in v3 entry.
- **No JSON-RPC re-impl** — SDK wraps `fetch`, returns typed
  `VerifiedResponse<T>`. Consumers handle batching, retries.
- **Byte-exact SPEC-04 pre-image** — Phase 19 will pin the 80-byte layout via a
  unit test mirroring `pre_image_layout_is_byte_exact` from the sidecar; any
  drift is a hard bug.
- **Typed errors at every boundary** — `VerificationError` subclasses for
  `MissingHeader`, `MalformedHeader`, `BadSignature`, `StaleTimestamp` arrive
  in Phase 19.
- **No throw-from-async-constructor** — synchronous fail-fast in
  `new VerifierClient(url, opts)` for config errors; runtime verification
  errors from call sites only.
- **Worktree rule** from parent `../AGENTS.md` applies in general; Phase 18 is
  an exception (branch is already checked out in the main checkout per the v3
  entry plan).
