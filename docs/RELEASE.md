# Release Process

This repository uses [Changesets](https://github.com/changesets/changesets) to manage
versioning, changelogs, and the release PR for the four published packages:

- `@ankr.com/vrpc-core` (`packages/core`)
- `@ankr.com/dstack-verify` (`packages/dstack-verify`)
- `@ankr.com/vrpc-ethers` (`packages/ethers`)
- `@ankr.com/vrpc-viem` (`packages/viem`)

Versioning is **independent per package** — a change to one package does not force a
version bump on the others, except that dependents of a changed internal package receive
an automatic bump (see `updateInternalDependencies` below).

> Scope note: the actual CI publish workflow (OIDC `id-token: write`, provenance,
> trusted-publisher config, bootstrap) is delivered in **Phase 38**, and the first real
> publish (human-gated) in **Phase 39**. This document establishes the authoring flow and
> the dist-tag policy that those phases wire into CI.

## 1. Authoring a changeset (every PR that changes a package)

When you make a change that should be released, add a changeset:

```bash
pnpm changeset
```

This interactively asks which packages changed and at what semver level
(`patch` / `minor` / `major`), then writes a markdown file under `.changeset/`. Commit
that file as part of your PR. A changeset describes **release intent**; it does not bump
any version itself.

If a change does not need a release (docs, CI, internal refactor), record that explicitly:

```bash
pnpm changeset add --empty
```

You can preview what the pending changesets will bump at any time:

```bash
pnpm changeset status
```

## 2. Versioning (the "Version Packages" PR — Phase 38 CI)

When changesets accumulate on `main`, CI opens (or updates) a **"Version Packages"** PR.
Merging that PR runs:

```bash
pnpm changeset version   # alias: pnpm version
```

This consumes the pending changeset files and, for each affected package:

1. Bumps the package version per the recorded semver intent.
2. Writes/updates that package's `CHANGELOG.md`.
3. Rewrites internal dependency **versions** in dependents per `updateInternalDependencies`.

### `updateInternalDependencies: patch`

When an internal package is bumped, every package that depends on it receives at least a
**patch** bump and its dependency range is updated to the new version. Example proven in
Phase 37: a `patch` to `@ankr.com/vrpc-core` cascades a patch bump to `@ankr.com/dstack-verify`,
`@ankr.com/vrpc-ethers`, and `@ankr.com/vrpc-viem`.

> The `workspace:*` protocol stays in the in-repo manifests; it is rewritten to a concrete
> version range only in the **published tarball** at `pnpm pack` / `changeset publish` time
> (verified in Phase 37-01: `@ankr.com/vrpc-ethers` → `@ankr.com/vrpc-core@0.1.0`,
> `@ankr.com/dstack-verify@0.1.0`).

## 3. Publishing (Phase 38 CI, OIDC)

After the "Version Packages" PR merges to `main`, CI runs:

```bash
pnpm changeset publish   # Phase 38 — DO NOT run manually
```

`changeset publish` publishes each newly-versioned package to npm in dependency order
(`vrpc-core` → `dstack-verify` → `vrpc-ethers` / `vrpc-viem`). `access: public` in
`.changeset/config.json` makes the scoped packages publicly installable.

> No real publish happens in Phases 36–37. Verification there uses `pnpm pack` /
> `pnpm publish --dry-run` / `changeset status` / `changeset version` (reverted) only.

## 4. dist-tag policy (REL-02)

| Channel | dist-tag | Where | How |
| ------- | -------- | ----- | --- |
| **GA (general availability)** | `latest` | `main` only, after the Version Packages PR merges | `changeset publish` |
| **RC (release candidate)** | `rc` | PR / release-candidate branches only | snapshot release (primary) or prerelease mode |

**Org rules (hard):**

- **RC dist-tags only on PR / release-candidate branches.** Never tag `latest` from a
  branch. RC branch numbering does **not** dictate the eventual GA number.
- **Sequential GA on `main` after merge.** Each GA is the previous GA `+1 patch`
  (sequential per org convention), regardless of how many RCs preceded it.

### RC mechanism — snapshot releases (primary)

For an ad-hoc RC from a PR branch, use a snapshot version (timestamped, never promoted to
`latest`):

```bash
pnpm changeset version --snapshot rc      # writes e.g. 0.1.0-rc-20260623120000
pnpm changeset publish --tag rc           # Phase 38 CI — publishes under dist-tag "rc"
```

Snapshot versions are disposable and are never merged back into `main`.

### RC mechanism — prerelease mode (alternative)

For a sustained RC train:

```bash
pnpm changeset pre enter rc               # enter prerelease mode (writes .changeset/pre.json)
pnpm changeset version                     # bumps to x.y.z-rc.N
pnpm changeset publish                      # publishes under dist-tag "rc"
# ...iterate...
pnpm changeset pre exit                    # leave prerelease mode before the GA on main
```

Snapshot releases are the **primary** RC mechanism for this repo (simpler, no `pre.json`
state to manage on shared branches); prerelease mode is available when a longer RC train is
warranted.

## Configuration reference

`.changeset/config.json`:

- `access: "public"` — scoped packages publish publicly.
- `baseBranch: "main"` — changeset diff base.
- `commit: false` — changesets does not auto-commit; CI / authors commit explicitly.
- `updateInternalDependencies: "patch"` — dependents get a patch bump on internal changes.
- `fixed: []`, `linked: []` — independent per-package versioning (no grouping).
- `changelog: "@changesets/cli/changelog"` — default zero-dependency changelog generator.

See also [`AGENTS.md`](../AGENTS.md) for repository-wide development conventions.
