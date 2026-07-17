# Publishing

Releasing the four `@w3tech.io/*` packages (`vrpc-core`, `vrpc-ethers`, `vrpc-viem`,
`dstack-verify`) is **tag-driven**: to release, push a `vX.Y.Z` (or prerelease
`vX.Y.Z-<suffix>`) git tag (or run the `publish.yml` workflow manually with a `tag`
input). The workflow does **not** create tags — the tag is the single trigger **and**
the version source.

> **dist-tag.** A plain `vX.Y.Z` publishes to `latest` (the default `npm install` channel).
> A prerelease (`vX.Y.Z-<suffix>`) publishes to its own channel and is **never** `latest`
> (see step 3).

## How a release happens

1. **Push a tag.** Create and push a SemVer tag, e.g.:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   Or trigger `Publish` manually from the Actions tab with a `tag` input (e.g. `v0.2.0`).

2. **Trigger.** The push of a `v*.*.*` tag triggers **two** workflows in parallel:
   `.github/workflows/publish.yml` (npm packages, below) and
   `.github/workflows/docker-publish.yml` (the `ghcr.io/w3tech/vrpc-proxy` container
   image — see "Docker image release"). The two are independent; either can succeed or
   fail on its own.

3. **Version + dist-tag derive.** The version is derived from the tag
   (`VERSION=${GITHUB_REF_NAME#v}`) and validated for shape only:
   - it must match `vX.Y.Z` with an **optional** prerelease suffix after a dash —
     `v1.2.3`, `v1.2.3-rc.1`, `v0.2.0-beta.2`, `v2.0.0-alpha`, etc.
   - **No** comparison against the published version — multiple major lines may each get
     their own minors/patches, so an "older" number is a legitimate release.

   The **dist-tag** is derived from the version:
   - plain `vX.Y.Z` (no suffix) → `latest`.
   - prerelease (`-<suffix>`) → the leading alphabetic id of the suffix (`rc`, `beta`,
     `alpha`, …); a numeric-only suffix → `pre`. Never `latest`.

4. **Lockstep version stamp.** `pnpm version "$VERSION" --no-git-tag-version -r` stamps the
   derived version into all four `package.json` files and resolves `workspace:*` to concrete
   versions at publish time. This runs in the runner only — `--no-git-tag-version` means **no
   git commit/tag is created and the bump is not committed back to `main`**.

5. **Publish (tokenless OIDC + provenance).** A `--dry-run` gate then the real publish, both
   `pnpm -r publish --provenance --no-git-checks --tag "$DIST_TAG"` — pinned to the derived
   dist-tag. `--no-git-checks` is required because publish runs from a detached
   `HEAD` at the tag.

6. **GitHub Release.** `softprops/action-gh-release` creates a GitHub Release with
   auto-generated, PR-label-categorized notes driven by `.github/release.yml`.

## Docker image release

The same `v*` tag that publishes the npm packages also builds and publishes the
`ghcr.io/w3tech/vrpc-proxy` container image via `.github/workflows/docker-publish.yml`.

- **amd64 only.** vrpc-proxy is a production infra tool; non-amd64 users run it via
  `npx @w3tech.io/vrpc-proxy`.
- **Hermetic build.** The release build runs with `no-cache: true` and reads no layer
  cache. Only `docker-test-build.yml` (on push) uses the gha layer cache; the release
  never does, so its attestation covers actually-built bytes rather than a possibly
  poisoned cache layer.
- **Tags.** `docker/metadata-action` derives image tags from the git tag: `vX.Y.Z` →
  `X.Y.Z` + `latest`.
- **Signing + provenance.** The pushed image is signed with cosign keyless (Sigstore
  OIDC) and gets two `attest-build-provenance` attestations — one on the image by
  digest (`push-to-registry: true`) and one on the extracted `cli.js` bundle
  (`subject-path`). The workflow never touches the GitHub Release, so it stays
  compatible with immutable releases (which forbid post-publish asset mutation).
- **Verify.** `cosign verify …` and
  `gh attestation verify oci://ghcr.io/w3tech/vrpc-proxy@sha256:<digest> --owner w3tech`
  — see `packages/proxy/README.md` for exact commands.
- **Immutable releases.** Immutable releases is a repo-wide **GitHub Releases** setting
  (it locks the tag, assets, and notes of every GitHub Release once published) — it is
  not specific to docker. In this repo the GitHub Release is created by the npm flow
  (`publish.yml`, step 6); `docker-publish.yml` only pushes to GHCR and never creates or
  mutates a release, so it is compatible by construction. The npm registry publish is
  independently immutable (npm forbids re-publishing a version).

## Changelog

The changelog is **GitHub-native**: release notes are auto-generated from the titles of the
PRs merged since the previous tag, grouped by PR **label** per `.github/release.yml`. There
are no Changesets `.md` files and no conventional-commit discipline.

- PR labels (`breaking`, `feature`/`enhancement`, `bug`/`fix`) feed the categories.
- Unlabeled PRs fall into the `*` catch-all (**Other Changes**), so notes are always
  produced even before the labels exist in the repo.
- `dependabot` and the release bot are excluded; PRs labeled `ignore-for-release` are dropped.

## Bootstrap-then-tokenless authentication (Phase 52)

The release job references `environment: prod` and sets `NODE_AUTH_TOKEN` from the temporary
`NPMJS_TOKEN` secret. npm tries OIDC (Trusted Publishing) first — because the job has
`id-token: write` — and falls back to the token only when no per-package trusted-publisher is
registered yet. This lets the **same** workflow bootstrap the first publish (token) and then
run fully tokenless (OIDC) afterwards.

After the first publish, for each published package register a per-package
trusted-publisher on npmjs.com:

- Provider: **GitHub Actions**
- Repository: **`w3tech/verifiable-rpc-sdk`**
- Workflow filename: **`publish.yml`** (this filename must stay exactly `publish.yml` — the
  npmjs.com trusted-publisher config references it case-sensitively; never rename it)

Then remove the `NODE_AUTH_TOKEN` line from `publish.yml` → fully tokenless OIDC + provenance.

> Provenance attestations attach only when **both** the source repo and the package are
> public. Until then, provenance does not attach — this is expected, not an error.

## Migration from Changesets

This repo previously used Changesets. The pending changes that were tracked in `.changeset/`
will surface in the first release's notes via their PR titles:

- **`deriveVrpcUrls` path-key URL support** — supports `rpc.ankr.com/<chain>/<key>` (inserts
  `_vrpc` on the chain segment while preserving the key).
- **Removal of the `apiKey` option** across the options types — authentication is header-only.
- **Trimming of `allowlist` / `tcb` / `pccsUrl`** from the options types, plus removal of the
  redundant `headers` field from ethers' `VrpcOptions` (set auth on the `FetchRequest` instead).
  viem's `VrpcHttpOptions` keeps `headers` as a deliberate passthrough.
