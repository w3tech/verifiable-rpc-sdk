# Publishing Runbook (npm Trusted Publishing)

This is a **human/admin runbook**. The SDK repository does **not** perform any of the steps
below — they are npmjs.com registry-side actions, some of them admin-only and irreversible
(they can create real package names). This repo only **authors** the release workflow and
keeps a **green publish dry-run** (see the publish CI workflow and [`RELEASE.md`](./RELEASE.md));
the steps here are what a human/admin must do once, by hand, to enable tokenless OIDC
publishing for the four `@ankr.com/*` packages.

> **Boundary.** Per-package trusted-publisher registration and the first-publish bootstrap
> are deliberately **not executed** by this repo. They are `human_needed` (the first real
> publish / org-admin handoff), **not** gaps. Perform them using this runbook.

---

## ⚠️ Workflow filename (load-bearing)

The npmjs.com trusted-publisher configuration must reference this **exact, case-sensitive**
workflow filename, located under `.github/workflows/` in `w3tech/verifiable-rpc-sdk`:

```
publish.yml
```

A typo in this filename is **not validated at save time** on npmjs.com — it surfaces only as
an `ENEEDAUTH` authentication failure at the first real publish. Copy it verbatim:
`publish.yml` (not `release.yml`, not `Publish.yml`).

---

## 1. Prerequisites

Both must be true before trusted publishing works:

1. **Publishing identity is an `@ankr.com` npm org member with publish rights.**
   The `@ankr.com` npm org exists and is owned by Ankr. Trusted publishing publishes *as*
   that org's package; the identity backing the trusted publisher (and the operator running
   the one-time bootstrap below) must be a member of the `@ankr.com` org with publish
   permission on each package. *(Open item: the specific operator is a pending org-admin
   decision.)*

2. **The GitHub repo `w3tech/verifiable-rpc-sdk` is made public.**
   This is **required for provenance.** npm attaches provenance attestations only when
   **both** the source repo **and** the package are public. A private repo still gets
   tokenless OIDC publish, but **without** a provenance attestation. Making the repo public
   is a **GitHub admin step** (deferred — the first real publish handoff). The package's `repository.url`
   must also match the GitHub repo exactly (already set in the manifests).

---

## 2. Per-package trusted-publisher registration (PUB-03)

Apply this **identical checklist to all four packages**. Trusted publishing is configured
**per package** (there is no org-wide setting):

| # | Package          | npm package page                         |
|---|------------------|------------------------------------------|
| 1 | `@ankr.com/vrpc-core`     | npmjs.com/package/@ankr.com/vrpc-core     |
| 2 | `@ankr.com/dstack-verify` | npmjs.com/package/@ankr.com/dstack-verify |
| 3 | `@ankr.com/vrpc-ethers`   | npmjs.com/package/@ankr.com/vrpc-ethers   |
| 4 | `@ankr.com/vrpc-viem`     | npmjs.com/package/@ankr.com/vrpc-viem     |

For **each** package, on npmjs.com:

1. Open the package → **Settings** → **Trusted Publishing**.
2. Add a publisher with:
   - **Organization / owner:** `w3tech`
   - **Repository:** `verifiable-rpc-sdk`
   - **Workflow filename:** `publish.yml` (the exact name from the callout above)
   - **Environment:** *(optional — leave blank unless a GitHub Actions environment is added to the job)*
3. Save.

> **Case-sensitivity warning.** `w3tech`, `verifiable-rpc-sdk`, and `publish.yml` are all
> case-sensitive and are **not validated at save time**. A mismatch fails silently here and
> only errors (`ENEEDAUTH`) at the first OIDC publish. Double-check each field against the
> actual repo and the workflow file.

This registration cannot be created until the package name already exists on the registry —
see the bootstrap below.

---

## 3. First-publish bootstrap (PUB-04)

Trusted publishing **cannot create a brand-new package name** — it can only publish new
versions of a name that already exists. So each of the four names must be published **once**
the traditional way, **then** OIDC takes over for every subsequent version.

For **each** of the four names, in **dependency order**
(`@ankr.com/vrpc-core` → `@ankr.com/dstack-verify` → `@ankr.com/vrpc-ethers` /
`@ankr.com/vrpc-viem`), publish the initial `0.1.0`:

- **Either** via a one-time **granular (least-privilege) access token** with publish scope on
  that package, e.g. from a clean checkout after `pnpm -r build`:

  ```
  # one-time only, per name, by an @ankr.com org member; replace with each package dir
  cd packages/core && npm publish --access public
  ```

  Set the granular token in the local npm config / `NODE_AUTH_TOKEN` for this one-time run.
  **Never commit the token.** Revoke it after bootstrap.

- **Or** publish the tarball via the npmjs.com website upload, also at **public** access.

Notes:
- `publishConfig.access` is already `"public"` on all four packages, so `--access public` is
  belt-and-suspenders — scoped packages otherwise default to restricted.
- Publish in the dependency order above so a dependent never references an
  unpublished version of an internal dep.
- After the initial `0.1.0` of a name exists, **register its trusted publisher (Section 2)**
  and stop using the bootstrap token for that name.

---

## 4. After bootstrap — automated OIDC releases

Once every name is bootstrapped and its trusted publisher is registered, **delete/revoke the
bootstrap token** and rely entirely on the authored workflow. Subsequent releases are
automatic and tokenless:

1. PRs that change a package include a changeset (`pnpm changeset`).
2. On merge to `main`, `publish.yml` runs `changesets/action@v1`, which opens/updates the
   **"Version Packages"** PR.
3. Merging that PR re-triggers `publish.yml`, which runs the root `release` script: build →
   **dry-run gate** → `pnpm -r publish --provenance` (tokenless OIDC, dependency-ordered).

For the RC/GA dist-tag policy, the changeset authoring flow, and the "Version Packages" PR
mechanics, see [`RELEASE.md`](./RELEASE.md) — that policy is **not duplicated here**.

---

## 5. Boundary — what this repo did vs. what a human must do

| Item | Status | Owner |
|------|--------|-------|
| `.github/workflows/publish.yml` authored (tokenless OIDC, provenance, dependency order, dry-run gate) | ✅ Done | SDK repo |
| Root `release` / `publish:dry-run` scripts | ✅ Done | SDK repo |
| Green publish dry-run proven locally (4× Skip, dependency order) | ✅ Done | SDK repo |
| Make GitHub repo `w3tech/verifiable-rpc-sdk` **public** (required for provenance) | ⏳ Pending | GitHub admin |
| Ensure publishing identity is an `@ankr.com` org member with publish rights | ⏳ Pending | npm org admin |
| **First-publish bootstrap** of each `0.1.0` name (token/website, `--access public`) | ⏳ Pending | npm org member (irreversible) |
| **Per-package trusted-publisher registration** ×4 (org `w3tech`, repo `verifiable-rpc-sdk`, `publish.yml`) | ⏳ Pending | npm org admin |
| First real OIDC publish + provenance verification (`npm audit signatures`) | ⏳ Pending | the first real publish handoff |
