# Third-party dependencies

## Policy

The SDK does not implement cryptographic primitives or the Binary HTTP codec itself.
HPKE, X25519, HKDF, AES-GCM, Ed25519 point handling and Binary HTTP come from the
libraries below. The SDK only composes them into the Oblivious HTTP message format
(RFC 9458, sections 4.3 and 4.4): a fixed header, the HPKE `info` string, the
response salt and the response key labels.

Before a dependency is added or upgraded, we review its license, maintainers,
release activity, usage, transitive dependencies, publishing provenance and known
advisories. Every version is pinned exactly. An upgrade is a new review.

## How the libraries reach your project

`@w3tech.io/vrpc-core` bundles the code of `@hpke/core`, `@hpke/dhkem-x25519`,
`@hpke/common`, `@noble/curves`, `bhttp-ts` and `quicvarint` into its published
`dist` at build time, from the exact reviewed versions: the direct libraries are
pinned in core's `package.json`, and `@hpke/common` and `quicvarint` by `overrides`
in `pnpm-workspace.yaml`, so a lockfile update cannot change any of them. Your
package manager therefore never resolves these packages or their version ranges:
npm, pnpm and Yarn (classic and Berry/PnP) install the reviewed code byte for byte.
Their MIT license texts are in `THIRD_PARTY_LICENSES` inside the package.

`@noble/hashes` stays a regular dependency, pinned to an exact version, so it is
shared with other users of the noble libraries.

## Reviewed versions

Reviewed 2026-10-15. Downloads are for the week 2026-10-06 to 2026-10-12.

| Package | Version | License | Maintainers | Latest release | Weekly downloads | Dependencies | Provenance | Known advisories |
|---|---|---|---|---|---|---|---|---|
| `@hpke/core` | 1.9.0 | MIT | 1 (Ajitomi Daisuke) | 2026-03-08 | 866,230 | `@hpke/common` | npm signature + SLSA v1 (GitHub Actions) | GHSA-73g8-5h73-26h4 (concurrent `seal` on one context could reuse a nonce) affects `<= 1.7.4`; fixed in 1.7.5. 1.9.0 is not affected, and the SDK seals once per context |
| `@hpke/dhkem-x25519` | 1.8.0 | MIT | 1 (Ajitomi Daisuke) | 2026-03-08 | 361,813 | `@hpke/common` | npm signature + SLSA v1 | none |
| `@hpke/common` | 1.10.1 | MIT | 1 (Ajitomi Daisuke) | 2026-03-12 | 875,802 | none | npm signature + SLSA v1 | none |
| `@noble/curves` | 2.4.0 | MIT | 1 (Paul Miller); audited (Trail of Bits 2023, Kudelski 2023, Cure53 2024) | 2026-08-27 | 33,397,215 | `@noble/hashes` (exact) | npm signature + SLSA v1, trusted publisher with maintainer approval | none |
| `@noble/hashes` | 2.4.0 | MIT | 1 (Paul Miller) | 2026-08-27 | 97,075,664 | none | npm signature + SLSA v1, trusted publisher with maintainer approval | none |
| `bhttp-ts` | 0.6.1 | MIT | 1 (Thibault Meunier) | 2026-09-30 | 3,954 | `quicvarint` | npm signature + SLSA v1 (GitHub Actions) | none |
| `quicvarint` | 0.2.1 | MIT | 1 (Thibault Meunier) | 2026-08-19 | 6,647 | none | npm signature + SLSA v1 (GitHub Actions) | none |

Why these libraries:

- `@hpke/core` and `@hpke/dhkem-x25519` are the minimal HPKE set for DHKEM(X25519,
  HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. They pass the CFRG HPKE test vectors for
  that suite. The X25519 key agreement runs natively through WebCrypto where the
  runtime supports it, and in JavaScript otherwise; both give identical bytes.
- `@noble/curves` converts the attested Ed25519 public key to its X25519 form and
  checks that the point is not of small order and has no torsion component.
- `bhttp-ts` is the only actively maintained Binary HTTP (RFC 9292) codec for
  JavaScript. It has one maintainer and few dependents; we accept that because the
  code is small, fuzz-tested and published with provenance, and because the SDK
  adds its own checks on top (framing, informational responses, request paths).
- `@noble/hashes` provides HKDF-Extract for the Oblivious HTTP response key, whose
  64-byte salt the HPKE library's own KDF does not accept.

Development-only packages used to run the tests in a headless browser
(`@vitest/browser-playwright`, `playwright`) are not part of any published package.

### Development-only packages

| Package | Version | License | Maintainers | Latest release | Weekly downloads | Dependencies | Provenance | Known advisories |
|---|---|---|---|---|---|---|---|---|
| `@vitest/browser-playwright` | 4.1.10 | MIT | 5 (vitest team) | 2026-07-06 (newest 4.1.x; the 5.x line needs vitest 5) | 9,456,790 | `@vitest/browser` 4.1.10, `@vitest/mocker` 4.1.10, `tinyrainbow`; peer `vitest` exactly 4.1.10, `playwright` | npm signature + SLSA v1 | none |
| `playwright` | 1.64.0 | Apache-2.0 | 5 (Microsoft) | 2026-10-07 | 113,562,399 | `playwright-core` 1.64.0 | npm signature + SLSA v1 | none |
| `knip` | 6.42.1 | ISC | 1 | 2026-10-19 | 10,907,867 | 12 | npm signature | none |
| `jscpd` | 5.4.1 | MIT | 1 | 2026-10-09 | 2,125,963 | 0 (+ optional platform binary) | SLSA v1 | none |
| `dependency-cruiser` | 18.6.0 | MIT | 2 | 2026-10-11 | 3,310,180 | 18 | SLSA v1 | none |
| `publint` | 0.3.25 | MIT | 1 | 2026-10-01 | 989,557 | 4 | SLSA v1 | none |
| `@arethetypeswrong/cli` | 0.18.5 | MIT | 1 | 2026-07-09 | 564,068 | 7 | SLSA v1 | none |
| `@microsoft/api-extractor` | 7.59.4 | MIT | 3 | 2026-10-06 | 2,625,508 | 13 | npm signature | `sprintf-js` GHSA-hp3w-g68c-fv3c (moderate, dev-only) |
| `@vitest/coverage-v8` | 4.1.10 | MIT | 5 | 2026-07-06 | 24,912,227 | 10 | SLSA v1 | none |

`@vitest/browser-playwright` is the official vitest browser provider; its version
must equal the repository's `vitest` version. `playwright` has no install script;
the test browsers are downloaded by an explicit CI step. Version 1.64.0 is used
rather than the newer 1.64.1, which was one day old at review time.
`jscpd` and `dependency-cruiser` are one release behind the newest, which was less
than a day old at review time. `@vitest/coverage-v8` must equal the repository's
`vitest` version, like `@vitest/browser-playwright`.

## Accepted residual risk

- Single maintainer: every library in the reviewed-versions table has one maintainer. Mitigated by exact
  pins, provenance checks on every upgrade and the known-answer tests in this repo.
- Bundled code is invisible to your audit tools: `npm audit` in your project does not
  see the bundled libraries. We watch their advisories in this repository and ship a
  new SDK release when one applies.
- Ranges outside the bundled set: `@w3tech.io/vrpc-core` also depends on
  `@noble/ed25519` (`^3.1.0`) and `lru-cache` (`^11.5.2`), which your package
  manager resolves within those ranges. `@w3tech.io/vrpc-proxy` depends on
  `undici` (`^8.7.0`), resolved the same way. `@w3tech.io/dstack-verify` depends on
  `@noble/hashes` at an exact version.
- Duplicate copies: if your application also installs `@hpke/*`, `@noble/curves` or
  `bhttp-ts`, it carries its own copy next to the bundled one. The SDK exposes none
  of their types or objects, so the two copies never interact.
