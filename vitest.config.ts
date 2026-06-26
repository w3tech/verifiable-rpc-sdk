import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Resolve the absolute path of a workspace source file from this config's dir.
const src = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));

// Dev source-resolution (option a — vitest resolve.alias).
//
// Under the old bun toolchain the `"bun"` export condition made in-repo imports
// of `@w3tech.io/*` resolve to `./src/*.ts`. That dev-only condition is removed
// (the published `exports`/`publishConfig` → ./dist are untouched). To keep
// tests resolving workspace packages to SOURCE (not built dist), we alias the 5
// `@w3tech.io/*` specifiers — including `@w3tech.io/vrpc-core/errors` — to their
// `src` entry. Longest-prefix subpath alias listed first so `/errors` wins over
// the bare package alias.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@w3tech.io/vrpc-core/errors",
        replacement: src("./packages/core/src/errors.ts"),
      },
      {
        find: "@w3tech.io/vrpc-core/compose",
        replacement: src("./packages/core/src/compose.ts"),
      },
      {
        find: "@w3tech.io/vrpc-core",
        replacement: src("./packages/core/src/index.ts"),
      },
      {
        find: "@w3tech.io/dstack-verify",
        replacement: src("./packages/dstack-verify/src/index.ts"),
      },
      {
        find: "@w3tech.io/vrpc-ethers",
        replacement: src("./packages/ethers/src/index.ts"),
      },
      {
        find: "@w3tech.io/vrpc-viem",
        replacement: src("./packages/viem/src/index.ts"),
      },
    ],
  },
  test: {
    environment: "node",
    // Globs are matched against each invocation's project root (the package dir
    // under `pnpm -r test`, or the repo root for a top-level `vitest run`), so
    // we use `**` rather than a `packages/*` prefix. node_modules + dist are
    // excluded by vitest defaults — the injected workspace copies under
    // `node_modules/@w3tech.io/*/tests` are therefore never collected.
    include: ["**/test/**/*.test.ts", "**/tests/**/*.test.ts"],
  },
});
