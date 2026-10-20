import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Resolve the absolute path of a workspace source file from this config's dir.
const src = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));

// Alias each `@w3tech.io/*` specifier (subpaths first) to its `src` entry so tests run on source.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@w3tech.io/vrpc-core/errors",
        replacement: src("./packages/core/src/errors.ts"),
      },
      {
        find: "@w3tech.io/vrpc-core/confidential",
        replacement: src("./packages/core/src/confidential.ts"),
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
    coverage: { include: ["src/**"] },
  },
});
