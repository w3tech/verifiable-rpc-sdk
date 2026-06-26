import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps (@w3tech.io/*)
// and peer deps stay EXTERNAL (tsup default) so nothing is duplicated into the
// bundle. This package is a dependency-free LEAF (no @w3tech.io/* imports); the
// external policy is kept for parity with the other packages.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  dts: true,
  clean: true,
  sourcemap: true,
});
