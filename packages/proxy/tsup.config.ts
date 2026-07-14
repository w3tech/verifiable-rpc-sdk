import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps (@w3tech.io/*)
// stay EXTERNAL (tsup default) so nothing is duplicated into the bundle.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  dts: true,
  clean: true,
  sourcemap: true,
});
