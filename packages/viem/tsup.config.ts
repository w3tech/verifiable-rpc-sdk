import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps
// (@w3tech.io/*) and peer deps stay EXTERNAL (tsup default), so the shared
// vrpc-core VerificationError keeps a single identity across adapters and
// nothing is duplicated into each bundle.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  dts: true,
  clean: true,
  sourcemap: true,
});
