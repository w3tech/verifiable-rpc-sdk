import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps
// (@w3tech.io/*) and peer deps stay EXTERNAL (tsup default), so the shared
// vrpc-core VerificationError keeps a single identity across adapters and
// nothing is duplicated into each bundle.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  // Declarations are emitted separately by `tsc -p tsconfig.build.json` (see build
  // script). tsup's dts:true uses rollup-plugin-dts, which needs the TypeScript
  // programmatic Compiler API — absent in the TS 7 native compiler until 7.1.
  dts: false,
  clean: true,
  sourcemap: true,
});
