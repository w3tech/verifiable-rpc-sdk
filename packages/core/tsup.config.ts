import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps
// (@w3tech.io/*) and peer deps stay EXTERNAL (tsup default), so the shared
// vrpc-core VerificationError keeps a single identity across adapters and
// nothing is duplicated into each bundle.
//
// `errors.ts` is a second entry so it gets a leaf `@w3tech.io/vrpc-core/errors`
// subpath: dstack-verify imports the base VerificationError from there instead
// of the full barrel, breaking the core<->dstack-verify ESM init cycle that
// otherwise leaves `VerificationError` undefined at class-extends time under
// Node. `splitting` keeps a single shared chunk so identity is preserved.
export default defineConfig({
  entry: ["src/index.ts", "src/errors.ts"],
  format: ["esm"],
  target: "node20",
  // Declarations are emitted separately by `tsc -p tsconfig.build.json` (see build
  // script). tsup's dts:true uses rollup-plugin-dts, which needs the TypeScript
  // programmatic Compiler API — absent in the TS 7 native compiler until 7.1.
  dts: false,
  clean: true,
  splitting: true,
  sourcemap: true,
});
