import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps
// (@ankr.com/*) and peer deps stay EXTERNAL (tsup default), so the shared
// vrpc-core VerificationError keeps a single identity across adapters and
// nothing is duplicated into each bundle.
//
// `errors.ts` is a second entry so it gets a leaf `@ankr.com/vrpc-core/errors`
// subpath: dstack-verify imports the base VerificationError from there instead
// of the full barrel, breaking the core<->dstack-verify ESM init cycle that
// otherwise leaves `VerificationError` undefined at class-extends time under
// Node. `splitting` keeps a single shared chunk so identity is preserved.
//
// `compose.ts` is a third leaf entry for the same cycle-avoidance reason:
// dstack-verify imports `computeComposeHash` from `@ankr.com/vrpc-core/compose`
// (CHK-A2) instead of the full barrel — the barrel re-exports trusted-verifier.ts
// which imports `@ankr.com/dstack-verify` (the CYCLE-01 ESM init cycle).
// compose.ts only depends on @noble/hashes + the leaf ./errors + ./preimage, so
// it is cycle-free.
export default defineConfig({
  entry: ["src/index.ts", "src/errors.ts", "src/compose.ts"],
  format: ["esm"],
  target: "node20",
  dts: true,
  clean: true,
  splitting: true,
  sourcemap: true,
});
