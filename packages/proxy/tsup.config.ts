import { defineConfig } from "tsup";

// ESM build for npm publish + plain-Node consumption. Workspace deps (@w3tech.io/*)
// stay EXTERNAL (tsup default) so nothing is duplicated into the bundle.
//
// `cli.ts` is a second entry producing the `vrpc-proxy` bin: its source shebang is
// preserved (and the output chmod +x'd) by tsup for that entry only. dts is scoped
// to index so no useless cli.d.ts ships.
export default defineConfig({
  entry: ["src/index.ts", "src/cli.ts"],
  format: ["esm"],
  target: "node20",
  dts: { entry: { index: "src/index.ts" } },
  clean: true,
  sourcemap: true,
});
