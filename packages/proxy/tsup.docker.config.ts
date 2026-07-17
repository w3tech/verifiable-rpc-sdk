import { defineConfig } from "tsup";

// Docker image build ONLY — never published to npm (excluded by the "files"
// whitelist in package.json). Unlike tsup.config.ts, which keeps workspace deps
// external by design, this config bundles EVERYTHING (vrpc-core, undici,
// noble/*, lru-cache) into one self-contained cli.js: the distroless runtime
// stage carries that single file and no node_modules.
export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["esm"],
  target: "node22",
  noExternal: [/.*/],
  splitting: false,
  sourcemap: false,
  clean: false,
  outDir: "dist-docker",
  banner: {
    // REQUIRED: undici is CJS and dynamic-requires node builtins; without this
    // banner the ESM bundle throws `Dynamic require of "assert" is not supported`.
    js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
  },
});
