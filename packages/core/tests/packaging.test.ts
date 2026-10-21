import { existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import testSupportManifest from "@w3tech.io/vrpc-test-support/package.json";
import { build, type Options } from "tsup";
import { afterAll, describe, expect, test } from "vitest";
import rootManifest from "../../../package.json";
import dstackVerifyManifest from "../../dstack-verify/package.json";
import proxyManifest from "../../proxy/package.json";
import coreManifest from "../package.json";
import tsupConfig from "../tsup.config";

const BUNDLED_PINS: Record<string, string> = {
  "@hpke/core": "1.9.0",
  "@hpke/dhkem-x25519": "1.8.0",
  "@noble/curves": "2.4.0",
  "bhttp-ts": "0.6.1",
};
const TRANSITIVE_PINS: Record<string, { version: string; parents: string[] }> = {
  "@hpke/common": { version: "1.10.1", parents: ["@hpke/core", "@hpke/dhkem-x25519"] },
  quicvarint: { version: "0.2.1", parents: ["bhttp-ts"] },
};
const NOBLE_HASHES = "2.4.0";
const BUNDLED_PACKAGES = [
  "@hpke/core",
  "@hpke/dhkem-x25519",
  "@hpke/common",
  "@noble/curves",
  "bhttp-ts",
  "quicvarint",
];
const EXACT_VERSION = /^\d+\.\d+\.\d+$/;

type Manifest = {
  name: string;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  browser?: Record<string, unknown>;
  files?: string[];
  exports?: Record<string, string | Record<string, string>>;
  publishConfig?: { exports?: Record<string, string | Record<string, string>> };
};

const core = coreManifest as Manifest;
const dstackVerify = dstackVerifyManifest as Manifest;
const proxy = proxyManifest as Manifest;
const testSupport = testSupportManifest as Manifest;
const root = rootManifest as Manifest;
const config = tsupConfig as Options;

const coreDir = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(coreDir, "dist");

// Matches `from "x"`, `import "x"` and `import("x")`.
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*)["']([^"']+)["']/g;
// Matches `from "x"` and `import "x"` only.
const STATIC_SPECIFIER = /(?:\bfrom\s*|\bimport\s+)["']([^"']+)["']/g;
const DYNAMIC_LOCAL = /\bimport\s*\(\s*["']\.\/([^"']+)["']/g;

const BHTTP_REQUEST_LABEL = "message/bhttp request";
const CLASS_DECLARATION = (name: string) => new RegExp(`\\bclass ${name}\\b|\\b${name} = class`);

function importSpecifiers(dir: string): string[] {
  const specifiers = new Set<string>();
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".js"))) {
    for (const match of readFileSync(join(dir, file), "utf8").matchAll(SPECIFIER)) {
      if (match[1] !== undefined) specifiers.add(match[1]);
    }
  }
  return [...specifiers];
}

function closure(dir: string, entry: string, pattern = SPECIFIER): string[] {
  const seen = new Set<string>();
  const visit = (file: string) => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const match of readFileSync(join(dir, file), "utf8").matchAll(pattern)) {
      const specifier = match[1];
      if (specifier?.startsWith("./")) visit(specifier.slice(2));
    }
  };
  visit(entry);
  return [...seen];
}

// Walks node_modules like Node does, so packages whose exports hide package.json resolve too.
function installedPackage(name: string, from: string): { dir: string; version: string } {
  for (const dir of createRequire(from).resolve.paths(name) ?? []) {
    const manifest = join(dir, name, "package.json");
    if (existsSync(manifest)) {
      const { version } = JSON.parse(readFileSync(manifest, "utf8")) as { version: string };
      return { dir: realpathSync(join(dir, name)), version };
    }
  }
  throw new Error(`${name} is not installed`);
}

function namesBundledPackage(specifier: string): boolean {
  return BUNDLED_PACKAGES.some((name) => specifier === name || specifier.startsWith(`${name}/`));
}

describe("exact pins", () => {
  test("bundled libraries are exact core devDependencies and never runtime dependencies", () => {
    for (const [name, version] of Object.entries(BUNDLED_PINS)) {
      expect(core.devDependencies?.[name], name).toBe(version);
      expect(core.dependencies?.[name], name).toBeUndefined();
      expect(core.peerDependencies?.[name], name).toBeUndefined();
    }
  });

  test("every bundled library is installed at its reviewed version and documented", () => {
    const reviewed: Record<string, string> = { ...BUNDLED_PINS };
    for (const [name, { version }] of Object.entries(TRANSITIVE_PINS)) reviewed[name] = version;
    expect(Object.keys(reviewed).sort()).toEqual([...BUNDLED_PACKAGES].sort());

    const fromCore = join(coreDir, "package.json");
    for (const [name, version] of Object.entries(BUNDLED_PINS)) {
      expect(installedPackage(name, fromCore).version, name).toBe(version);
    }
    for (const [name, { version, parents }] of Object.entries(TRANSITIVE_PINS)) {
      for (const parent of parents) {
        const parentDir = installedPackage(parent, fromCore).dir;
        const installed = installedPackage(name, join(parentDir, "package.json"));
        expect(installed.version, `${name} under ${parent}`).toBe(version);
      }
    }

    const licenses = readFileSync(join(coreDir, "THIRD_PARTY_LICENSES"), "utf8").split("\n");
    const dependencies = readFileSync(join(coreDir, "../../docs/dependencies.md"), "utf8");
    for (const [name, version] of Object.entries(reviewed)) {
      expect(licenses, name).toContain(`${name} ${version}`);
      expect(dependencies, name).toContain(`| \`${name}\` | ${version} |`);
    }
  });

  test("@noble/hashes is exact in core and dstack-verify", () => {
    expect(core.dependencies?.["@noble/hashes"]).toBe(NOBLE_HASHES);
    expect(dstackVerify.dependencies?.["@noble/hashes"]).toBe(NOBLE_HASHES);
  });

  test("test-support declares the same exact versions as core", () => {
    const coreVersions = { ...core.devDependencies, ...core.dependencies };
    const entries = Object.entries(testSupport.dependencies ?? {});
    expect(entries.length).toBeGreaterThan(0);
    for (const [name, version] of entries) {
      expect(version, name).toMatch(EXACT_VERSION);
      expect(coreVersions[name], name).toBe(version);
    }
  });

  test("browser test and coverage packages are exact root devDependencies matching the installed vitest", () => {
    const vitest = JSON.parse(
      readFileSync(new URL("../../../node_modules/vitest/package.json", import.meta.url), "utf8"),
    ) as { version: string };
    expect(root.devDependencies?.["@vitest/browser-playwright"]).toBe("4.1.10");
    expect(root.devDependencies?.["@vitest/browser-playwright"]).toBe(vitest.version);
    expect(root.devDependencies?.["@vitest/coverage-v8"]).toBe(vitest.version);
    expect(root.devDependencies?.playwright).toBe("1.64.0");
  });
});

describe("core manifest", () => {
  test("engines, browser field and shipped license file", () => {
    expect(core.engines?.node).toBe("^22.16.0 || >=24");
    expect(proxy.engines?.node).toBe(">=24");
    expect(core.browser).toEqual({ crypto: false });
    expect(core.files).toContain("THIRD_PARTY_LICENSES");
  });

  test("the confidential subpath is exported like the errors subpath", () => {
    expect(core.exports?.["./errors"]).toEqual({
      types: "./src/errors.ts",
      import: "./dist/errors.js",
      default: "./dist/errors.js",
    });
    expect(core.exports?.["./confidential"]).toEqual({
      types: "./src/confidential.ts",
      import: "./dist/confidential.js",
      default: "./dist/confidential.js",
    });
    expect(core.publishConfig?.exports?.["./errors"]).toEqual({
      types: "./dist/errors.d.ts",
      import: "./dist/errors.js",
      default: "./dist/errors.js",
    });
    expect(core.publishConfig?.exports?.["./confidential"]).toEqual({
      types: "./dist/confidential.d.ts",
      import: "./dist/confidential.js",
      default: "./dist/confidential.js",
    });
  });
});

describe("bundling", () => {
  const outDir = mkdtempSync(join(tmpdir(), "vrpc-core-bundle-"));

  afterAll(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  test("tsup noExternal lists every bundled library", () => {
    expect(config.noExternal).toEqual(expect.arrayContaining(BUNDLED_PACKAGES));
  });

  test("tsup builds the main, errors and confidential entries", () => {
    expect(config.entry).toEqual(
      expect.arrayContaining(["src/index.ts", "src/errors.ts", "src/confidential.ts"]),
    );
  });

  test("the confidential code is reachable statically only from the confidential entry", async () => {
    const entriesDir = mkdtempSync(join(tmpdir(), "vrpc-core-entries-"));
    try {
      await build({
        ...config,
        config: false,
        entry: {
          index: fileURLToPath(new URL("../src/index.ts", import.meta.url)),
          errors: fileURLToPath(new URL("../src/errors.ts", import.meta.url)),
          confidential: fileURLToPath(new URL("../src/confidential.ts", import.meta.url)),
        },
        outDir: entriesDir,
        dts: false,
        sourcemap: false,
        silent: true,
        skipNodeModulesBundle: true,
      });
      const read = (file: string) => readFileSync(join(entriesDir, file), "utf8");
      const hasBhttp = (entry: string) =>
        closure(entriesDir, entry).some((file) => read(file).includes(BHTTP_REQUEST_LABEL));
      for (const entry of ["index.js", "errors.js"]) {
        for (const file of closure(entriesDir, entry, STATIC_SPECIFIER)) {
          expect(read(file), `${file} from ${entry}`).not.toContain(BHTTP_REQUEST_LABEL);
        }
      }
      const lazy = [...read("index.js").matchAll(DYNAMIC_LOCAL)].map((match) => match[1] ?? "");
      expect(lazy.some(hasBhttp), "index.js loads the confidential client on demand").toBe(true);
      expect(hasBhttp("confidential.js")).toBe(true);
      for (const specifier of importSpecifiers(entriesDir)) {
        expect(namesBundledPackage(specifier), specifier).toBe(false);
      }
      const outputs = readdirSync(entriesDir).filter((name) => name.endsWith(".js"));
      for (const name of [
        "VrpcError",
        "ConfidentialClient",
        "VerificationError",
        "UnavailableError",
        "InternalError",
        "ResponseTooLarge",
      ]) {
        const declaring = outputs.filter((file) => CLASS_DECLARATION(name).test(read(file)));
        expect(declaring, name).toHaveLength(1);
      }
    } finally {
      rmSync(entriesDir, { recursive: true, force: true });
    }
  }, 60_000);

  test("crypto modules bundle to imports of @noble/hashes, crypto and local chunks only", async () => {
    await build({
      ...config,
      config: false,
      entry: {
        ohttp: fileURLToPath(new URL("../src/ohttp.ts", import.meta.url)),
        bhttp: fileURLToPath(new URL("../src/bhttp.ts", import.meta.url)),
      },
      outDir,
      dts: false,
      sourcemap: false,
      silent: true,
      // Externalise every package except the noExternal list, whatever the dependency fields say.
      skipNodeModulesBundle: true,
    });
    const specifiers = importSpecifiers(outDir);
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      const allowed =
        specifier === "crypto" ||
        specifier.startsWith("@noble/hashes/") ||
        specifier.startsWith("./");
      expect(allowed, specifier).toBe(true);
    }
  }, 30_000);

  test.skipIf(!existsSync(join(distDir, "index.js")))(
    "built dist neither imports nor declares the bundled libraries",
    () => {
      expect(existsSync(join(distDir, "confidential.js"))).toBe(true);
      expect(existsSync(join(distDir, "confidential.d.ts"))).toBe(true);
      for (const specifier of importSpecifiers(distDir)) {
        expect(namesBundledPackage(specifier), specifier).toBe(false);
      }
      for (const file of readdirSync(distDir).filter((name) => name.endsWith(".d.ts"))) {
        expect(readFileSync(join(distDir, file), "utf8")).not.toMatch(
          /@hpke|@noble\/curves|bhttp-ts|quicvarint/,
        );
      }
    },
  );
});
