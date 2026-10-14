import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, type Options } from "tsup";
import { afterAll, describe, expect, test } from "vitest";
import dstackVerifyManifest from "../../dstack-verify/package.json";
import proxyManifest from "../../proxy/package.json";
import testSupportManifest from "../../test-support/package.json";
import coreManifest from "../package.json";
import tsupConfig from "../tsup.config";

const BUNDLED_PINS: Record<string, string> = {
  "@hpke/core": "1.9.0",
  "@hpke/dhkem-x25519": "1.8.0",
  "@noble/curves": "2.4.0",
  "bhttp-ts": "0.6.1",
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
};

const core = coreManifest as Manifest;
const dstackVerify = dstackVerifyManifest as Manifest;
const proxy = proxyManifest as Manifest;
const testSupport = testSupportManifest as Manifest;
const config = tsupConfig as Options;

const coreDir = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(coreDir, "dist");

// Matches `from "x"`, `import "x"` and `import("x")`.
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*)["']([^"']+)["']/g;

function importSpecifiers(dir: string): string[] {
  const specifiers = new Set<string>();
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".js"))) {
    for (const match of readFileSync(join(dir, file), "utf8").matchAll(SPECIFIER)) {
      if (match[1] !== undefined) specifiers.add(match[1]);
    }
  }
  return [...specifiers];
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
});

describe("core manifest", () => {
  test("engines, browser field and shipped license file", () => {
    expect(core.engines?.node).toBe(">=20.19.0");
    expect(proxy.engines?.node).toBe(">=22.19.0");
    expect(core.browser).toEqual({ crypto: false });
    expect(core.files).toContain("THIRD_PARTY_LICENSES");
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

  test("crypto modules bundle to imports of @noble/hashes, crypto and local chunks only", async () => {
    await build({
      ...config,
      config: false,
      entry: {
        "node-key": fileURLToPath(new URL("../src/node-key.ts", import.meta.url)),
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
