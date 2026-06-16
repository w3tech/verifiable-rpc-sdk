import { describe, expect, test } from "bun:test";
import ethersManifest from "../../ethers/package.json";
import viemManifest from "../../viem/package.json";
import coreManifest from "../package.json";

// TEST-01: encode the dependency-isolation invariants (PKG-02/03/04/05) as a
// checkable test now, while the adapters are stubs. A wrong dependency field
// (e.g. ethers/viem listed under `dependencies` instead of `peerDependencies`)
// would silently pull a duplicate client-lib instance and break `instanceof`
// identity for the downstream adapters — so we assert the exact field layout.

type Manifest = {
  name: string;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

const core = coreManifest as Manifest;
const ethers = ethersManifest as Manifest;
const viem = viemManifest as Manifest;

describe("vrpc-core dependency isolation (PKG-02)", () => {
  test("core is @ankr.com/vrpc-core", () => {
    expect(core.name).toBe("@ankr.com/vrpc-core");
  });

  test("core declares neither ethers nor viem in dependencies", () => {
    expect(core.dependencies?.ethers).toBeUndefined();
    expect(core.dependencies?.viem).toBeUndefined();
  });

  test("core declares neither ethers nor viem in peerDependencies", () => {
    expect(core.peerDependencies?.ethers).toBeUndefined();
    expect(core.peerDependencies?.viem).toBeUndefined();
  });

  test("core depends on the @noble/* crypto primitives only", () => {
    expect(core.dependencies?.["@noble/ed25519"]).toBeDefined();
    expect(core.dependencies?.["@noble/hashes"]).toBeDefined();
  });
});

describe("vrpc-ethers dependency isolation (PKG-03/PKG-05)", () => {
  test("ethers is @ankr.com/vrpc-ethers", () => {
    expect(ethers.name).toBe("@ankr.com/vrpc-ethers");
  });

  test("lists ethers ONLY under peerDependencies (not dependencies)", () => {
    expect(ethers.peerDependencies?.ethers).toBeDefined();
    expect(ethers.dependencies?.ethers).toBeUndefined();
  });

  test("does not list viem in any dependency field", () => {
    expect(ethers.dependencies?.viem).toBeUndefined();
    expect(ethers.peerDependencies?.viem).toBeUndefined();
    expect(ethers.devDependencies?.viem).toBeUndefined();
  });

  test("depends on @ankr.com/vrpc-core as workspace:* (PKG-05)", () => {
    expect(ethers.dependencies?.["@ankr.com/vrpc-core"]).toBe("workspace:*");
  });
});

describe("vrpc-viem dependency isolation (PKG-04/PKG-05)", () => {
  test("viem is @ankr.com/vrpc-viem", () => {
    expect(viem.name).toBe("@ankr.com/vrpc-viem");
  });

  test("lists viem ONLY under peerDependencies (not dependencies)", () => {
    expect(viem.peerDependencies?.viem).toBeDefined();
    expect(viem.dependencies?.viem).toBeUndefined();
  });

  test("does not list ethers in any dependency field", () => {
    expect(viem.dependencies?.ethers).toBeUndefined();
    expect(viem.peerDependencies?.ethers).toBeUndefined();
    expect(viem.devDependencies?.ethers).toBeUndefined();
  });

  test("depends on @ankr.com/vrpc-core as workspace:* (PKG-05)", () => {
    expect(viem.dependencies?.["@ankr.com/vrpc-core"]).toBe("workspace:*");
  });
});
