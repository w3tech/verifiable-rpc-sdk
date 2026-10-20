// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared checks of the built ethers and viem adapters.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

export const ERROR_CLASSES = [
  "AttestationFailed",
  "AttestationUnavailable",
  "BadSignature",
  "ConfidentialDecryptFailed",
  "ConfidentialSealFailed",
  "ConfidentialSignerMismatch",
  "InvalidChainId",
  "InvalidInnerRequest",
  "MalformedAttestationResponse",
  "MalformedConfidentialResponse",
  "MalformedHeader",
  "MissingHeader",
  "RequestRejected",
  "StaleTimestamp",
  "TransportFailed",
  "UnavailableError",
  "UnexpectedResponse",
  "VerificationError",
] as const;

export const CONFIDENTIAL_CLASSES = [
  "AttestationUnavailable",
  "ConfidentialDecryptFailed",
  "ConfidentialSealFailed",
  "ConfidentialSignerMismatch",
  "InvalidInnerRequest",
  "MalformedConfidentialResponse",
  "RequestRejected",
  "TransportFailed",
  "UnavailableError",
  "UnexpectedResponse",
] as const;

const ENTRY = "@w3tech.io/vrpc-core/confidential";
const quoted = ENTRY.replace(/[./]/g, "\\$&");
const DYNAMIC = new RegExp(`\\bimport\\s*\\(\\s*["']${quoted}["']`);
const STATIC = new RegExp(`(?:\\bfrom\\s*|\\bimport\\s+)["']${quoted}["']`);

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

// The built adapter in a plain node process, where no test alias maps a package to its source:
// one class identity with the built core, and the confidential entry loaded only on demand.
export function describeBuiltAdapter(adapter: string, distUrl: URL): void {
  const distDir = fileURLToPath(distUrl);
  const built =
    existsSync(join(distDir, "index.js")) &&
    existsSync(join(repoRoot, "packages/core/dist/confidential.js"));

  // CI builds before testing and sets REQUIRE_DIST, so a missing build fails there instead of skipping.
  test.runIf(process.env.REQUIRE_DIST === "1")("the package and core are built", () => {
    expect(built).toBe(true);
  });

  describe.skipIf(!built)("built package", () => {
    test("the confidential entry is imported dynamically only", () => {
      const files = readdirSync(distDir).filter((name) => name.endsWith(".js"));
      for (const file of files) {
        const text = readFileSync(join(distDir, file), "utf8");
        if (!text.includes(ENTRY)) continue;
        expect(STATIC.test(text), file).toBe(false);
        expect(DYNAMIC.test(text), file).toBe(true);
      }
      expect(DYNAMIC.test(readFileSync(join(distDir, "index.js"), "utf8"))).toBe(true);
    });

    test("a plain node process sees one class identity across the adapter and core", () => {
      const script = `
        import * as adapter from "${adapter}";
        import * as core from "@w3tech.io/vrpc-core";
        import * as errors from "@w3tech.io/vrpc-core/errors";
        import * as conf from "${ENTRY}";
        const all = ${JSON.stringify(ERROR_CLASSES)};
        const confidential = ${JSON.stringify(CONFIDENTIAL_CLASSES)};
        let checked = 0;
        for (const name of all) {
          const value = adapter[name];
          if (typeof value !== "function" || value !== core[name] || value !== errors[name]) {
            throw new Error("identity: " + name);
          }
          if (confidential.includes(name) && value !== conf[name]) throw new Error("entry: " + name);
          checked += 1;
        }
        if (!(new core.RequestRejected(429, "n") instanceof adapter.UnavailableError)) {
          throw new Error("instanceof");
        }
        process.stdout.write(String(checked));
      `;
      const out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        cwd: repoRoot,
        encoding: "utf8",
      });
      expect(out).toBe(String(ERROR_CLASSES.length));
    });

    test("the declarations carry the error kind and node info types", () => {
      const dts = readFileSync(join(distDir, "index.d.ts"), "utf8");
      expect(dts).toContain("UnavailableErrorKind");
      expect(dts).toContain("ConfidentialInfo");
    });
  });
}
