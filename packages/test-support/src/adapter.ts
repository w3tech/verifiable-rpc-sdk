// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared checks of the ethers and viem adapters.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const ERROR_CLASSES = [
  "AttestationFailed",
  "AttestationUnavailable",
  "BadSignature",
  "ConfidentialDecryptFailed",
  "ConfidentialSignerMismatch",
  "InternalError",
  "InvalidChainId",
  "InvalidInnerRequest",
  "InvalidOption",
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
  "VrpcError",
] as const;

const CONFIDENTIAL_CLASSES = [
  "AttestationUnavailable",
  "ConfidentialDecryptFailed",
  "ConfidentialSignerMismatch",
  "InternalError",
  "InvalidInnerRequest",
  "InvalidOption",
  "MalformedConfidentialResponse",
  "RequestRejected",
  "TransportFailed",
  "UnavailableError",
  "UnexpectedResponse",
  "VrpcError",
] as const;

type Namespace = Record<string, unknown>;

function errorExports(namespace: Namespace): string[] {
  return Object.keys(namespace)
    .filter((name) => {
      const value = namespace[name];
      return typeof value === "function" && value.prototype instanceof Error;
    })
    .sort();
}

// The adapter exports each error class as the very class the core entries export.
export function describeAdapterErrors(
  name: string,
  entries: { adapter: object; core: object; errors: object; confidential: object },
): void {
  const adapter = entries.adapter as Namespace;
  describe(`error classes exported by the ${name} adapter`, () => {
    test.each(ERROR_CLASSES)("%s is the core class from the main and errors entries", (error) => {
      const value = adapter[error];
      expect(typeof value).toBe("function");
      expect(value).toBe((entries.core as Namespace)[error]);
      expect(value).toBe((entries.errors as Namespace)[error]);
    });

    test.each(CONFIDENTIAL_CLASSES)("%s is the core class from the confidential entry", (error) => {
      expect(adapter[error]).toBe((entries.confidential as Namespace)[error]);
    });

    test("the adapter exports exactly this error set and declares none of its own", () => {
      expect(errorExports(adapter)).toEqual([...ERROR_CLASSES]);
    });
  });
}

const ENTRY = "@w3tech.io/vrpc-core/confidential";
const quoted = ENTRY.replace(/[./]/g, "\\$&");
const STATIC = new RegExp(`(?:\\bfrom\\s*|\\bimport\\s+)["']${quoted}["']`);

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

// The built adapter in a plain node process, where no test alias maps a package to its source:
// one class identity with the built core, and the confidential entry never loaded statically.
export function describeBuiltAdapter(adapter: string): void {
  const distDir = join(repoRoot, "packages", adapter.replace("@w3tech.io/vrpc-", ""), "dist");
  const built =
    existsSync(join(distDir, "index.js")) &&
    existsSync(join(repoRoot, "packages/core/dist/confidential.js"));

  // CI builds before testing and sets REQUIRE_DIST, so a missing build fails there instead of skipping.
  test.runIf(process.env.REQUIRE_DIST === "1")("the package and core are built", () => {
    expect(built).toBe(true);
  });

  describe.skipIf(!built)("built package", () => {
    test("the confidential entry is never imported statically", () => {
      for (const file of readdirSync(distDir).filter((name) => name.endsWith(".js"))) {
        expect(STATIC.test(readFileSync(join(distDir, file), "utf8")), file).toBe(false);
      }
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
