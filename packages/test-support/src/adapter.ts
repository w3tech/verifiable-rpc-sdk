// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Shared checks of the ethers and viem adapters.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { rejectionOf } from "./rejection";
import { failureAnswer, type ServedRequest, type TestNodeServer } from "./server";

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
  const classes = errorExports(entries.errors as Namespace);
  describe(`error classes exported by the ${name} adapter`, () => {
    test("the adapter exports every core error class and declares none of its own", () => {
      expect(classes.length).toBeGreaterThan(0);
      expect(errorExports(adapter)).toEqual(classes);
    });

    test.each(classes)("%s is the core class from every entry that exports it", (error) => {
      expect(adapter[error]).toBe((entries.core as Namespace)[error]);
      expect(adapter[error]).toBe((entries.errors as Namespace)[error]);
      if (error in entries.confidential) {
        expect(adapter[error]).toBe((entries.confidential as Namespace)[error]);
      }
    });

    test("mayHaveExecuted is the function every core entry exports", () => {
      for (const entry of [entries.core, entries.errors, entries.confidential]) {
        expect(adapter.mayHaveExecuted).toBe((entry as Namespace).mayHaveExecuted);
      }
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
        const classes = (ns) =>
          Object.keys(ns).filter((n) => ns[n]?.prototype instanceof Error).sort().join();
        const all = classes(errors).split(",");
        if (!all[0] || classes(adapter) !== all.join()) throw new Error("set: " + classes(adapter));
        for (const name of all) {
          const value = adapter[name];
          if (value !== core[name] || value !== errors[name]) throw new Error("identity: " + name);
          if (name in conf && value !== conf[name]) throw new Error("entry: " + name);
        }
        if (!(new core.RequestRejected(429, "n") instanceof adapter.UnavailableError)) {
          throw new Error("instanceof");
        }
        process.stdout.write(String(all.length));
      `;
      const out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        cwd: repoRoot,
        encoding: "utf8",
      });
      expect(Number(out)).toBeGreaterThan(0);
    });

    test("the declarations carry the error kind and node info types", () => {
      const dts = readFileSync(join(distDir, "index.d.ts"), "utf8");
      expect(dts).toContain("UnavailableErrorKind");
      expect(dts).toContain("ConfidentialInfo");
    });
  });
}

/** Only attestation GETs and sealed POSTs left, with no JSON-RPC or sentinel in clear. */
export function expectSealedTrafficOnly(
  requests: readonly ServedRequest[],
  sentinels: readonly string[],
): void {
  const hex = (text: string) => Buffer.from(text, "utf8").toString("hex");
  for (const request of requests) {
    const query = new URLSearchParams(request.url.split("?")[1] ?? "");
    if (request.method === "GET") {
      expect(request.path.endsWith("/attestation")).toBe(true);
      expect(query.has("nonce")).toBe(true);
    } else {
      expect(request.method).toBe("POST");
      expect(request.path.endsWith("/confidential")).toBe(true);
      expect(query.has("node_id")).toBe(true);
      expect(request.headers["content-type"]).toBe("message/ohttp-req");
    }
    const bodyText = Buffer.from(request.body).toString("utf8");
    const bodyHex = Buffer.from(request.body).toString("hex");
    // The route prefix is the caller's own URL; everything after it is checked.
    const afterRoute = request.url.replace(/^\/eth_vrpc\//, "/");
    for (const needle of ["eth_", "jsonrpc", ...sentinels]) {
      expect(afterRoute).not.toContain(needle);
      expect(bodyText).not.toContain(needle);
      expect(bodyHex).not.toContain(needle);
      expect(bodyHex).not.toContain(hex(needle));
    }
  }
}

function textForms(err: unknown): string[] {
  if (typeof err !== "object" || err === null) return [String(err)];
  const e = err as Error;
  let json: string;
  try {
    json =
      JSON.stringify(e, (_key, value) => (typeof value === "bigint" ? value.toString() : value)) ??
      "";
  } catch {
    json = "unserialisable";
  }
  return [String(e.message), String(e), String(e.stack ?? ""), json];
}

function windows(bytes: Uint8Array): string[] {
  const out: string[] = [];
  for (let offset = 0; offset + 16 <= bytes.byteLength; offset += 16) {
    out.push(Buffer.from(bytes.subarray(offset, offset + 16)).toString("hex"));
  }
  return out;
}

/** No secret and no 16-byte hex window of a body in the message, string, stack or JSON of any error. */
export function expectNoSecrets(
  errors: readonly unknown[],
  secrets: readonly string[],
  bodies: readonly Uint8Array[],
): void {
  const needles = [...secrets, ...bodies.flatMap(windows)];
  for (const item of errors) {
    for (const form of textForms(item)) {
      for (const needle of needles) expect(form).not.toContain(needle);
    }
  }
}

interface OneRequestCase {
  server: TestNodeServer;
  call(): Promise<unknown>;
  ready(): Promise<unknown>;
  /** Requests the caller's own fetcher saw, when it has one. */
  fetched?: (() => number) | undefined;
}

/** One outer request per call whatever the gateway answers; `vrpcError` finds the core error in the adapter's. */
export function describeOneRequestPerCall(
  title: string,
  setup: () => Promise<OneRequestCase>,
  vrpcError: (err: unknown) => unknown,
): void {
  async function failedOnce(leg: "POST" | "GET", status: number): Promise<unknown> {
    const run = await setup();
    if (leg === "POST") await run.ready();
    run.server.requests.splice(0);
    const before = run.fetched?.() ?? 0;
    run.server.answer((request) =>
      request.method === leg ? failureAnswer(run.server, status) : undefined,
    );
    const err = vrpcError(await rejectionOf(run.call()));
    expect(run.server.requests.map((request) => request.method)).toEqual([leg]);
    if (run.fetched) expect(run.fetched() - before).toBe(1);
    return err;
  }

  describe(title, () => {
    test.each([
      429, 301, 302, 303, 307, 308, 500, 502, 503, 504,
    ])("the sealed POST answered %i is sent once and no redirect is followed", async (status) => {
      expect(await failedOnce("POST", status)).toMatchObject(
        status === 429
          ? { kind: "RequestRejected", status, executed: "no" }
          : { kind: "UnexpectedResponse", status },
      );
    });

    test.each([
      429, 302, 307, 502,
    ])("the cold attestation answered %i is sent once and nothing is sealed", async (status) => {
      expect(await failedOnce("GET", status)).toMatchObject({
        kind: "AttestationUnavailable",
        reason: "status",
        status,
      });
    });
  });
}
