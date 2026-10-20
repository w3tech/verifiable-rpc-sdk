// Every error class Ankr Confidential RPC mode can throw is exported by the adapter as the very
// class core exports from each of its entries, so instanceof holds whichever one a caller imports.

import * as core from "@w3tech.io/vrpc-core";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import * as errors from "@w3tech.io/vrpc-core/errors";
import * as adapter from "@w3tech.io/vrpc-ethers";
import {
  createTestNode,
  mockHardwareVerifier,
  serveTestNode,
  type TestUpstreamResponse,
} from "@w3tech.io/vrpc-test-support";
import { afterEach, describe, expect, test } from "vitest";
import { CHAIN_ID, TEST_SEED } from "./fixtures";

const ERROR_CLASSES = [
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

const CONFIDENTIAL_CLASSES = [
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

type Namespace = Record<string, unknown>;

const KEY = "0123456789abcdefghijABCDEFGHIJkl";
const cleanups: Array<() => unknown> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function errorExports(namespace: Namespace): string[] {
  return Object.keys(namespace)
    .filter((name) => {
      const value = namespace[name];
      return typeof value === "function" && value.prototype instanceof Error;
    })
    .sort();
}

describe("error classes exported by the ethers adapter", () => {
  test.each(ERROR_CLASSES)("%s is the core class from the main and errors entries", (name) => {
    const value = (adapter as Namespace)[name];
    expect(typeof value).toBe("function");
    expect(value).toBe((core as Namespace)[name]);
    expect(value).toBe((errors as Namespace)[name]);
  });

  test.each(CONFIDENTIAL_CLASSES)("%s is the core class from the confidential entry", (name) => {
    expect((adapter as Namespace)[name]).toBe((conf as Namespace)[name]);
  });

  test("the adapter exports exactly this error set and declares none of its own", () => {
    expect(errorExports(adapter as Namespace)).toEqual([...ERROR_CLASSES]);
  });
});

describe("an error from a live call", () => {
  test("a rejected sealed call is an instance of the classes from every entry", async () => {
    const node = createTestNode({
      seed: TEST_SEED,
      chainId: CHAIN_ID,
      nodeId: "alpha-vrpc-1",
      upstream: async (request): Promise<TestUpstreamResponse> => {
        const call = JSON.parse(await request.text()) as { id: number };
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: call.id, result: "0x10" }),
        };
      },
    });
    const server = await serveTestNode(node);
    cleanups.push(() => server.close());
    server.answer((request) =>
      request.method === "POST"
        ? { status: 429, headers: { "content-type": "text/plain", "retry-after": "1" } }
        : undefined,
    );
    const provider = new adapter.VrpcProvider(`${server.url}/eth_vrpc/${KEY}`, 42161, {
      confidential: true,
      hardwareVerifier: mockHardwareVerifier(),
      cacheTimeout: -1,
    });
    cleanups.push(() => provider.destroy());

    const err = await provider.getBlockNumber().then(
      () => undefined,
      (e: unknown) => e,
    );

    for (const entry of [adapter, core, errors, conf]) {
      expect(err).toBeInstanceOf(entry.RequestRejected);
      expect(err).toBeInstanceOf(entry.UnavailableError);
    }
    expect((err as core.RequestRejected).status).toBe(429);
  });
});
