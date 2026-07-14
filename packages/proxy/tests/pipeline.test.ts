// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Unit tests for the pipeline's pure helpers: the undici error → transport
// taxonomy map and the upstream target-URL merge (path join, query merge,
// dot-segment traversal containment). No network, no server.

import { describe, expect, test } from "vitest";

import { UpstreamConnectError, UpstreamTimeoutError } from "../src/errors";
import { buildTargetUrl, mapUndiciError } from "../src/pipeline";

function undiciError(code: string, message = code): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

describe("mapUndiciError", () => {
  test("connectTimeoutMapsTo504UpstreamTimeout", () => {
    const err = mapUndiciError(undiciError("UND_ERR_CONNECT_TIMEOUT"));
    expect(err).toBeInstanceOf(UpstreamTimeoutError);
    expect(err.httpStatus).toBe(504);
  });

  test("headersTimeoutMapsTo504UpstreamTimeout", () => {
    const err = mapUndiciError(undiciError("UND_ERR_HEADERS_TIMEOUT"));
    expect(err).toBeInstanceOf(UpstreamTimeoutError);
    expect(err.httpStatus).toBe(504);
  });

  test("bodyTimeoutMapsTo504UpstreamTimeout", () => {
    const err = mapUndiciError(undiciError("UND_ERR_BODY_TIMEOUT"));
    expect(err).toBeInstanceOf(UpstreamTimeoutError);
    expect(err.httpStatus).toBe(504);
  });

  test("connectionRefusedMapsTo502UpstreamConnect", () => {
    const err = mapUndiciError(undiciError("ECONNREFUSED", "connect ECONNREFUSED 127.0.0.1:1"));
    expect(err).toBeInstanceOf(UpstreamConnectError);
    expect(err.httpStatus).toBe(502);
  });

  test("nonErrorInputMapsTo502UpstreamConnect", () => {
    const err = mapUndiciError("socket hang up");
    expect(err).toBeInstanceOf(UpstreamConnectError);
    expect(err.httpStatus).toBe(502);
  });
});

describe("buildTargetUrl", () => {
  const UPSTREAM = "https://rpc.example.com/arbitrum_vrpc/APIKEY";

  test("rootPathForwardsUpstreamUrlUnchanged", () => {
    // No trailing slash appended — key-in-path upstreams stay verbatim.
    expect(buildTargetUrl(UPSTREAM, "/")).toBe(UPSTREAM);
  });

  test("clientPathAppendsToUpstreamBasePath", () => {
    expect(buildTargetUrl(UPSTREAM, "/foo/bar")).toBe(`${UPSTREAM}/foo/bar`);
  });

  test("upstreamTrailingSlashStrippedBeforeJoin", () => {
    expect(buildTargetUrl(`${UPSTREAM}/`, "/foo")).toBe(`${UPSTREAM}/foo`);
  });

  test("clientQueryIsCarriedOver", () => {
    expect(buildTargetUrl(UPSTREAM, "/foo?b=2")).toBe(`${UPSTREAM}/foo?b=2`);
  });

  test("upstreamQueryMergesBeforeClientQuery", () => {
    expect(buildTargetUrl("https://rpc.example.com/path?a=1", "/foo?b=2")).toBe(
      "https://rpc.example.com/path/foo?a=1&b=2",
    );
  });

  test("dotDotTraversalCannotEscapeBasePath", () => {
    // `..` segments resolve WITHIN the client path before the join, so the
    // result stays under the configured base path (WR-02).
    expect(buildTargetUrl(UPSTREAM, "/../../foo")).toBe(`${UPSTREAM}/foo`);
    expect(buildTargetUrl(UPSTREAM, "/a/../../b")).toBe(`${UPSTREAM}/b`);
  });

  test("percentEncodedDotSegmentsAreNormalizedToo", () => {
    expect(buildTargetUrl(UPSTREAM, "/%2e%2e/foo")).toBe(`${UPSTREAM}/foo`);
    expect(buildTargetUrl(UPSTREAM, "/%2E%2E/%2e/foo")).toBe(`${UPSTREAM}/foo`);
  });

  test("singleDotSegmentsAreCollapsed", () => {
    expect(buildTargetUrl(UPSTREAM, "/./foo/./bar")).toBe(`${UPSTREAM}/foo/bar`);
  });

  test("doubleSlashPrefixStaysAPathNotAnAuthority", () => {
    // `//evil.example/foo` as a request-target must not be re-parsed as a
    // protocol-relative URL whose host swallows the first path segment.
    expect(buildTargetUrl(UPSTREAM, "//evil.example/foo")).toBe(`${UPSTREAM}//evil.example/foo`);
  });

  test("traversalWithQueryStillContainedAndQueryPreserved", () => {
    expect(buildTargetUrl(UPSTREAM, "/../foo?x=1")).toBe(`${UPSTREAM}/foo?x=1`);
  });
});
