// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Status, kind and executed for every confidential failure, and the JSON error body. Pure.

import {
  AttestationFailed,
  AttestationUnavailable,
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSignerMismatch,
  InternalError,
  InvalidInnerRequest,
  type InvalidInnerRequestReason,
  InvalidNonce,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnexpectedResponse,
  VrpcError,
} from "@w3tech.io/vrpc-core";
import { describe, expect, test } from "vitest";

import { describeConfidentialError } from "../src/confidential";
import {
  BodyTooLargeError,
  DecodeFailedError,
  errorResponseBody,
  UnsupportedMediaTypeError,
  UpstreamBodyTooLargeError,
  UpstreamConnectError,
  UpstreamTimeoutError,
} from "../src/errors";

function expectRow(
  err: unknown,
  status: number,
  kind: string,
  executed?: "no" | "unknown",
): ReturnType<typeof describeConfidentialError> {
  const result = describeConfidentialError(err);
  expect(result.status).toBe(status);
  expect(result.kind).toBe(kind);
  expect("executed" in result).toBe(err instanceof VrpcError);
  if (err instanceof VrpcError) expect(result.executed).toBe(err.executed);
  if (executed !== undefined) expect(result.executed).toBe(executed);
  return result;
}

describe("proxy-side rejections", () => {
  test("body over the limit is 413 BodyTooLarge", () => {
    expectRow(new BodyTooLargeError(10), 413, "BodyTooLarge");
  });

  test("unsupported media type is 415", () => {
    expectRow(new UnsupportedMediaTypeError("x"), 415, "UnsupportedMediaType");
  });

  test.each<InvalidInnerRequestReason>([
    "method",
    "path",
    "header",
    "content-type-required",
    "encode-failed",
  ])("InvalidInnerRequest %s is 400 executed no", (reason) => {
    const err = new InvalidInnerRequest(reason);
    err.executed = "no";
    const result = expectRow(err, 400, "InvalidInnerRequest", "no");
    expect(result.message).toBe(`Inner request rejected: ${reason}`);
  });
});

describe("AttestationUnavailable", () => {
  test.each<[string, AttestationUnavailable, number]>([
    ["status 429", new AttestationUnavailable("status", { status: 429 }), 429],
    ["timeout", new AttestationUnavailable("timeout"), 504],
    [
      "transport with an upstream timeout",
      new AttestationUnavailable("transport", { cause: new UpstreamTimeoutError("t") }),
      504,
    ],
    ["status 401", new AttestationUnavailable("status", { status: 401 }), 503],
    ["status 403", new AttestationUnavailable("status", { status: 403 }), 503],
    ["status 404", new AttestationUnavailable("status", { status: 404 }), 503],
    ["status 500", new AttestationUnavailable("status", { status: 500 }), 503],
    ["status 502", new AttestationUnavailable("status", { status: 502 }), 503],
    ["status 302", new AttestationUnavailable("status", { status: 302 }), 503],
    ["node-id-missing", new AttestationUnavailable("node-id-missing"), 503],
    [
      "transport with a connect failure",
      new AttestationUnavailable("transport", { cause: new UpstreamConnectError("c") }),
      503,
    ],
  ])("%s", (_name, err, status) => {
    err.executed = "no";
    expectRow(err, status, "AttestationUnavailable", "no");
  });
});

describe("RequestRejected", () => {
  test.each([
    [413, 413],
    [429, 429],
    [400, 502],
    [401, 502],
    [403, 502],
    [404, 502],
    [405, 502],
  ])("upstream %i is %i", (upstream, status) => {
    expectRow(new RequestRejected(upstream, "n"), status, "RequestRejected", "no");
  });
});

describe("UnexpectedResponse", () => {
  test.each([500, 502, 503, 302, 200, 0, 204])("upstream %i is 502 executed unknown", (s) => {
    expectRow(new UnexpectedResponse(s, "n"), 502, "UnexpectedResponse", "unknown");
  });
});

describe("TransportFailed", () => {
  test.each<[Error, number, string]>([
    [new UpstreamTimeoutError("timed out"), 504, "UpstreamTimeout"],
    [new UpstreamConnectError("refused"), 502, "UpstreamConnect"],
    [new UpstreamBodyTooLargeError(5), 502, "UpstreamBodyTooLarge"],
    [new DecodeFailedError("bad gzip"), 502, "DecodeFailed"],
  ])("cause %s renders as the cause, executed unknown", (cause, status, kind) => {
    const result = expectRow(
      new TransportFailed("network", "n", { cause }),
      status,
      kind,
      "unknown",
    );
    expect(result.message).toBe(cause.message);
  });

  test.each<[string, TransportFailed]>([
    ["too-large", new TransportFailed("too-large", "n")],
    ["foreign cause", new TransportFailed("network", "n", { cause: new Error("x") })],
  ])("%s is 502 TransportFailed executed unknown", (_name, err) => {
    expectRow(err, 502, "TransportFailed", "unknown");
  });
});

test.each([
  "no",
  "unknown",
] as const)("InternalError is 502 executed %s without its cause", (executed) => {
  const err = new InternalError({ cause: new Error("secret-detail") });
  err.executed = executed;
  const result = expectRow(err, 502, "InternalError", executed);
  expect(result.message).not.toContain("secret-detail");
});

describe("verification failures", () => {
  const sig = `0x${"ab".repeat(64)}`;
  const key = `0x${"cd".repeat(32)}`;
  test.each<[string, VrpcError]>([
    ["Attestation", new AttestationFailed("check", "detail", { chkId: "CHK-1" })],
    ["Attestation", new AttestationFailed("malformed", "r")],
    ["InvalidNonce", new InvalidNonce("r")],
  ])("%s before sending is 502 with its own kind, executed no", (kind, err) => {
    err.executed = "no";
    const result = expectRow(err, 502, kind, "no");
    expect(result.message).toBe(err.message);
  });

  test.each<[string, Error]>([
    ["ConfidentialSignerMismatch", new ConfidentialSignerMismatch(key, key)],
    [
      "BadSignature",
      new BadSignature({ signatureHex: sig, pubkeyHex: key, preImageSha256: new Uint8Array(32) }),
    ],
    [
      "StaleTimestamp",
      new StaleTimestamp({ observedMs: 1n, nowMs: 2n, skewMs: -1n, allowedWindowMs: 1 }),
    ],
    ["MissingHeader", new MissingHeader("vRPC-Signature")],
    ["MalformedHeader", new MalformedHeader("vRPC-Signature", "x", "r")],
    ["ConfidentialDecryptFailed", new ConfidentialDecryptFailed()],
    ["MalformedConfidentialResponse", new MalformedConfidentialResponse("framing")],
  ])("%s on the answer is 502 executed unknown", (kind, err) => {
    const result = expectRow(err, 502, kind, "unknown");
    expect(result.message).toBe(err.message);
  });
});

describe("anything else", () => {
  test.each<[string, unknown]>([
    ["Error", new Error("secret-detail")],
    ["TypeError", new TypeError("x")],
    ["string", "boom"],
    ["undefined", undefined],
  ])("%s is 502 Internal with a fixed message", (_name, err) => {
    const result = expectRow(err, 502, "Internal");
    expect(result.message).toBe("Internal proxy error");
  });
});

describe("errorResponseBody", () => {
  test("carries executed after the message when given", () => {
    const body = errorResponseBody("RequestRejected", "m", undefined, "no");
    expect(body).toBe('{"error":{"kind":"RequestRejected","message":"m","executed":"no"}}');
  });

  test("has neither executed nor traceId by default", () => {
    expect(JSON.parse(errorResponseBody("K", "m"))).toEqual({ error: { kind: "K", message: "m" } });
  });

  test("keeps the traceId", () => {
    expect(JSON.parse(errorResponseBody("K", "m", "t"))).toEqual({
      error: { kind: "K", message: "m", traceId: "t" },
    });
  });
});
