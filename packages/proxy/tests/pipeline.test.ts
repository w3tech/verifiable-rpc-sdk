// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Unit tests for the pipeline's pure helpers: the undici error → transport
// taxonomy map. No network, no server.

import { describe, expect, test } from "vitest";

import { UpstreamConnectError, UpstreamTimeoutError } from "../src/errors";
import { mapUndiciError } from "../src/pipeline";

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
