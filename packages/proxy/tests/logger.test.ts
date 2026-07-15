// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// createProxyLogger level gating: silent < error < debug, plus line format.

import { describe, expect, test } from "vitest";

import { createProxyLogger } from "../src/logger";

function capture(level: "silent" | "error" | "debug") {
  const lines: string[] = [];
  const log = createProxyLogger(level, (line) => lines.push(line));
  return { log, lines };
}

describe("createProxyLogger", () => {
  test("silentEmitsNothing", () => {
    const { log, lines } = capture("silent");
    log.error("proxy.error", { kind: "X" });
    log.debug("proxy.forward");
    expect(lines).toEqual([]);
  });

  test("errorLevelEmitsErrorNotDebug", () => {
    const { log, lines } = capture("error");
    log.debug("proxy.forward");
    log.error("proxy.error", { kind: "UnsignedUpstream", status: 502 });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe(
      '[vrpc-proxy] error proxy.error {"kind":"UnsignedUpstream","status":502}\n',
    );
  });

  test("debugLevelEmitsBoth", () => {
    const { log, lines } = capture("debug");
    log.error("proxy.error");
    log.debug("proxy.forward", { url: "/" });
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("[vrpc-proxy] error proxy.error\n");
    expect(lines[1]).toBe('[vrpc-proxy] debug proxy.forward {"url":"/"}\n');
  });

  test("throwingSinkNeverPropagates", () => {
    const log = createProxyLogger("error", () => {
      throw new Error("sink down");
    });
    expect(() => log.error("proxy.error")).not.toThrow();
  });
});
