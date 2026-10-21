// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The error a call is expected to throw, or a promise to reject with, and the text it carries.

export async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the promise to reject");
}

export function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected the call to throw");
}

const bigintSafe = (_key: string, value: unknown) =>
  typeof value === "bigint" ? value.toString() : value;

/** Message, string, stack and JSON form of `err` and of every cause below it. */
export function errorTexts(err: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<unknown>();
  let current = err;
  while (current !== undefined && current !== null && !seen.has(current)) {
    seen.add(current);
    if (current instanceof Error) out.push(current.message, String(current), current.stack ?? "");
    else out.push(String(current));
    try {
      out.push(JSON.stringify(current, bigintSafe) ?? "");
    } catch {
      out.push("unserialisable");
    }
    current = (current as { cause?: unknown }).cause;
  }
  return out;
}
