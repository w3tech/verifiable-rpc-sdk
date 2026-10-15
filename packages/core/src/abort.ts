// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Settle a promise early when a signal aborts, with one abort listener per signal.

type Fail = (reason: unknown) => void;

const waiters = new WeakMap<AbortSignal, Set<Fail>>();
const handlers = new WeakMap<AbortSignal, () => void>();

function register(signal: AbortSignal): Set<Fail> {
  const existing = waiters.get(signal);
  if (existing !== undefined) return existing;
  const fresh = new Set<Fail>();
  const onAbort = () => {
    waiters.delete(signal);
    handlers.delete(signal);
    for (const fail of fresh) fail(signal.reason);
  };
  waiters.set(signal, fresh);
  handlers.set(signal, onAbort);
  signal.addEventListener("abort", onAbort, { once: true });
  return fresh;
}

function release(signal: AbortSignal, entry: Set<Fail>, fail: Fail): void {
  entry.delete(fail);
  if (entry.size > 0 || waiters.get(signal) !== entry) return;
  waiters.delete(signal);
  const onAbort = handlers.get(signal);
  handlers.delete(signal);
  if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
}

/** Settles like `promise`, or rejects with `signal.reason` first; never cancels `promise`. */
export function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) {
    promise.catch(() => {});
    return Promise.reject(signal.reason);
  }
  return new Promise<T>((resolve, reject) => {
    const entry = register(signal);
    entry.add(reject);
    promise.then(
      (value) => {
        release(signal, entry, reject);
        resolve(value);
      },
      (err: unknown) => {
        release(signal, entry, reject);
        reject(err);
      },
    );
  });
}
