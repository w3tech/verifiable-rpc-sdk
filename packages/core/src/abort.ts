// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Settle a promise early when a signal aborts, with one abort listener per signal.

type Fail = (reason: unknown) => void;

interface Waiters {
  readonly fails: Set<Fail>;
  readonly onAbort: () => void;
}

const registry = new WeakMap<AbortSignal, Waiters>();

/** Calls `fail(signal.reason)` when `signal` aborts; returns the release. */
function subscribe(signal: AbortSignal, fail: Fail): () => void {
  let entry = registry.get(signal);
  if (entry === undefined) {
    const fails = new Set<Fail>();
    const onAbort = () => {
      registry.delete(signal);
      for (const waiter of fails) waiter(signal.reason);
    };
    entry = { fails, onAbort };
    registry.set(signal, entry);
    signal.addEventListener("abort", onAbort, { once: true });
  }
  const own = entry;
  own.fails.add(fail);
  return () => {
    own.fails.delete(fail);
    if (own.fails.size > 0 || registry.get(signal) !== own) return;
    registry.delete(signal);
    signal.removeEventListener("abort", own.onAbort);
  };
}

/** Settles like `promise`, or rejects with `signal.reason` first; never cancels `promise`. */
export function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) {
    promise.catch(() => {});
    return Promise.reject(signal.reason);
  }
  return new Promise<T>((resolve, reject) => {
    const release = subscribe(signal, reject);
    promise.then(
      (value) => {
        release();
        resolve(value);
      },
      (err: unknown) => {
        release();
        reject(err);
      },
    );
  });
}

/**
 * One signal per call that aborts with the caller's reason, or with a `TimeoutError` after
 * `timeoutMs` (none when `timeoutMs` is not positive); `done()` releases it. However many calls
 * share a caller signal, it holds one abort listener.
 */
export function linkSignal(
  caller: AbortSignal | undefined,
  timeoutMs: number,
): { signal: AbortSignal | undefined; done(): void } {
  if (caller === undefined) {
    return { signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined, done() {} };
  }
  const controller = new AbortController();
  if (caller.aborted) {
    controller.abort(caller.reason);
    return { signal: controller.signal, done() {} };
  }
  const release = subscribe(caller, (reason) => controller.abort(reason));
  const timer =
    timeoutMs > 0
      ? setTimeout(
          () => controller.abort(new DOMException("The operation timed out.", "TimeoutError")),
          timeoutMs,
        )
      : undefined;
  return {
    signal: controller.signal,
    done() {
      clearTimeout(timer);
      release();
    },
  };
}
