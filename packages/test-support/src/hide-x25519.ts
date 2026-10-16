// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Makes WebCrypto behave like a runtime without X25519 support.

type SubtleMethod = (this: SubtleCrypto, ...args: unknown[]) => Promise<unknown>;
type HiddenMethod = "generateKey" | "importKey" | "deriveBits";

const ALGORITHM_ARGUMENT: Record<HiddenMethod, number> = {
  generateKey: 0,
  importKey: 2,
  deriveBits: 0,
};

function algorithmName(algorithm: unknown): string | undefined {
  if (typeof algorithm === "string") return algorithm;
  if (typeof algorithm === "object" && algorithm !== null && "name" in algorithm) {
    return typeof algorithm.name === "string" ? algorithm.name : undefined;
  }
  return undefined;
}

export function hideX25519(): () => void {
  const prototype = SubtleCrypto.prototype as unknown as Record<HiddenMethod, SubtleMethod>;
  const saved: Record<HiddenMethod, SubtleMethod> = {
    generateKey: prototype.generateKey,
    importKey: prototype.importKey,
    deriveBits: prototype.deriveBits,
  };
  for (const method of Object.keys(ALGORITHM_ARGUMENT) as HiddenMethod[]) {
    const original = saved[method];
    const index = ALGORITHM_ARGUMENT[method];
    prototype[method] = function (this: SubtleCrypto, ...args: unknown[]) {
      if (algorithmName(args[index])?.toUpperCase() === "X25519") {
        return Promise.reject(new DOMException("Unrecognized algorithm name", "NotSupportedError"));
      }
      return original.apply(this, args);
    };
  }
  return () => {
    Object.assign(prototype, saved);
  };
}
