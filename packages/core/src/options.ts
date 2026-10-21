// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// One synchronous check of client options, before any network or crypto; it throws only InvalidOption.

import { InvalidChainId, InvalidOption } from "./errors";
import { validateChainId } from "./preimage";
import { deriveVrpcUrls, type VrpcUrls } from "./vrpc-url";

/** Default pubkey-cache TTL: 1 hour in ms. */
export const DEFAULT_PUBKEY_CACHE_TTL_MS = 3_600_000;

export interface OptionsInput {
  url?: string | undefined;
  chainId?: string | number | bigint | undefined;
  headers?: Record<string, string> | undefined;
  replayWindowMs?: number | undefined;
  pubkeyCacheTtlMs?: number | undefined;
  confidential?: boolean | undefined;
}

export interface CheckedOptions<T extends OptionsInput = OptionsInput> {
  urls: T["url"] extends string ? VrpcUrls : VrpcUrls | undefined;
  /** Trimmed; a number or bigint becomes its decimal string. */
  chainId: T["chainId"] extends string | number | bigint ? string : string | undefined;
  replayWindowMs: number | undefined;
  pubkeyCacheTtlMs: number;
  confidential: boolean;
}

const MS_REASON = "must be a positive whole number of milliseconds";

/** Validates and normalizes client options; a bad or missing `required` one throws `InvalidOption`. */
export function checkOptions<T extends OptionsInput>(
  input: T,
  required?: readonly ("url" | "chainId")[],
): CheckedOptions<T>;
export function checkOptions(
  input: OptionsInput,
  required: readonly ("url" | "chainId")[] = [],
): CheckedOptions {
  for (const option of required) {
    if (input[option] === undefined) throw new InvalidOption(option, "is required");
  }
  let urls: VrpcUrls | undefined;
  if (input.url !== undefined) {
    try {
      urls = deriveVrpcUrls(input.url);
    } catch {
      throw new InvalidOption("url", "is not a valid URL");
    }
  }
  if (input.headers !== undefined) {
    try {
      new Headers(input.headers);
    } catch {
      throw new InvalidOption("headers", "is not a valid header set");
    }
  }
  if (input.replayWindowMs !== undefined && !isPositiveMs(input.replayWindowMs)) {
    throw new InvalidOption("replayWindowMs", MS_REASON);
  }
  const pubkeyCacheTtlMs = input.pubkeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS;
  if (!isPositiveMs(pubkeyCacheTtlMs)) throw new InvalidOption("pubkeyCacheTtlMs", MS_REASON);
  if (input.confidential !== undefined && typeof input.confidential !== "boolean") {
    throw new InvalidOption("confidential", "must be a boolean");
  }
  return {
    urls,
    chainId: input.chainId === undefined ? undefined : checkChainId(input.chainId),
    replayWindowMs: input.replayWindowMs,
    pubkeyCacheTtlMs,
    confidential: input.confidential ?? false,
  };
}

/** Confidential clients set their own content-type, so a caller's entry is dropped before the check. */
export function withoutContentType(headers: Record<string, string> = {}): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => name.toLowerCase() !== "content-type"),
  );
}

function isPositiveMs(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function checkChainId(chainId: string | number | bigint): string {
  if (typeof chainId !== "string" && typeof chainId !== "number" && typeof chainId !== "bigint") {
    throw new InvalidOption("chainId", "must be a string, number or bigint");
  }
  if (typeof chainId === "number" && !Number.isSafeInteger(chainId)) {
    throw new InvalidOption("chainId", "must be an integer");
  }
  try {
    return validateChainId(typeof chainId === "string" ? chainId : BigInt(chainId).toString(10));
  } catch (err) {
    // The InvalidChainId message quotes the whole id; only its reason is kept.
    if (err instanceof InvalidChainId) throw new InvalidOption("chainId", err.reason);
    throw err;
  }
}
