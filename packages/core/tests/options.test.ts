import { describe, expect, test } from "vitest";

import { type InvalidChainId, InvalidOption, type OptionName, VrpcError } from "../src/errors";
import { checkOptions, DEFAULT_PUBKEY_CACHE_TTL_MS, type OptionsInput } from "../src/options";
import { validateChainId } from "../src/preimage";

const MS = "must be a positive whole number of milliseconds";

function thrown(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}

const chainIdReason = (chainId: string) =>
  (thrown(() => validateChainId(chainId)) as InvalidChainId).reason;

describe("checkOptions", () => {
  test.each<[string, OptionsInput, OptionName, string]>([
    ["url", { url: "::not a url SECRETKEY42" }, "url", "is not a valid URL"],
    [
      "header",
      { headers: { "x-api-key": "bad\nSECRETKEY42" } },
      "headers",
      "is not a valid header set",
    ],
    [
      "header name",
      { headers: { "bad key": "SECRETKEY42" } },
      "headers",
      "is not a valid header set",
    ],
    ["empty chain id", { chainId: "" }, "chainId", chainIdReason("")],
    ["blank chain id", { chainId: " " }, "chainId", chainIdReason(" ")],
    ["long chain id", { chainId: "7".repeat(65) }, "chainId", chainIdReason("7".repeat(65))],
    ["non-ASCII chain id", { chainId: "arbitruméone" }, "chainId", chainIdReason("arbitruméone")],
    ["fractional chain id", { chainId: 1.5 }, "chainId", "must be an integer"],
    ["unsafe chain id", { chainId: 2 ** 53 }, "chainId", "must be an integer"],
    ["replayWindowMs 0", { replayWindowMs: 0 }, "replayWindowMs", MS],
    ["replayWindowMs -1", { replayWindowMs: -1 }, "replayWindowMs", MS],
    ["replayWindowMs 1.5", { replayWindowMs: 1.5 }, "replayWindowMs", MS],
    ["replayWindowMs NaN", { replayWindowMs: Number.NaN }, "replayWindowMs", MS],
    ["replayWindowMs Infinity", { replayWindowMs: Infinity }, "replayWindowMs", MS],
    ["TTL 0", { pubkeyCacheTtlMs: 0 }, "pubkeyCacheTtlMs", MS],
    ["TTL -1", { pubkeyCacheTtlMs: -1 }, "pubkeyCacheTtlMs", MS],
    ["TTL 1.5", { pubkeyCacheTtlMs: 1.5 }, "pubkeyCacheTtlMs", MS],
    ["TTL NaN", { pubkeyCacheTtlMs: Number.NaN }, "pubkeyCacheTtlMs", MS],
    ["TTL Infinity", { pubkeyCacheTtlMs: Infinity }, "pubkeyCacheTtlMs", MS],
    [
      "confidential",
      { confidential: "yes" as unknown as boolean },
      "confidential",
      "must be a boolean",
    ],
  ])("a bad %s is InvalidOption without the value", (_, input, option, reason) => {
    const err = thrown(() => checkOptions(input));
    expect(err).toBeInstanceOf(InvalidOption);
    expect(err).toBeInstanceOf(VrpcError);
    expect(err).toMatchObject({ option, reason, executed: "no" });
    expect("cause" in (err as object)).toBe(false);
    const text = `${String(err)} ${JSON.stringify(err)}`;
    expect(text).not.toContain("SECRETKEY42");
    if (typeof input.chainId === "string" && input.chainId.length > 1) {
      expect(text).not.toContain(input.chainId);
    }
  });

  test.each<[OptionsInput["chainId"], string]>([
    [" 42161 ", "42161"],
    [42161, "42161"],
    [42161n, "42161"],
    ["-239", "-239"],
  ])("chain id %o becomes %s", (chainId, expected) => {
    expect(checkOptions({ chainId }).chainId).toBe(expected);
  });

  test("normalizes the rest and applies defaults", () => {
    expect(checkOptions({})).toEqual({
      urls: undefined,
      chainId: undefined,
      replayWindowMs: undefined,
      pubkeyCacheTtlMs: DEFAULT_PUBKEY_CACHE_TTL_MS,
      confidential: false,
    });
    expect(
      checkOptions({
        url: "https://rpc.ankr.com/arbitrum_vrpc/",
        headers: { "x-api-key": "k" },
        replayWindowMs: Number.MAX_SAFE_INTEGER,
        pubkeyCacheTtlMs: 1,
        confidential: true,
      }),
    ).toEqual({
      urls: {
        rpcUrl: "https://rpc.ankr.com/arbitrum_vrpc",
        attestationUrl: "https://rpc.ankr.com/arbitrum_vrpc/attestation",
        confidentialUrl: "https://rpc.ankr.com/arbitrum_vrpc/confidential",
      },
      chainId: undefined,
      replayWindowMs: Number.MAX_SAFE_INTEGER,
      pubkeyCacheTtlMs: 1,
      confidential: true,
    });
    expect(DEFAULT_PUBKEY_CACHE_TTL_MS).toBe(3_600_000);
  });
});
