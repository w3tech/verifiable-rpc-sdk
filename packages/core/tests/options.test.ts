import { thrownBy } from "@w3tech.io/vrpc-test-support";
import { describe, expect, test } from "vitest";

import { type InvalidChainId, InvalidOption, type OptionName, VrpcError } from "../src/errors";
import { checkOptions, DEFAULT_PUBKEY_CACHE_TTL_MS, type OptionsInput } from "../src/options";
import { validateChainId } from "../src/preimage";

const MS = "must be a positive whole number of milliseconds";

const chainIdReason = (chainId: string) =>
  (thrownBy(() => validateChainId(chainId)) as InvalidChainId).reason;

type Bad = [string, OptionsInput, OptionName, string];

const badOptions: Bad[] = [
  ["url", { url: "::not a url SECRETKEY42" }, "url", "is not a valid URL"],
  ...[{ "x-api-key": "bad\nSECRETKEY42" }, { "bad key": "SECRETKEY42" }].map(
    (headers): Bad => ["headers", { headers }, "headers", "is not a valid header set"],
  ),
  ...["", " ", "7".repeat(65), "arbitruméone"].map(
    (chainId): Bad => [`chain id ${chainId}`, { chainId }, "chainId", chainIdReason(chainId)],
  ),
  ...[1.5, 2 ** 53].map(
    (chainId): Bad => [`chain id ${chainId}`, { chainId }, "chainId", "must be an integer"],
  ),
  ...[true, null, {}].map(
    (chainId): Bad => [
      `chain id ${JSON.stringify(chainId)}`,
      { chainId: chainId as never },
      "chainId",
      "must be a string, number or bigint",
    ],
  ),
  ...(["replayWindowMs", "pubkeyCacheTtlMs"] as const).flatMap((option) =>
    [0, -1, 1.5, Number.NaN, Infinity].map(
      (value): Bad => [`${option} ${value}`, { [option]: value }, option, MS],
    ),
  ),
  ["confidential", { confidential: "yes" as never }, "confidential", "must be a boolean"],
];

describe("checkOptions", () => {
  test.each(badOptions)(
    "a bad %s is InvalidOption without the value",
    (_, input, option, reason) => {
      const err = thrownBy(() => checkOptions(input));
      expect(err).toBeInstanceOf(InvalidOption);
      expect(err).toBeInstanceOf(VrpcError);
      expect(err).toMatchObject({ option, reason, executed: "no" });
      expect("cause" in (err as object)).toBe(false);
      const text = `${String(err)} ${JSON.stringify(err)}`;
      expect(text).not.toContain("SECRETKEY42");
      if (typeof input.chainId === "string" && input.chainId.length > 1) {
        expect(text).not.toContain(input.chainId);
      }
    },
  );

  test.each(["url", "chainId"] as const)(
    "a missing %s is InvalidOption when required",
    (option) => {
      const input = { url: "https://rpc.example/eth_vrpc", chainId: "1", [option]: undefined };
      const err = thrownBy(() => checkOptions(input, ["url", "chainId"]));
      expect(err).toMatchObject({ option, reason: "is required", executed: "no" });
      expect(() => checkOptions(input)).not.toThrow();
    },
  );

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
