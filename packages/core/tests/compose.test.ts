import { describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  computeComposeHash,
  InfoEndpointComposeSource,
  RegistryComposeSource,
} from "../src/compose";
import { ComposeSourceNotImplemented, MalformedInfoResponse } from "../src/errors";
import { sha256 } from "../src/preimage";

const TEST_URL = "http://test.local:15269";

interface MockState {
  capturedUrl: string | undefined;
}

/** A `fetch` override that returns `body` as JSON and captures the requested URL. */
function mockInfoFetch(body: unknown): { state: MockState; fetch: typeof fetch } {
  const state: MockState = { capturedUrl: undefined };
  const fetchImpl = (async (input: string | URL | Request) => {
    state.capturedUrl = typeof input === "string" ? input : input.toString();
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { state, fetch: fetchImpl };
}

describe("computeComposeHash", () => {
  test("equals sha256(utf8) as bare lowercase hex", () => {
    const s = '{"manifest_version":2,"name":"demo"}';
    expect(computeComposeHash(s)).toBe(bytesToHex(sha256(new TextEncoder().encode(s))));
  });

  test("reproduces the dstack rule with no canonicalization (sha256 empty vector)", () => {
    expect(computeComposeHash("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("InfoEndpointComposeSource", () => {
  test("getAppCompose returns tcb_info.app_compose verbatim and hits /info", async () => {
    const appCompose = '{"manifest_version":2,"name":"demo"}';
    const { state, fetch } = mockInfoFetch({ tcb_info: { app_compose: appCompose } });
    const src = new InfoEndpointComposeSource(TEST_URL, { fetch });
    expect(await src.getAppCompose()).toBe(appCompose);
    expect(state.capturedUrl).toBe(`${TEST_URL}/info`);
  });

  test("getComposeHash equals computeComposeHash(appCompose)", async () => {
    const appCompose = '{"manifest_version":2,"name":"demo"}';
    const { fetch } = mockInfoFetch({ tcb_info: { app_compose: appCompose } });
    const src = new InfoEndpointComposeSource(TEST_URL, { fetch });
    expect(await src.getComposeHash()).toBe(computeComposeHash(appCompose));
  });

  test("rejects a non-http(s) url synchronously in the constructor", () => {
    expect(() => new InfoEndpointComposeSource("ftp://nope")).toThrow(TypeError);
  });

  test("throws MalformedInfoResponse when tcb_info is missing", async () => {
    const { fetch } = mockInfoFetch({ app_id: "abc" });
    const src = new InfoEndpointComposeSource(TEST_URL, { fetch });
    await expect(src.getAppCompose()).rejects.toBeInstanceOf(MalformedInfoResponse);
  });

  test("throws MalformedInfoResponse when app_compose is not a string", async () => {
    const { fetch } = mockInfoFetch({ tcb_info: { app_compose: 123 } });
    const src = new InfoEndpointComposeSource(TEST_URL, { fetch });
    await expect(src.getAppCompose()).rejects.toBeInstanceOf(MalformedInfoResponse);
  });
});

describe("RegistryComposeSource", () => {
  test("getAppCompose rejects with ComposeSourceNotImplemented (DEC-03)", async () => {
    const src = new RegistryComposeSource({ source: "github://w3tech/compose-registry" });
    await expect(src.getAppCompose()).rejects.toBeInstanceOf(ComposeSourceNotImplemented);
  });

  test("getComposeHash rejects with ComposeSourceNotImplemented (DEC-03)", async () => {
    const src = new RegistryComposeSource({ source: "github://w3tech/compose-registry" });
    await expect(src.getComposeHash()).rejects.toBeInstanceOf(ComposeSourceNotImplemented);
  });
});
