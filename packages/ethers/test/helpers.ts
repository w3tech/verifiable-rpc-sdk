// Test helper: inject a synthetic ethers `FetchResponse` into a `FetchRequest`
// without touching the network. Plan 30-02's `provider.test.ts` feeds the
// signed fixtures from `fixtures.ts` through `VrpcProvider._send` via this seam.

import { getPublicKeyAsync } from "@noble/ed25519";
import { FetchRequest } from "ethers";

import { type SignFixtureOptions, signResponseBytes, TEST_SEED } from "./fixtures";

/**
 * Build a `FetchRequest` that resolves to a synthetic response carrying the
 * given body + headers, with no live network.
 *
 * Injection seam: `FetchRequest.getUrlFunc` (the documented network-override
 * setter, see `ethers.js/src.ts/utils/fetch.ts` — `FetchGetUrlFunc` returns
 * `{ statusCode, statusMessage, headers, body }`). The override is set
 * per-instance, so it does NOT leak into the global `defaultGetUrlFunc` the way
 * `FetchRequest.registerGetUrl` would.
 */
export function fixtureRequest(
  body: Uint8Array,
  headers: Record<string, string>,
  status = 200,
): FetchRequest {
  const req = new FetchRequest("http://test.invalid");
  req.getUrlFunc = async () => ({
    statusCode: status,
    statusMessage: status === 200 ? "OK" : "ERROR",
    headers,
    body,
  });
  return req;
}

/**
 * Options for {@link signingRequest}.
 */
export interface SigningRequestOptions extends SignFixtureOptions {
  /**
   * If true, emit ONLY `content-type` (no `vRPC-*` triple) — drives the
   * strict-mode `MissingHeader` fail-closed path.
   */
  unsigned?: boolean;
  /**
   * If true, flip a byte of the signed response body so the signature no longer
   * matches — drives `BadSignature`.
   */
  tamper?: boolean;
}

/**
 * Build a `FetchRequest` whose `getUrlFunc` signs the chosen `responseBody` over
 * the EXACT request bytes ethers POSTs (`req.body`), then returns the signed
 * response. This is the request-aware seam Plan 30-02 uses so a real
 * `getBalance` / Contract payload verifies through `VrpcProvider._send` without
 * the test predicting ethers' internal payload bytes (key order, id counter,
 * resolved blockTag). TEST-02 asserts adapter WIRING, not pre-image bytes.
 *
 * `tamper` flips a response byte AFTER signing → `BadSignature`. `unsigned`
 * strips the `vRPC-*` triple → `MissingHeader`. `signingChainId` (via
 * SigningRequestOptions) forges a valid signature bound to a different chain →
 * `BadSignature` when verified against the provider's chainId.
 */
export function signingRequest(
  responseBody: string,
  opts: SigningRequestOptions = {},
): FetchRequest {
  const req = new FetchRequest("http://test.invalid");
  const responseBytes = new TextEncoder().encode(responseBody);
  req.getUrlFunc = async (sentReq) => {
    // The exact bytes ethers serialized and POSTed (JSON.stringify(payload)).
    const requestBytes = sentReq.body ?? new Uint8Array();
    const headers = opts.unsigned
      ? { "content-type": "application/json" }
      : await signResponseBytes(requestBytes, responseBytes, opts);
    let body = responseBytes;
    if (opts.tamper) {
      body = new Uint8Array(responseBytes);
      // Mutate ONE digit byte AFTER signing so the bytes differ (→ BadSignature)
      // while the body stays valid UTF-8/JSON. Flip the first ASCII digit
      // (0x30-0x39) found, mapping it to a different digit.
      for (let i = 0; i < body.length; i++) {
        if (body[i] >= 0x30 && body[i] <= 0x39) {
          body[i] = body[i] === 0x39 ? 0x30 : body[i] + 1;
          break;
        }
      }
    }
    return { statusCode: 200, statusMessage: "OK", headers, body };
  };
  return req;
}

/** Local lowercase-hex encode (no `0x` prefix). */
function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Mutable state returned by {@link installAttestationMock}. */
export interface AttMockState {
  /** `fetch` override to pass as the provider's `fetch` option (attestation leg). */
  fetch: typeof fetch;
  /** Count of `/attestation` GETs served (cache / fail-closed assertions). */
  attGetCount: number;
}

/**
 * Mock ONLY the attestation GET leg (the always-on verify seam fetches it on the
 * FIRST read per pubkey). The returned `pubkey` is derived from the SAME
 * TEST_SEED the RPC responses are signed with, so the seam's pubkey correlation
 * passes; the v5.0 mock verifier (allowInsecureMock) then resolves.
 *
 * `requireNodeId` mimics a shark route that can only resolve WITH a `node_id`
 * query param: a fetch lacking `node_id` returns 404 → the seam fails closed
 * (exercises the no-node_id path). Counts how many times `/attestation` is hit.
 */
export function installAttestationMock(opts: { requireNodeId?: boolean } = {}): AttMockState {
  const state: AttMockState = { fetch: (() => {}) as unknown as typeof fetch, attGetCount: 0 };
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/attestation")) {
      state.attGetCount += 1;
      // Shark-style routing: without a node_id the route cannot resolve → 404,
      // which fetchAttestation maps to AttestationNodeNotFoundError (fail-closed).
      if (opts.requireNodeId === true && !url.includes("node_id=")) {
        return new Response("not found", { status: 404 });
      }
      const attPubkey = await getPublicKeyAsync(TEST_SEED);
      const body = {
        quote: { quote: "00", event_log: "00", report_data: "00", vm_config: "" },
        pubkey: `0x${toHex(attPubkey)}`,
        composeHash: "deadbeef",
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
  state.fetch = impl as typeof fetch;
  return state;
}
