// Test helper: inject a synthetic ethers `FetchResponse` into a `FetchRequest`
// without touching the network. Plan 30-02's `provider.test.ts` feeds the
// signed fixtures from `fixtures.ts` through `VrpcProvider._send` via this seam.

import { FetchRequest } from "ethers";

import { type SignFixtureOptions, signResponseBytes } from "./fixtures";

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
