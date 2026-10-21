// Test helper: inject a synthetic ethers `FetchResponse` into a `FetchRequest`
// without touching the network. `provider.test.ts` feeds the
// signed fixtures from `fixtures.ts` through `VrpcProvider._send` via this seam.

import { type SignedAnswerOptions, signedAnswer } from "@w3tech.io/vrpc-test-support";
import { FetchRequest } from "ethers";

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
 * Build a `FetchRequest` whose `getUrlFunc` signs the chosen `responseBody` over
 * the EXACT request bytes ethers POSTs (`req.body`), then returns the signed
 * response. This is the request-aware seam the adapter uses so a real
 * `getBalance` / Contract payload verifies through `VrpcProvider._send` without
 * the test predicting ethers' internal payload bytes (key order, id counter,
 * resolved blockTag). This suite asserts adapter WIRING, not pre-image bytes.
 *
 * A function `responseBody` gets the request id, so repeated calls answer their own id.
 * `tamper` flips a response byte AFTER signing → `BadSignature`. `unsigned`
 * strips the `vRPC-*` triple → `MissingHeader`. `signingChainId` forges a valid
 * signature bound to a different chain → `BadSignature` when verified against
 * the provider's chainId.
 */
export function signingRequest(
  responseBody: string | ((id: number) => string),
  opts: SignedAnswerOptions = {},
): FetchRequest {
  const req = new FetchRequest("http://test.invalid");
  req.getUrlFunc = async (sentReq) => {
    // The exact bytes ethers serialized and POSTed (JSON.stringify(payload)).
    const requestBytes = sentReq.body ?? new Uint8Array();
    const answer = signedAnswer(
      requestBytes,
      typeof responseBody === "string"
        ? responseBody
        : responseBody((JSON.parse(new TextDecoder().decode(requestBytes)) as { id: number }).id),
      opts,
    );
    return {
      statusCode: answer.status,
      statusMessage: "",
      headers: answer.headers,
      body: answer.body,
    };
  };
  return req;
}
