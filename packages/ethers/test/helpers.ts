// Test helper: inject a synthetic ethers `FetchResponse` into a `FetchRequest`
// without touching the network. Plan 30-02's `provider.test.ts` feeds the
// signed fixtures from `fixtures.ts` through `VrpcProvider._send` via this seam.

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
