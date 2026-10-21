// Test helper: inject a synthetic ethers `FetchResponse` into a `FetchRequest`
// without touching the network. `provider.test.ts` feeds the
// signed fixtures from `fixtures.ts` through `VrpcProvider._send` via this seam.

import { CHAIN_ID, signedJsonHeaders } from "@w3tech.io/vrpc-test-support";
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
 * Options for {@link signingRequest}.
 */
export interface SigningRequestOptions {
  /** Chain id the response is signed for. Defaults to `CHAIN_ID`. */
  signingChainId?: string;
  nodeId?: string;
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
  /** HTTP status of the answer. Defaults to 200. */
  status?: number;
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
  opts: SigningRequestOptions = {},
): FetchRequest {
  const req = new FetchRequest("http://test.invalid");
  req.getUrlFunc = async (sentReq) => {
    // The exact bytes ethers serialized and POSTed (JSON.stringify(payload)).
    const requestBytes = sentReq.body ?? new Uint8Array();
    const responseBytes = new TextEncoder().encode(
      typeof responseBody === "string"
        ? responseBody
        : responseBody((JSON.parse(new TextDecoder().decode(requestBytes)) as { id: number }).id),
    );
    const headers = opts.unsigned
      ? { "content-type": "application/json" }
      : signedJsonHeaders(opts.signingChainId ?? CHAIN_ID, requestBytes, responseBytes, {
          nodeId: opts.nodeId,
        });
    const body = opts.tamper ? flipFirstDigit(responseBytes) : responseBytes;
    return { statusCode: opts.status ?? 200, statusMessage: "", headers, body };
  };
  return req;
}

/**
 * Return a copy of `bytes` with ONE digit byte mutated, so a body tampered AFTER
 * signing differs (→ BadSignature) while it stays valid UTF-8/JSON. Flips the
 * first ASCII digit (0x30-0x39) found, mapping it to a different digit.
 */
export function flipFirstDigit(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes);
  for (const [i, b] of out.entries()) {
    if (b >= 0x30 && b <= 0x39) {
      out[i] = b === 0x39 ? 0x30 : b + 1;
      break;
    }
  }
  return out;
}
