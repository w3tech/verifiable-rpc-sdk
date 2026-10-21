// Confidential clients and node answers shared by the core suites.

import { hexToBytes } from "@noble/hashes/utils.js";
import {
  CHAIN_ID,
  type ConfidentialContext,
  KEY,
  mockHardwareVerifier,
  type TestOuterResponse,
} from "@w3tech.io/vrpc-test-support";
import sidecarVectors from "@w3tech.io/vrpc-test-support/vectors/sidecar-confidential.json";
import { ConfidentialClient, type ConfidentialClientOptions } from "../../src/confidential-client";
import type { ConfidentialTransport } from "../../src/transport";

export const BASE_URL = "https://rpc.example/eth_vrpc";
export const KEYED_URL = `${BASE_URL}/${KEY}`;

const utf8 = new TextEncoder();

export function optionsFor(
  transport: ConfidentialTransport,
  overrides: Partial<ConfidentialClientOptions> = {},
): ConfidentialClientOptions {
  return {
    url: KEYED_URL,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
    transport,
    ...overrides,
  };
}

export function clientFor(
  transport: ConfidentialTransport,
  overrides: Partial<ConfidentialClientOptions> = {},
): ConfidentialClient {
  return new ConfidentialClient(optionsFor(transport, overrides));
}

/** An unsealed answer; no content-type header without `contentType`. */
export function plain(
  status: number,
  contentType?: string,
  body: Uint8Array | string = new Uint8Array(0),
): TestOuterResponse {
  return {
    status,
    headers: contentType === undefined ? {} : { "content-type": contentType },
    body: typeof body === "string" ? utf8.encode(body) : body,
  };
}

interface PreDecapsulationError {
  name: string;
  status: number;
  content_type?: string;
  body: string;
}

export const preDecapsulationErrors = (
  sidecarVectors as { pre_decapsulation_errors: PreDecapsulationError[] }
).pre_decapsulation_errors;

/** The sidecar's answer for the pre-decapsulation error `name`. */
export function fromVector(name: string): TestOuterResponse {
  const entry = preDecapsulationErrors.find((candidate) => candidate.name === name);
  if (entry === undefined) throw new Error(`missing vector ${name}`);
  return plain(entry.status, entry.content_type, hexToBytes(entry.body));
}

/** A sealed answer carrying `body`, signed for the context's request. */
export function signed(context: ConfidentialContext, body: Uint8Array): TestOuterResponse {
  return {
    status: 200,
    headers: { "content-type": "message/ohttp-res", ...context.sign(body) },
    body,
  };
}
