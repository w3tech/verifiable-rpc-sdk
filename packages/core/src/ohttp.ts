// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Oblivious HTTP (RFC 9458) request encapsulation and response decapsulation over HPKE.

import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  HkdfSha256,
  DhkemX25519HkdfSha256 as NativeX25519,
  type SenderContext,
  type SenderContextParams,
} from "@hpke/core";
import { DhkemX25519HkdfSha256 as JsX25519 } from "@hpke/dhkem-x25519";
import { extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { InvalidNodeKey } from "./node-key";

export type KemChoice = "native" | "js";

export const CONTRACT_KEY_ID = 0x00;

const utf8 = new TextEncoder();
const EMPTY = new Uint8Array(0);
const REQUEST_LABEL = utf8.encode("message/bhttp request");
const RESPONSE_LABEL = utf8.encode("message/bhttp response");
const KEY_LABEL = utf8.encode("key");
const NONCE_LABEL = utf8.encode("nonce");

export type OhttpErrorReason = "seal-failed" | "response-too-short" | "open-failed";

export class OhttpError extends Error {
  readonly kind = "OhttpError" as const;

  constructor(
    readonly reason: OhttpErrorReason,
    options?: { cause?: unknown },
  ) {
    super(`Confidential message processing failed: ${reason}`, options);
    this.name = "OhttpError";
  }
}

export interface ResponseOpener {
  readonly suite: CipherSuite;
  readonly context: SenderContext;
  readonly enc: Uint8Array;
}

export interface SealedRequest {
  readonly body: Uint8Array;
  readonly opener: ResponseOpener;
}

export function createSuite(kem: KemChoice, aeadId: 0x0001 | 0x0002 = 0x0002): CipherSuite {
  return new CipherSuite({
    kem: kem === "native" ? new NativeX25519() : new JsX25519(),
    kdf: new HkdfSha256(),
    aead: aeadId === 0x0001 ? new Aes128Gcm() : new Aes256Gcm(),
  });
}

// CFRG HPKE test vector for this suite (mode 0): the native KEM must open its first encryption.
const PROBE_IKM_R = "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee";
const PROBE_ENC = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";
const PROBE_INFO = "4f6465206f6e2061204772656369616e2055726e";
const PROBE_CT =
  "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a";
const PROBE_AAD = "436f756e742d30";
const PROBE_PT = "4265617574792069732074727574682c20747275746820626561757479";

export async function nativeX25519Works(): Promise<boolean> {
  try {
    const suite = createSuite("native");
    await suite.kem.generateKeyPair();
    const recipientKey = await suite.kem.deriveKeyPair(hexToBytes(PROBE_IKM_R));
    const context = await suite.createRecipientContext({
      recipientKey,
      enc: hexToBytes(PROBE_ENC),
      info: hexToBytes(PROBE_INFO),
    });
    const pt = await context.open(hexToBytes(PROBE_CT), hexToBytes(PROBE_AAD));
    return bytesToHex(new Uint8Array(pt)) === PROBE_PT;
  } catch {
    return false;
  }
}

export async function selectKem(): Promise<KemChoice> {
  const node = (globalThis as { process?: { versions?: { node?: unknown } } }).process?.versions
    ?.node;
  // Node 20.19.0-20.19.2 print an ExperimentalWarning on the first WebCrypto X25519 use.
  if (typeof node === "string" && Number.parseInt(node, 10) < 22) return "js";
  return (await nativeX25519Works()) ? "native" : "js";
}

let contractSuitePromise: Promise<CipherSuite> | undefined;

export function contractSuite(): Promise<CipherSuite> {
  contractSuitePromise ??= selectKem().then((kem) => createSuite(kem));
  return contractSuitePromise;
}

function u16(value: number): [number, number] {
  return [(value >> 8) & 0xff, value & 0xff];
}

export async function seal(
  suite: CipherSuite,
  keyId: number,
  nodeKey: Uint8Array,
  bhttpRequest: Uint8Array,
  ekm?: SenderContextParams["ekm"],
): Promise<SealedRequest> {
  const header = new Uint8Array([
    keyId,
    ...u16(suite.kem.id),
    ...u16(suite.kdf.id),
    ...u16(suite.aead.id),
  ]);
  const info = concatBytes(REQUEST_LABEL, new Uint8Array([0]), header);

  let recipientPublicKey: CryptoKey;
  try {
    recipientPublicKey = await suite.kem.deserializePublicKey(nodeKey);
  } catch (cause) {
    throw new InvalidNodeKey("malformed", { cause });
  }

  let context: SenderContext;
  try {
    const params: SenderContextParams = { recipientPublicKey, info };
    if (ekm !== undefined) params.ekm = ekm;
    context = await suite.createSenderContext(params);
  } catch (cause) {
    throw new InvalidNodeKey("encap-failed", { cause });
  }

  let ct: Uint8Array;
  try {
    ct = new Uint8Array(await context.seal(bhttpRequest, EMPTY));
  } catch (cause) {
    throw new OhttpError("seal-failed", { cause });
  }
  const enc = new Uint8Array(context.enc);
  return { body: concatBytes(header, enc, ct), opener: { suite, context, enc } };
}

export async function sealRequest(
  nodeKey: Uint8Array,
  bhttpRequest: Uint8Array,
): Promise<SealedRequest> {
  return seal(await contractSuite(), CONTRACT_KEY_ID, nodeKey, bhttpRequest);
}

export async function openResponse(opener: ResponseOpener, body: Uint8Array): Promise<Uint8Array> {
  const { suite, context, enc } = opener;
  const nk = suite.aead.keySize;
  const nn = suite.aead.nonceSize;
  const nonceLength = Math.max(nk, nn);
  if (body.length < nonceLength + suite.aead.tagSize) throw new OhttpError("response-too-short");
  try {
    const secret = new Uint8Array(await context.export(RESPONSE_LABEL, nonceLength));
    // noble's argument order is (hash, ikm, salt), not the RFC's Extract(salt, ikm).
    const prk = extract(sha256, secret, concatBytes(enc, body.subarray(0, nonceLength)));
    const key = await suite.kdf.expand(prk, KEY_LABEL, nk);
    const nonce = await suite.kdf.expand(prk, NONCE_LABEL, nn);
    const plaintext = await suite.aead
      .createEncryptionContext(key)
      .open(nonce, body.subarray(nonceLength), EMPTY);
    return new Uint8Array(plaintext);
  } catch (cause) {
    throw new OhttpError("open-failed", { cause });
  }
}
