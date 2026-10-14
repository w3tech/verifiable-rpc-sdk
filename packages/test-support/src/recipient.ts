// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// In-test Oblivious HTTP recipient that answers like a node holding the Ed25519 seed.

import {
  Aes256Gcm,
  CipherSuite,
  HkdfSha256,
  DhkemX25519HkdfSha256 as NativeX25519,
} from "@hpke/core";
import { DhkemX25519HkdfSha256 as JsX25519 } from "@hpke/dhkem-x25519";
import { ed25519 } from "@noble/curves/ed25519.js";
import { extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { BHttpDecoder, BHttpEncoder } from "bhttp-ts";

const CONTRACT_HEADER = "00002000010002";
const HEADER_LENGTH = 7;
const ENC_LENGTH = 32;
const utf8 = new TextEncoder();
const EMPTY = new Uint8Array(0);

export interface OpenedRequest {
  hdr: Uint8Array;
  bhttp: Uint8Array;
  request: Request;
  sealResponse(innerBhttp: Uint8Array): Promise<Uint8Array>;
  respond(init: {
    status: number;
    headers?: Record<string, string>;
    body?: Uint8Array | string;
  }): Promise<Uint8Array>;
}

export interface Recipient {
  ed25519PublicKey: Uint8Array;
  openRequest(body: Uint8Array): Promise<OpenedRequest>;
}

export function x25519SecretFromSeed(seed: Uint8Array): Uint8Array {
  // toMontgomerySecret returns a 32-byte view over a 64-byte buffer.
  return ed25519.utils.toMontgomerySecret(seed).slice();
}

export function createRecipient(seed: Uint8Array, options?: { kem?: "native" | "js" }): Recipient {
  const suite = new CipherSuite({
    kem: options?.kem === "native" ? new NativeX25519() : new JsX25519(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const skR = x25519SecretFromSeed(seed);

  async function openRequest(body: Uint8Array): Promise<OpenedRequest> {
    const hdr = body.slice(0, HEADER_LENGTH);
    if (bytesToHex(hdr) !== CONTRACT_HEADER) throw new Error("unexpected request header");
    const enc = body.slice(HEADER_LENGTH, HEADER_LENGTH + ENC_LENGTH);
    const recipientKey = await suite.kem.importKey("raw", skR.slice().buffer, false);
    const info = concatBytes(utf8.encode("message/bhttp request"), new Uint8Array([0]), hdr);
    const context = await suite.createRecipientContext({ recipientKey, enc, info });
    const bhttp = new Uint8Array(
      await context.open(body.subarray(HEADER_LENGTH + ENC_LENGTH), EMPTY),
    );
    const request = new BHttpDecoder().decodeRequest(bhttp);

    async function sealResponse(innerBhttp: Uint8Array): Promise<Uint8Array> {
      const secret = new Uint8Array(
        await context.export(utf8.encode("message/bhttp response"), 32),
      );
      const responseNonce = crypto.getRandomValues(new Uint8Array(32));
      const prk = extract(sha256, secret, concatBytes(enc, responseNonce));
      const key = await suite.kdf.expand(prk, utf8.encode("key"), 32);
      const nonce = await suite.kdf.expand(prk, utf8.encode("nonce"), 12);
      const ct = await suite.aead.createEncryptionContext(key).seal(nonce, innerBhttp, EMPTY);
      return concatBytes(responseNonce, new Uint8Array(ct));
    }

    async function respond(init: {
      status: number;
      headers?: Record<string, string>;
      body?: Uint8Array | string;
    }): Promise<Uint8Array> {
      const responseInit: ResponseInit =
        init.headers === undefined
          ? { status: init.status }
          : { status: init.status, headers: init.headers };
      const inner = await new BHttpEncoder().encodeResponse(
        new Response(init.body ?? null, responseInit),
      );
      return sealResponse(inner);
    }

    return { hdr, bhttp, request, sealResponse, respond };
  }

  return { ed25519PublicKey: ed25519.getPublicKey(seed), openRequest };
}
