// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Known-length BHTTP response (RFC 9292), status 200, as hex.

import { bytesToHex } from "@noble/hashes/utils.js";

const utf8 = new TextEncoder();

function vli(length: number): string {
  return length < 64 ? length.toString(16).padStart(2, "0") : (0x4000 | length).toString(16);
}

function lengthPrefixed(text: string): string {
  const bytes = utf8.encode(text);
  return vli(bytes.length) + bytesToHex(bytes);
}

export function bhttpField(name: string, value: string): string {
  return lengthPrefixed(name) + lengthPrefixed(value);
}

export function bhttpOkResponse(fields: string[], body: string): string {
  const section = fields.join("");
  return `0140c8${vli(section.length / 2)}${section}${lengthPrefixed(body)}00`;
}
