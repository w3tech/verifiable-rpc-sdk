// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Known-length BHTTP response (RFC 9292), status 200, as hex.

import { bytesToHex } from "@noble/hashes/utils.js";

const utf8 = new TextEncoder();

function vli(length: number): string {
  return length < 64 ? length.toString(16).padStart(2, "0") : (0x4000 | length).toString(16);
}

export function bhttpField(name: string, value: string): string {
  return (
    vli(name.length) +
    bytesToHex(utf8.encode(name)) +
    vli(value.length) +
    bytesToHex(utf8.encode(value))
  );
}

export function bhttpOkResponse(fields: string[], body: string): string {
  const section = fields.join("");
  const content = bytesToHex(utf8.encode(body));
  return `0140c8${vli(section.length / 2)}${section}${vli(content.length / 2)}${content}00`;
}
