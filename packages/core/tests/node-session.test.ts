import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { x25519SecretFromSeed } from "@w3tech.io/vrpc-test-support";
import vector from "@w3tech.io/vrpc-test-support/vectors/ed25519-to-x25519.json";
import { describe, expect, test } from "vitest";
import type { AttestationFailed } from "../src/errors";
import { nodeKeyFromEd25519 } from "../src/node-session";

describe("nodeKeyFromEd25519", () => {
  test("converts the libsodium vector key", () => {
    const nodeKey = nodeKeyFromEd25519(hexToBytes(vector.ed25519PublicKey));
    expect(bytesToHex(nodeKey)).toBe(vector.x25519PublicKey);
  });

  test("the test recipient derives the matching X25519 secret from the seed", () => {
    const secret = x25519SecretFromSeed(hexToBytes(vector.seed));
    expect(bytesToHex(secret)).toBe(vector.x25519SecretKey);
    expect(bytesToHex(x25519.getPublicKey(secret))).toBe(vector.x25519PublicKey);
  });

  test.each(vector.reject)("rejects $name", ({ ed25519PublicKey }) => {
    let caught: unknown;
    try {
      nodeKeyFromEd25519(hexToBytes(ed25519PublicKey));
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ reason: "malformed" });
    const { message } = caught as AttestationFailed;
    expect(message).toContain("attested pubkey is not a usable encryption key");
    expect(message.toLowerCase()).not.toContain(ed25519PublicKey);
  });
});
