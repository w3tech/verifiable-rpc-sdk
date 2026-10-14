import { x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vitest";
import { x25519SecretFromSeed } from "../../test-support/src/index";
import vector from "../../test-support/vectors/ed25519-to-x25519.json";
import { InvalidNodeKey, nodeKeyFromEd25519 } from "../src/node-key";

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

  test.each(vector.reject)("rejects $name as $reason", ({ ed25519PublicKey, reason }) => {
    let caught: unknown;
    try {
      nodeKeyFromEd25519(hexToBytes(ed25519PublicKey));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(InvalidNodeKey);
    const error = caught as InvalidNodeKey;
    expect(error.kind).toBe("InvalidNodeKey");
    expect(error.reason).toBe(reason);
    expect(error.message.toLowerCase()).not.toContain(ed25519PublicKey);
  });
});
