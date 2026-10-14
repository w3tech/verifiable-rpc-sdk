import type { CipherSuite } from "@hpke/core";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, test } from "vitest";
import { hideX25519 } from "../../test-support/src/index";
import vector from "../../test-support/vectors/hpke-cfrg-mode0-x25519-sha256-aes256gcm.json";
import { createSuite, type KemChoice, nativeX25519Works, selectKem } from "../src/ohttp";

const KEMS: readonly KemChoice[] = ["js", "native"];

interface SenderOutput {
  enc: string;
  ciphertexts: string[];
  exports: string[];
}

async function runSender(suite: CipherSuite): Promise<SenderOutput> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(hexToBytes(vector.pkRm));
  const context = await suite.createSenderContext({
    recipientPublicKey,
    info: hexToBytes(vector.info),
    ekm: hexToBytes(vector.ikmE),
  });
  const ciphertexts: string[] = [];
  for (const encryption of vector.encryptions) {
    const ct = await context.seal(hexToBytes(encryption.pt), hexToBytes(encryption.aad));
    ciphertexts.push(bytesToHex(new Uint8Array(ct)));
  }
  const exports: string[] = [];
  for (const entry of vector.exports) {
    const value = await context.export(hexToBytes(entry.exporter_context), entry.L);
    exports.push(bytesToHex(new Uint8Array(value)));
  }
  return { enc: bytesToHex(new Uint8Array(context.enc)), ciphertexts, exports };
}

function expectVector(output: SenderOutput): void {
  expect(output.enc).toBe(vector.enc);
  expect(output.ciphertexts).toEqual(vector.encryptions.map((encryption) => encryption.ct));
  expect(output.exports).toEqual(vector.exports.map((entry) => entry.exported_value));
}

describe("KEM selection", () => {
  test("is silent and picks native X25519 only from Node 22", async () => {
    const warnings: Error[] = [];
    const onWarning = (warning: Error) => warnings.push(warning);
    process.on("warning", onWarning);
    try {
      const kem = await selectKem();
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(warnings).toEqual([]);
      const major = Number.parseInt(process.versions.node, 10);
      expect(kem).toBe(major < 22 ? "js" : "native");
    } finally {
      process.off("warning", onWarning);
    }
  });
});

describe.each(KEMS)("CFRG HPKE vector with the %s KEM", (kem) => {
  test("the sender reproduces enc, both ciphertexts and all exports", async () => {
    expectVector(await runSender(createSuite(kem)));
  });

  test("a recipient derived from ikmR opens the first encryption", async () => {
    const suite = createSuite(kem);
    const recipientKey = await suite.kem.deriveKeyPair(hexToBytes(vector.ikmR));
    const context = await suite.createRecipientContext({
      recipientKey,
      enc: hexToBytes(vector.enc),
      info: hexToBytes(vector.info),
    });
    const [first] = vector.encryptions;
    if (first === undefined) throw new Error("vector has no encryptions");
    const pt = await context.open(hexToBytes(first.ct), hexToBytes(first.aad));
    expect(bytesToHex(new Uint8Array(pt))).toBe(first.pt);
  });
});

test("the JS and native KEMs produce identical bytes", async () => {
  const js = await runSender(createSuite("js"));
  const native = await runSender(createSuite("native"));
  expect(native).toEqual(js);
});

describe("without WebCrypto X25519", () => {
  let restore: (() => void) | undefined;

  afterEach(() => {
    restore?.();
    restore = undefined;
  });

  test("the probe fails, selection falls back to JS and the vector still passes", async () => {
    restore = hideX25519();
    expect(await nativeX25519Works()).toBe(false);
    expect(await selectKem()).toBe("js");
    expectVector(await runSender(createSuite("js")));
  });

  test("restoring brings native X25519 back", async () => {
    restore = hideX25519();
    expect(await nativeX25519Works()).toBe(false);
    restore();
    restore = undefined;
    expect(await nativeX25519Works()).toBe(true);
  });
});
