import { describe, expect, test } from "vitest";

import {
  AttestationCorrelationError,
  AttestationNodeNotFoundError,
  BadSignature,
  InvalidChainId,
  InvalidNonce,
  MalformedAttestationResponse,
  MalformedHeader,
  MissingHeader,
  StaleTimestamp,
  VerificationError,
} from "../src/errors";

describe("errors", () => {
  test("subclassesAreInstanceOfVerificationErrorAndError", () => {
    const missing = new MissingHeader("vRPC-Signature");
    expect(missing instanceof Error).toBe(true);
    expect(missing instanceof VerificationError).toBe(true);
    expect(missing instanceof MissingHeader).toBe(true);

    const malformed = new MalformedHeader("vRPC-Pubkey", "x", "y");
    expect(malformed instanceof Error).toBe(true);
    expect(malformed instanceof VerificationError).toBe(true);
    expect(malformed instanceof MalformedHeader).toBe(true);

    const bad = new BadSignature({
      signatureHex: `0x${"00".repeat(64)}`,
      pubkeyHex: `0x${"00".repeat(32)}`,
      preImageSha256: new Uint8Array(32),
    });
    expect(bad instanceof Error).toBe(true);
    expect(bad instanceof VerificationError).toBe(true);
    expect(bad instanceof BadSignature).toBe(true);

    const stale = new StaleTimestamp({
      observedMs: 100n,
      nowMs: 70_000n,
      skewMs: -69_900n,
      allowedWindowMs: 60_000,
    });
    expect(stale instanceof Error).toBe(true);
    expect(stale instanceof VerificationError).toBe(true);
    expect(stale instanceof StaleTimestamp).toBe(true);

    const invalidNonce = new InvalidNonce("too short");
    expect(invalidNonce instanceof Error).toBe(true);
    expect(invalidNonce instanceof VerificationError).toBe(true);
    expect(invalidNonce instanceof InvalidNonce).toBe(true);

    const invalidChainId = new InvalidChainId("", "must not be empty");
    expect(invalidChainId instanceof Error).toBe(true);
    expect(invalidChainId instanceof VerificationError).toBe(true);
    expect(invalidChainId instanceof InvalidChainId).toBe(true);

    const malformedAttestation = new MalformedAttestationResponse("missing field quote.event_log");
    expect(malformedAttestation instanceof Error).toBe(true);
    expect(malformedAttestation instanceof VerificationError).toBe(true);
    expect(malformedAttestation instanceof MalformedAttestationResponse).toBe(true);
  });

  test("kindFieldDiscriminates", () => {
    const missing = new MissingHeader("vRPC-Signature");
    expect(missing.kind).toBe("MissingHeader");

    const malformed = new MalformedHeader("vRPC-Pubkey", "x", "y");
    expect(malformed.kind).toBe("MalformedHeader");

    const bad = new BadSignature({
      signatureHex: "0x00",
      pubkeyHex: "0x00",
      preImageSha256: new Uint8Array(32),
    });
    expect(bad.kind).toBe("BadSignature");

    const stale = new StaleTimestamp({
      observedMs: 0n,
      nowMs: 0n,
      skewMs: 0n,
      allowedWindowMs: 0,
    });
    expect(stale.kind).toBe("StaleTimestamp");

    expect(new InvalidNonce("x").kind).toBe("InvalidNonce");
    expect(new MalformedAttestationResponse("y").kind).toBe("MalformedAttestationResponse");
    expect(new InvalidChainId("a b", "whitespace").kind).toBe("InvalidChainId");
  });

  test("invalidChainIdCarriesIdAndReason", () => {
    const err = new InvalidChainId("cépas", "contains non-printable-ASCII or whitespace character");
    expect(err.chainId).toBe("cépas");
    expect(err.reason).toBe("contains non-printable-ASCII or whitespace character");
    expect(err.message).toContain("cépas");
    expect(err.message).toContain("non-printable-ASCII");
  });

  test("missingHeaderCarriesHeaderName", () => {
    const err = new MissingHeader("vRPC-Signature");
    expect(err.headerName).toBe("vRPC-Signature");
    expect(err.message).toContain("vRPC-Signature");
  });

  test("malformedHeaderCarriesNameValueAndReason", () => {
    const err = new MalformedHeader(
      "vRPC-Pubkey",
      "deadbeef",
      "expected 0x-prefixed 64-char lowercase hex",
    );
    expect(err.headerName).toBe("vRPC-Pubkey");
    expect(err.value).toBe("deadbeef");
    expect(err.reason).toBe("expected 0x-prefixed 64-char lowercase hex");
    expect(err.message).toContain("vRPC-Pubkey");
    expect(err.message).toContain("deadbeef");
    expect(err.message).toContain("expected 0x-prefixed 64-char lowercase hex");
  });

  test("badSignatureCarriesContext", () => {
    const ctx = {
      signatureHex: `0x${"ab".repeat(64)}`,
      pubkeyHex: `0x${"cd".repeat(32)}`,
      preImageSha256: new Uint8Array(32).fill(0xef),
    };
    const err = new BadSignature(ctx);
    expect(err.signatureHex).toBe(ctx.signatureHex);
    expect(err.pubkeyHex).toBe(ctx.pubkeyHex);
    expect(err.preImageSha256.length).toBe(32);
    expect(err.preImageSha256[0]).toBe(0xef);
  });

  test("invalidNonceCarriesReason", () => {
    const err = new InvalidNonce("expected 32 bytes, got 31");
    expect(err.reason).toBe("expected 32 bytes, got 31");
    expect(err.message).toContain("expected 32 bytes, got 31");
  });

  test("malformedAttestationResponseCarriesReason", () => {
    const err = new MalformedAttestationResponse("missing field: quote.event_log");
    expect(err.reason).toBe("missing field: quote.event_log");
    expect(err.message).toContain("missing field: quote.event_log");
  });

  test("staleTimestampCarriesSkew", () => {
    const err = new StaleTimestamp({
      observedMs: 100n,
      nowMs: 70_000n,
      skewMs: -69_900n,
      allowedWindowMs: 60_000,
    });
    expect(err.observedMs).toBe(100n);
    expect(err.nowMs).toBe(70_000n);
    expect(err.skewMs).toBe(-69_900n);
    expect(err.allowedWindowMs).toBe(60_000);
    expect(typeof err.allowedWindowMs).toBe("number");
    expect(typeof err.observedMs).toBe("bigint");
  });

  test("abstractBaseCannotBeInstantiated", () => {
    // Compile-time enforcement: `new VerificationError(...)` is a type error.
    // @ts-expect-error VerificationError is abstract.
    const ctor = () => new VerificationError("x");
    expect(ctor).toBeDefined();
    // Structural check: subclasses each have their own constructor.
    expect(MissingHeader.prototype.constructor).toBe(MissingHeader);
    expect(MalformedHeader.prototype.constructor).toBe(MalformedHeader);
    expect(BadSignature.prototype.constructor).toBe(BadSignature);
    expect(StaleTimestamp.prototype.constructor).toBe(StaleTimestamp);
  });

  test("errorNameMatchesClassName", () => {
    expect(new MissingHeader("h").name).toBe("MissingHeader");
    expect(new MalformedHeader("h", "v", "r").name).toBe("MalformedHeader");
    expect(
      new BadSignature({
        signatureHex: "0x",
        pubkeyHex: "0x",
        preImageSha256: new Uint8Array(32),
      }).name,
    ).toBe("BadSignature");
    expect(
      new StaleTimestamp({
        observedMs: 0n,
        nowMs: 0n,
        skewMs: 0n,
        allowedWindowMs: 0,
      }).name,
    ).toBe("StaleTimestamp");
    expect(new InvalidNonce("x").name).toBe("InvalidNonce");
    expect(new MalformedAttestationResponse("y").name).toBe("MalformedAttestationResponse");
    expect(new InvalidChainId("", "must not be empty").name).toBe("InvalidChainId");
  });

  test("attestationNodeNotFoundCarriesNodeIdAndKind", () => {
    const err = new AttestationNodeNotFoundError("node-7");
    expect(err instanceof Error).toBe(true);
    expect(err instanceof VerificationError).toBe(true);
    expect(err instanceof AttestationNodeNotFoundError).toBe(true);
    expect(err.kind).toBe("AttestationNodeNotFound");
    expect(err.name).toBe("AttestationNodeNotFoundError");
    expect(err.nodeId).toBe("node-7");
    expect(err.message).toContain("node-7");
  });

  test("attestationCorrelationCarriesPubkeysAndKind", () => {
    const expected = `0x${"ab".repeat(32)}`;
    const actual = `0x${"cd".repeat(32)}`;
    const err = new AttestationCorrelationError(expected, actual);
    expect(err instanceof Error).toBe(true);
    expect(err instanceof VerificationError).toBe(true);
    expect(err instanceof AttestationCorrelationError).toBe(true);
    expect(err.kind).toBe("AttestationCorrelation");
    expect(err.name).toBe("AttestationCorrelationError");
    expect(err.expectedPubkey).toBe(expected);
    expect(err.actualPubkey).toBe(actual);
    expect(err.message).toContain(expected);
    expect(err.message).toContain(actual);
  });
});
