import { describe, expect, test } from "vitest";

import {
  AttestationCorrelationError,
  AttestationFailed,
  AttestationNodeNotFoundError,
  AttestationUnavailable,
  BadSignature,
  ConfidentialDecryptFailed,
  ConfidentialSealFailed,
  ConfidentialSignerMismatch,
  InvalidChainId,
  InvalidInnerRequest,
  InvalidNonce,
  MalformedAttestationResponse,
  MalformedConfidentialResponse,
  MalformedHeader,
  MissingHeader,
  RequestRejected,
  StaleTimestamp,
  TransportFailed,
  UnavailableError,
  UnexpectedResponse,
  VerificationError,
  VrpcError,
} from "../src/errors";

describe("errors", () => {
  test("everyClassIsAVrpcErrorThatMayHaveExecutedByDefault", () => {
    const key = `0x${"00".repeat(32)}`;
    const all: VrpcError[] = [
      new MissingHeader("vRPC-Signature"),
      new MalformedHeader("vRPC-Pubkey", "x", "y"),
      new InvalidChainId("", "empty"),
      new BadSignature({
        signatureHex: `0x${"00".repeat(64)}`,
        pubkeyHex: key,
        preImageSha256: new Uint8Array(32),
      }),
      new StaleTimestamp({ observedMs: 1n, nowMs: 2n, skewMs: -1n, allowedWindowMs: 1 }),
      new InvalidNonce("r"),
      new MalformedAttestationResponse("r"),
      new AttestationNodeNotFoundError("n"),
      new AttestationCorrelationError(key, key),
      new AttestationFailed("CHK-1", "d"),
      new ConfidentialSignerMismatch(key, key),
      new InvalidInnerRequest("path"),
      new ConfidentialDecryptFailed(),
      new MalformedConfidentialResponse("framing"),
      new AttestationUnavailable("timeout"),
      new UnexpectedResponse(502, "n"),
      new TransportFailed("network", "n"),
      new ConfidentialSealFailed(),
    ];
    for (const err of all) {
      expect(err).toBeInstanceOf(VrpcError);
      expect(err.executed).toBe("unknown");
      expect("cause" in err).toBe(false);
    }
    const rejected = new RequestRejected(429, "n");
    expect(rejected).toBeInstanceOf(VrpcError);
    expect(rejected.executed).toBe("no");
  });

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

  test("unavailableErrorsAreNotVerificationErrors", () => {
    const attestation = new AttestationUnavailable("node-id-missing");
    const unexpected = new UnexpectedResponse(502, "node-1", "text/plain");
    for (const err of [attestation, unexpected]) {
      expect(err instanceof Error).toBe(true);
      expect(err instanceof UnavailableError).toBe(true);
      expect(err instanceof VerificationError).toBe(false);
    }
    expect(attestation.executed).toBe("unknown");
    expect(unexpected.executed).toBe("unknown");
    expect(attestation.name).toBe("AttestationUnavailable");
    expect(unexpected.name).toBe("UnexpectedResponse");
    expect(attestation.kind).toBe("AttestationUnavailable");
    expect(unexpected.kind).toBe("UnexpectedResponse");
  });

  test("attestationUnavailableCarriesReasonAndOptionalStatus", () => {
    const withStatus = new AttestationUnavailable("status", { status: 429 });
    expect(withStatus.reason).toBe("status");
    expect(withStatus.status).toBe(429);
    expect(withStatus.message).toBe("Attestation unavailable: HTTP 429");

    const cause = new Error("socket closed");
    const withoutStatus = new AttestationUnavailable("transport", { cause });
    expect(withoutStatus.message).toBe("Attestation unavailable: transport");
    expect("status" in withoutStatus).toBe(false);
    expect(withoutStatus.cause).toBe(cause);
    expect("cause" in new AttestationUnavailable("timeout")).toBe(false);
  });

  test("unexpectedResponseCarriesStatusNodeIdAndOptionalContentType", () => {
    const err = new UnexpectedResponse(502, "node-1", "text/plain");
    expect(err.status).toBe(502);
    expect(err.nodeId).toBe("node-1");
    expect(err.contentType).toBe("text/plain");
    expect(err.message).toBe("Unexpected confidential response: HTTP 502");
    expect("contentType" in new UnexpectedResponse(0, "node-1")).toBe(false);
  });

  test("confidentialSignerMismatchIsAVerificationError", () => {
    const expected = `0x${"ab".repeat(32)}`;
    const actual = `0x${"cd".repeat(32)}`;
    const err = new ConfidentialSignerMismatch(expected, actual);
    expect(err instanceof VerificationError).toBe(true);
    expect(err.kind).toBe("ConfidentialSignerMismatch");
    expect(err.name).toBe("ConfidentialSignerMismatch");
    expect(err.expectedPubkey).toBe(expected);
    expect(err.actualPubkey).toBe(actual);
  });

  test("invalidInnerRequestIsNeitherAVerificationNorAnUnavailableError", () => {
    const err = new InvalidInnerRequest("content-type-required");
    expect(err instanceof VrpcError).toBe(true);
    expect(err instanceof VerificationError).toBe(false);
    expect(err instanceof UnavailableError).toBe(false);
    expect(err.kind).toBe("InvalidInnerRequest");
    expect(err.name).toBe("InvalidInnerRequest");
    expect(err.reason).toBe("content-type-required");
    expect(err.message).toBe("Inner request rejected: content-type-required");
  });

  test("requestRejectedAndTransportFailedAreUnavailableErrors", () => {
    const rejected = new RequestRejected(429, "node-1", "text/plain");
    const failed = new TransportFailed("network", "node-1");
    for (const err of [rejected, failed]) {
      expect(err instanceof UnavailableError).toBe(true);
      expect(err instanceof VerificationError).toBe(false);
      expect("body" in err).toBe(false);
    }
    expect(rejected.kind).toBe("RequestRejected");
    expect(rejected.name).toBe("RequestRejected");
    expect(rejected.executed).toBe("no");
    expect(rejected.status).toBe(429);
    expect(rejected.nodeId).toBe("node-1");
    expect(rejected.contentType).toBe("text/plain");
    expect(rejected.message).toBe("Confidential request rejected: HTTP 429");
    expect("contentType" in new RequestRejected(413, "node-1")).toBe(false);

    expect(failed.kind).toBe("TransportFailed");
    expect(failed.name).toBe("TransportFailed");
    expect(failed.executed).toBe("unknown");
    expect(failed.reason).toBe("network");
    expect(failed.message).toBe("Confidential request failed in transport: network");
  });

  test("transportFailedKeepsCauseOnlyWhenGiven", () => {
    const cause = new TypeError("fetch failed");
    expect(new TransportFailed("network", "node-1", { cause }).cause).toBe(cause);
    expect("cause" in new TransportFailed("too-large", "node-1")).toBe(false);
  });

  test("confidentialSealFailedIsUnavailableAndKeepsCause", () => {
    const cause = new Error("platform crypto failure");
    const err = new ConfidentialSealFailed({ cause });
    expect(err instanceof UnavailableError).toBe(true);
    expect(err instanceof VerificationError).toBe(false);
    expect(err.kind).toBe("ConfidentialSealFailed");
    expect(err.name).toBe("ConfidentialSealFailed");
    expect(err.cause).toBe(cause);
    expect(err.message).toBe(
      "Confidential request could not be sealed by the local crypto runtime",
    );
  });

  test("confidentialDecryptAndMalformedResponseAreVerificationKinds", () => {
    const decrypt = new ConfidentialDecryptFailed();
    expect(decrypt instanceof VerificationError).toBe(true);
    expect(decrypt.kind).toBe("ConfidentialDecryptFailed");
    expect(decrypt.name).toBe("ConfidentialDecryptFailed");
    expect(decrypt.message).toBe("Signed confidential response could not be decrypted");
    expect("cause" in decrypt).toBe(false);

    for (const reason of ["too-short", "framing", "informational", "decode-failed"] as const) {
      const malformed = new MalformedConfidentialResponse(reason);
      expect(malformed instanceof VerificationError).toBe(true);
      expect(malformed.kind).toBe("MalformedConfidentialResponse");
      expect(malformed.reason).toBe(reason);
      expect(malformed.message).toBe(`Malformed confidential response: ${reason}`);
      expect(malformed.message).not.toMatch(/[0-9a-f]{9,}/i);
      expect("cause" in malformed).toBe(false);
    }
    expect(decrypt.message).not.toMatch(/[0-9a-f]{9,}/i);
  });
});
