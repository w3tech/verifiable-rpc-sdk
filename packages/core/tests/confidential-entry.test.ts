import type {
  AttestationUnavailableReason as MainAttestationUnavailableReason,
  InvalidInnerRequestReason as MainInvalidInnerRequestReason,
  MalformedConfidentialResponseReason as MainMalformedConfidentialResponseReason,
  TransportFailedReason as MainTransportFailedReason,
} from "@w3tech.io/vrpc-core";
import * as main from "@w3tech.io/vrpc-core";
import type {
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialResponse,
  ConfidentialTransport,
  AttestationUnavailableReason as EntryAttestationUnavailableReason,
  InvalidInnerRequestReason as EntryInvalidInnerRequestReason,
  MalformedConfidentialResponseReason as EntryMalformedConfidentialResponseReason,
  TransportFailedReason as EntryTransportFailedReason,
  InnerRequest,
  OuterRequest,
  OuterResponse,
  UnavailableErrorKind,
} from "@w3tech.io/vrpc-core/confidential";
import * as conf from "@w3tech.io/vrpc-core/confidential";
import type {
  AttestationUnavailableReason,
  InvalidInnerRequestReason,
  MalformedConfidentialResponseReason,
  TransportFailedReason,
} from "@w3tech.io/vrpc-core/errors";
import * as errors from "@w3tech.io/vrpc-core/errors";
import { CHAIN_ID, createTestNode, mockHardwareVerifier } from "@w3tech.io/vrpc-test-support";
import { describe, expect, expectTypeOf, test } from "vitest";

const utf8 = new TextEncoder();

function errorClasses(): [string, unknown][] {
  return Object.entries(errors).filter(([, value]) => typeof value === "function");
}

function extendsUnavailableError(value: unknown): boolean {
  return (
    typeof value === "function" &&
    Object.prototype.isPrototypeOf.call(errors.UnavailableError.prototype, value.prototype)
  );
}

describe("@w3tech.io/vrpc-core/confidential", () => {
  test("a JSON-RPC call through the entry succeeds", async () => {
    const node = createTestNode();
    const client = new conf.ConfidentialClient({
      url: "https://rpc.example/eth_vrpc/0123456789abcdefghijABCDEFGHIJkl",
      chainId: CHAIN_ID,
      hardwareVerifier: mockHardwareVerifier(),
      transport: node.transport,
    });
    const response = await client.request({
      method: "POST",
      path: "/",
      contentType: "application/json",
      accept: "application/json",
      body: utf8.encode('{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'),
    });

    expect(response.status).toBe(200);
  });

  test("every error class of the errors entry is the same value in the main entry", () => {
    const classes = errorClasses();
    expect(classes.length).toBeGreaterThan(0);
    for (const [name, value] of classes) {
      expect((main as Record<string, unknown>)[name], name).toBe(value);
    }
  });

  test("every error the client throws is the same value in the entry", () => {
    const names = [
      "VrpcError",
      "VerificationError",
      "UnavailableError",
      "BadSignature",
      "StaleTimestamp",
      "MissingHeader",
      "MalformedHeader",
      "AttestationFailed",
      "ConfidentialSignerMismatch",
      "ConfidentialDecryptFailed",
      "MalformedConfidentialResponse",
      "InvalidInnerRequest",
      "InvalidOption",
      ...errorClasses()
        .filter(([, value]) => extendsUnavailableError(value))
        .map(([name]) => name),
    ];
    expect(names).toEqual(
      expect.arrayContaining([
        "AttestationUnavailable",
        "InternalError",
        "RequestRejected",
        "TransportFailed",
        "UnexpectedResponse",
      ]),
    );
    for (const name of names) {
      expect((conf as Record<string, unknown>)[name], name).toBe(
        (errors as Record<string, unknown>)[name],
      );
    }
  });

  test("the main entry does not export the client", () => {
    expect("ConfidentialClient" in main).toBe(false);
  });

  test("the public types are importable from the entry", () => {
    expectTypeOf<ConfidentialClientOptions>().toHaveProperty("url");
    expectTypeOf<ConfidentialInfo>().toBeObject();
    expectTypeOf<ConfidentialResponse>().toHaveProperty("status");
    expectTypeOf<OuterRequest>().toBeObject();
    expectTypeOf<OuterResponse>().toBeObject();
    expectTypeOf<ConfidentialTransport>().toBeFunction();
    expectTypeOf<InnerRequest>().toHaveProperty("path");
    expectTypeOf<UnavailableErrorKind>().toEqualTypeOf<
      | "AttestationUnavailable"
      | "RequestRejected"
      | "UnexpectedResponse"
      | "TransportFailed"
      | "InternalError"
    >();
    expectTypeOf<EntryAttestationUnavailableReason>().toEqualTypeOf<AttestationUnavailableReason>();
    expectTypeOf<EntryInvalidInnerRequestReason>().toEqualTypeOf<InvalidInnerRequestReason>();
    expectTypeOf<EntryMalformedConfidentialResponseReason>().toEqualTypeOf<MalformedConfidentialResponseReason>();
    expectTypeOf<EntryTransportFailedReason>().toEqualTypeOf<TransportFailedReason>();
    expectTypeOf<MainAttestationUnavailableReason>().toEqualTypeOf<AttestationUnavailableReason>();
    expectTypeOf<MainInvalidInnerRequestReason>().toEqualTypeOf<InvalidInnerRequestReason>();
    expectTypeOf<MainMalformedConfidentialResponseReason>().toEqualTypeOf<MalformedConfidentialResponseReason>();
    expectTypeOf<MainTransportFailedReason>().toEqualTypeOf<TransportFailedReason>();
  });
});
