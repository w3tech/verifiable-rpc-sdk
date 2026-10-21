import { describe, expect, test } from "vitest";
import {
  type ConfidentialTransport,
  guardedSend,
  type OuterRequest,
  type OuterResponse,
  ResponseTooLarge,
} from "../src/transport";

const MAX = 8;
const reason = new Error("caller gave up");
const KEYED = "https://rpc.example/eth_vrpc/k3y-secret";

function answer(bytes: number): OuterResponse {
  return { status: 200, headers: new Headers(), body: new Uint8Array(bytes) };
}

const fail = (failure: string, cause?: unknown) =>
  Object.assign(new Error(failure), { failure, cause });

interface Row {
  name: string;
  transport: (controller: AbortController) => ConfidentialTransport;
  abortFirst?: true;
  expected: (err: unknown) => void;
}

const rejectsWithReason = (err: unknown) => expect(err).toBe(reason);

function messages(err: unknown): string {
  return err instanceof Error ? `${err.message} ${messages(err.cause)}` : "";
}

function sanitisedTo(code?: string): Row["expected"] {
  return (err) => {
    const { failure, cause } = err as { failure: string; cause: Error };
    expect(failure).toBe("network");
    expect(cause.message).toBe("The request failed.");
    expect((cause as { code?: string }).code).toBe(code);
    expect(messages(err)).not.toMatch(/eth_vrpc|k3y-secret/);
  };
}

const rows: Row[] = [
  {
    name: "a body of exactly maxBytes resolves",
    transport: () => async () => answer(MAX),
    expected: (err) => expect(err).toBeUndefined(),
  },
  {
    name: "a body of maxBytes + 1 fails too-large without a cause",
    transport: () => async () => answer(MAX + 1),
    expected: (err) => expect(err).toMatchObject({ failure: "too-large", cause: undefined }),
  },
  {
    name: "a transport over its own size cap fails too-large",
    transport: () => async () => {
      throw new ResponseTooLarge();
    },
    expected: (err) => expect(err).toMatchObject({ failure: "too-large", cause: undefined }),
  },
  {
    name: "a signal aborted before the call never reaches the transport",
    transport: () => async () => answer(1),
    abortFirst: true,
    expected: rejectsWithReason,
  },
  {
    name: "an abort while a transport that ignores the signal is pending",
    transport: (controller) => () => {
      controller.abort(reason);
      return new Promise<OuterResponse>(() => {});
    },
    expected: rejectsWithReason,
  },
  {
    name: "a transport failing after the abort",
    transport: (controller) => async () => {
      controller.abort(reason);
      throw new TypeError("socket closed");
    },
    expected: rejectsWithReason,
  },
  {
    name: "a synchronous throw quoting the keyed URL keeps only its code",
    transport: () => () => {
      throw Object.assign(new TypeError(`bad ${KEYED}`), { code: "ERR_INVALID_URL" });
    },
    expected: sanitisedTo("ERR_INVALID_URL"),
  },
  {
    name: "a rejection quoting the keyed URL keeps only the code of its cause",
    transport: () => async () => {
      const cause = Object.assign(new Error(`connect ${KEYED}`), { code: "ECONNRESET" });
      throw Object.assign(new Error(`request to ${KEYED} failed`), { cause });
    },
    expected: sanitisedTo("ECONNRESET"),
  },
  {
    name: "a lower-case or non-string code is not copied",
    transport: () => async () => {
      throw Object.assign(new Error(KEYED), { code: "econnreset", cause: { code: 42 } });
    },
    expected: sanitisedTo(undefined),
  },
];

describe("guardedSend", () => {
  test.each(rows)("$name", async (row) => {
    const controller = new AbortController();
    if (row.abortFirst) controller.abort(reason);
    let calls = 0;
    const inner = row.transport(controller);
    const transport: ConfidentialTransport = (request) => {
      calls += 1;
      return inner(request);
    };
    const request: OuterRequest = {
      method: "POST",
      url: "https://rpc.example/eth_vrpc",
      headers: {},
      signal: controller.signal,
    };

    const err = await guardedSend(transport, request, MAX, fail).then(
      () => undefined,
      (e: unknown) => e,
    );
    row.expected(err);
    expect(calls).toBe(row.abortFirst ? 0 : 1);
  });
});
