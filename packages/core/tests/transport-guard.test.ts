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

function answer(bytes: number): OuterResponse {
  return { status: 200, headers: new Headers(), body: new Uint8Array(bytes) };
}

const fail = (failure: string, cause?: unknown) =>
  Object.assign(new Error(failure), { failure, cause });

interface Row {
  name: string;
  transport: (controller: AbortController) => ConfidentialTransport;
  abortFirst?: true;
  calls: number;
  expected: (err: unknown, sent: unknown) => void;
}

const rejectsWithReason = (err: unknown) => expect(err).toBe(reason);

const rows: Row[] = [
  {
    name: "a body of exactly maxBytes resolves",
    transport: () => async () => answer(MAX),
    calls: 1,
    expected: (err) => expect(err).toBeUndefined(),
  },
  {
    name: "a body of maxBytes + 1 fails too-large without a cause",
    transport: () => async () => answer(MAX + 1),
    calls: 1,
    expected: (err) => expect(err).toMatchObject({ failure: "too-large", cause: undefined }),
  },
  {
    name: "a transport over its own size cap fails too-large",
    transport: () => async () => {
      throw new ResponseTooLarge();
    },
    calls: 1,
    expected: (err) => expect(err).toMatchObject({ failure: "too-large", cause: undefined }),
  },
  {
    name: "a signal aborted before the call never reaches the transport",
    transport: () => async () => answer(1),
    abortFirst: true,
    calls: 0,
    expected: rejectsWithReason,
  },
  {
    name: "an abort while a transport that ignores the signal is pending",
    transport: (controller) => () => {
      controller.abort(reason);
      return new Promise<OuterResponse>(() => {});
    },
    calls: 1,
    expected: rejectsWithReason,
  },
  {
    name: "a transport failing after the abort",
    transport: (controller) => async () => {
      controller.abort(reason);
      throw new TypeError("socket closed");
    },
    calls: 1,
    expected: rejectsWithReason,
  },
  {
    name: "a transport throwing synchronously fails network",
    transport: () => () => {
      throw new TypeError("bad url");
    },
    calls: 1,
    expected: (err, sent) => expect(err).toMatchObject({ failure: "network", cause: sent }),
  },
];

describe("guardedSend", () => {
  test.each(rows)("$name", async (row) => {
    const controller = new AbortController();
    if (row.abortFirst) controller.abort(reason);
    let calls = 0;
    let sent: unknown;
    const inner = row.transport(controller);
    const transport: ConfidentialTransport = (request) => {
      calls += 1;
      try {
        return inner(request);
      } catch (err) {
        sent = err;
        throw err;
      }
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
    row.expected(err, sent);
    expect(calls).toBe(row.calls);
  });
});
