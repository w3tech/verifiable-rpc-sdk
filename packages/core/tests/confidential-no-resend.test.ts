// The client with its default transport puts exactly one request on the wire per call whatever
// the gateway answers, follows no redirect, and only re-attests on the next call.

import {
  CHAIN_ID,
  createTestNode,
  isPost,
  jsonRpcCall,
  KEY,
  mockHardwareVerifier,
  rejectionOf,
} from "@w3tech.io/vrpc-test-support";
import {
  describeOneRequestPerCall,
  SEALED_POST_FAILURES,
} from "@w3tech.io/vrpc-test-support/adapter";
import {
  failureAnswer,
  serveTestNode,
  type TestNodeServer,
  type TestNodeServerOptions,
} from "@w3tech.io/vrpc-test-support/server";
import { describe, expect, onTestFinished, test } from "vitest";
import { ConfidentialClient } from "../src/confidential-client";
import { AttestationUnavailable, RequestRejected, UnexpectedResponse } from "../src/errors";

const UPSTREAM_BODY = '{"jsonrpc":"2.0","id":1,"result":"0x10"}';
const text = new TextDecoder();
const coreClass = { RequestRejected, UnexpectedResponse, AttestationUnavailable };

async function serve(options: TestNodeServerOptions = {}): Promise<TestNodeServer> {
  const server = await serveTestNode(createTestNode(), options);
  onTestFinished(() => server.close());
  return server;
}

function clientAt(server: TestNodeServer): ConfidentialClient {
  return new ConfidentialClient({
    url: `${server.url}/eth_vrpc/${KEY}`,
    chainId: CHAIN_ID,
    hardwareVerifier: mockHardwareVerifier(),
  });
}

describeOneRequestPerCall(
  "one request per call with the default transport",
  async () => {
    const server = await serve();
    const client = clientAt(server);
    return { server, call: () => client.request(jsonRpcCall()), ready: () => client.ready() };
  },
  (err) => {
    expect(err).toBeInstanceOf(coreClass[(err as { kind: keyof typeof coreClass }).kind]);
    return err;
  },
);

test.each(SEALED_POST_FAILURES)(
  "after the sealed POST answered %i the next call succeeds",
  async (status) => {
    const server = await serve();
    const client = clientAt(server);
    server.answer((request) => (isPost(request) ? failureAnswer(server, status) : undefined));
    await rejectionOf(client.request(jsonRpcCall()));

    server.answer();
    const response = await client.request(jsonRpcCall());
    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
  },
);

describe("encoding", () => {
  test("gzipped answers are decoded before verification", async () => {
    const server = await serve({ gzipWhenAccepted: true });
    const client = clientAt(server);

    const response = await client.request(jsonRpcCall());

    expect(text.decode(response.body)).toBe(UPSTREAM_BODY);
    expect(server.requests.some((r) => r.gzipped)).toBe(true);
  });
});
