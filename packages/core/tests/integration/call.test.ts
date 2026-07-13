// Integration tests for the signed-call wire contract against a live sidecar
// backed by the dstack simulator + an in-process mock JSON-RPC upstream. Drives
// `verifyResponse` over raw fetched bytes plus the standalone `fetchAttestation`
// helper. See `tests/integration/harness.ts` for the spawn machinery — this file
// is just assertions.
//
// Env-gated: if any of `DSTACK_SIMULATOR_BIN`, `DSTACK_SIMULATOR_FIXTURES_DIR`,
// or `SIDECAR_BIN` is unset, the entire `describe` block is skipped and a
// one-line skip message is logged at module load.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { fetchAttestation, type VerifiedPair, verifyResponse } from "../../src/index";
import {
  cleanup,
  integrationEnabled,
  type MockUpstreamHandle,
  type SidecarHandle,
  type SimulatorHandle,
  spawnMockUpstream,
  spawnSidecar,
  spawnSimulator,
} from "./harness";

if (!integrationEnabled) {
  console.log(
    "[integration] skipping — set DSTACK_SIMULATOR_BIN, DSTACK_SIMULATOR_FIXTURES_DIR, SIDECAR_BIN to run",
  );
}

const d = integrationEnabled ? describe : describe.skip;

// Auto-incrementing JSON-RPC id: consecutive calls must send distinct request
// bytes so their pre-images (and deterministic Ed25519 signatures) always
// differ, even when two loopback round-trips land in the same millisecond.
let nextId = 1;

/** POST a JSON-RPC envelope to the sidecar and return the raw wire triple. */
async function rpcCall(
  url: string,
  method: string,
  params: unknown[],
): Promise<{ requestBytes: Uint8Array; responseBytes: Uint8Array; headers: Headers }> {
  const requestBytes = new TextEncoder().encode(
    JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  );
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBytes,
  });
  const responseBytes = new Uint8Array(await res.arrayBuffer());
  return { requestBytes, responseBytes, headers: res.headers };
}

/** Fetch + verify one `eth_blockNumber` call, returning the verified pair and raw bytes. */
async function verifiedBlockNumber(
  url: string,
): Promise<{ pair: VerifiedPair; responseBytes: Uint8Array }> {
  const { requestBytes, responseBytes, headers } = await rpcCall(url, "eth_blockNumber", []);
  const pair = await verifyResponse(requestBytes, responseBytes, headers, { chainId: "1" });
  return { pair, responseBytes };
}

d("integration: call", () => {
  let simulator: SimulatorHandle | undefined;
  let upstream: MockUpstreamHandle | undefined;
  let sidecar: SidecarHandle | undefined;

  beforeAll(async () => {
    simulator = await spawnSimulator();
    upstream = await spawnMockUpstream();
    sidecar = await spawnSidecar(simulator.socketPath, upstream.url, "1");
  });

  afterAll(async () => {
    await cleanup([sidecar, upstream, simulator]);
  });

  it("eth_blockNumber over the live wire verifies with a valid signature", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const { pair, responseBytes } = await verifiedBlockNumber(sidecar.url);

    // Nothing parses JSON-RPC anymore — decode the verified bytes manually.
    const body = JSON.parse(new TextDecoder().decode(responseBytes)) as { result: string };
    expect(body.result).toBe("0x1234");

    expect(pair.verification.pubkeyHex).toBe(sidecar.pubkeyHex);
    // signatureHex is "0x" + 128 lowercase hex (64 raw bytes).
    expect(pair.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(pair.verification.preImageSha256.length).toBe(32);

    const nowMs = BigInt(Date.now());
    expect(pair.verification.timestampMs > 0n).toBe(true);
    // Sidecar timestamp must be within the last 60s of the local clock.
    const skew = nowMs - pair.verification.timestampMs;
    expect(skew >= -60_000n && skew <= 60_000n).toBe(true);
  });

  it("call's pubkey matches fetchAttestation pubkey (cross-endpoint consistency)", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const { pair } = await verifiedBlockNumber(sidecar.url);
    const nonce = new Uint8Array(32).fill(0x42);
    const att = await fetchAttestation({ attestationUrl: `${sidecar.url}/attestation`, nonce });
    // The same TDX-attested keypair signs call responses and is reported by
    // `/attestation`. If these ever diverge the sidecar is broken — either it
    // rotates keys mid-flight, or one of the two endpoints reads from a stale
    // cache.
    expect(att.pubkey).toBe(pair.verification.pubkeyHex);
  });

  it("multiple consecutive calls each produce fresh signatures", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const { pair: a } = await verifiedBlockNumber(sidecar.url);
    const { pair: b } = await verifiedBlockNumber(sidecar.url);
    expect(a.verification.pubkeyHex).toBe(b.verification.pubkeyHex);
    // The two requests carry distinct JSON-RPC ids, so their pre-images differ
    // regardless of timestamp resolution. If this ever fires on the same
    // signatureHex, the sidecar signed a stale/cached pre-image.
    expect(a.verification.signatureHex).not.toBe(b.verification.signatureHex);
  });
});
