// Integration tests for `VerifierClient.call` against a live sidecar backed by
// the dstack simulator + an in-process mock JSON-RPC upstream. See
// `tests/integration/harness.ts` for the spawn machinery — this file is just
// assertions.
//
// Env-gated: if any of `DSTACK_SIMULATOR_BIN`, `DSTACK_SIMULATOR_FIXTURES_DIR`,
// or `SIDECAR_BIN` is unset, the entire `describe` block is skipped and a
// one-line skip message is logged at module load.

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { VerifierClient } from "../../src/index";
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

d("integration: call", () => {
  let simulator: SimulatorHandle | undefined;
  let upstream: MockUpstreamHandle | undefined;
  let sidecar: SidecarHandle | undefined;
  let client: VerifierClient;

  beforeAll(async () => {
    simulator = await spawnSimulator();
    upstream = await spawnMockUpstream();
    sidecar = await spawnSidecar(simulator.socketPath, upstream.url, 1);
    client = new VerifierClient(sidecar.url, { chainId: 1n });
  });

  afterAll(async () => {
    await cleanup([sidecar, upstream, simulator]);
  });

  it("call('eth_blockNumber', []) returns VerifiedResponse with valid signature", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const resp = await client.call<string>("eth_blockNumber", []);

    expect(resp.result).toBe("0x1234");
    expect(resp.verification.pubkeyHex).toBe(sidecar.pubkeyHex);
    // signatureHex is "0x" + 128 lowercase hex (64 raw bytes).
    expect(resp.verification.signatureHex).toMatch(/^0x[0-9a-f]{128}$/);
    expect(resp.verification.preImageSha256.length).toBe(32);

    const nowMs = BigInt(Date.now());
    expect(resp.verification.timestampMs > 0n).toBe(true);
    // Sidecar timestamp must be within the last 60s of the local clock.
    const skew = nowMs - resp.verification.timestampMs;
    expect(skew >= -60_000n && skew <= 60_000n).toBe(true);
  });

  it("call's pubkey matches fetchAttestation pubkey (cross-endpoint consistency)", async () => {
    const callResp = await client.call<string>("eth_blockNumber", []);
    const nonce = new Uint8Array(32).fill(0x42);
    const att = await client.fetchAttestation(nonce);
    // The same TDX-attested keypair signs `call` responses and is reported by
    // `/attestation`. If these ever diverge the sidecar is broken — either it
    // rotates keys mid-flight, or one of the two endpoints reads from a stale
    // cache.
    expect(att.pubkey).toBe(callResp.verification.pubkeyHex);
  });

  it("multiple consecutive calls each produce fresh signatures", async () => {
    const a = await client.call<string>("eth_blockNumber", []);
    const b = await client.call<string>("eth_blockNumber", []);
    expect(a.verification.pubkeyHex).toBe(b.verification.pubkeyHex);
    // If this ever fires on the same signatureHex, the sidecar is broken —
    // either the timestamp is frozen or the signing key got reused with a
    // stale pre-image.
    expect(a.verification.signatureHex).not.toBe(b.verification.signatureHex);
  });
});
