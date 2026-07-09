// Integration tests for `fetchAttestation` against a live sidecar + dstack
// simulator. Captures and diff-checks the canonical wire fixture at
// `tests/fixtures/attestation-v0.1.0.json`.

import { promises as fs } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { fetchAttestation } from "../../src/index";
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

const d = integrationEnabled ? describe : describe.skip;

d("integration: attestation", () => {
  let simulator: SimulatorHandle | undefined;
  let upstream: MockUpstreamHandle | undefined;
  let sidecar: SidecarHandle | undefined;

  beforeAll(async () => {
    simulator = await spawnSimulator();
    // `/attestation` does not hit the upstream, but the sidecar still requires
    // `--upstream-url` to start, so spawn a mock and pass its URL.
    upstream = await spawnMockUpstream();
    sidecar = await spawnSidecar(simulator.socketPath, upstream.url, "1");
  });

  afterAll(async () => {
    await cleanup([sidecar, upstream, simulator]);
  });

  it("fetchAttestation returns a parseable Attestation against a live simulator-backed sidecar", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const nonce = new Uint8Array(32).fill(0x01);
    const att = await fetchAttestation({ attestationUrl: `${sidecar.url}/attestation`, nonce });

    expect(att.pubkey).toBe(sidecar.pubkeyHex);
    expect(att.quote.quote.length).toBeGreaterThan(0);
    expect(/^[0-9a-f]+$/i.test(att.quote.quote)).toBe(true);
    expect(typeof att.quote.event_log).toBe("string");
    expect(att.quote.report_data.length).toBeGreaterThan(0);
    expect(/^[0-9a-f]+$/i.test(att.quote.report_data)).toBe(true);
    expect(typeof att.quote.vm_config).toBe("string");
    // composeHash may be empty under the simulator + SIDECAR_ALLOW_EMPTY_COMPOSE_HASH.
    expect(typeof att.composeHash).toBe("string");
  });

  it("different nonces produce different quote.quote bytes but the same pubkey", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const n1 = new Uint8Array(32).fill(0xaa);
    const n2 = new Uint8Array(32).fill(0xbb);
    const a1 = await fetchAttestation({ attestationUrl: `${sidecar.url}/attestation`, nonce: n1 });
    const a2 = await fetchAttestation({ attestationUrl: `${sidecar.url}/attestation`, nonce: n2 });

    expect(a1.pubkey).toBe(a2.pubkey);
    // The nonce flows into REPORTDATA → quote bytes differ per nonce.
    expect(a1.quote.quote).not.toBe(a2.quote.quote);
    expect(a1.quote.report_data).not.toBe(a2.quote.report_data);
  });

  it("captures the canonical attestation-v0.1.0.json fixture", async () => {
    if (!sidecar) throw new Error("sidecar not initialised");

    const fixturesDir = join(import.meta.dirname, "..", "fixtures");
    const fixturePath = join(fixturesDir, "attestation-v0.1.0.json");

    const nonce = new Uint8Array(32); // canonical all-zero nonce
    const att = await fetchAttestation({ attestationUrl: `${sidecar.url}/attestation`, nonce });

    const exists = await fs
      .access(fixturePath)
      .then(() => true)
      .catch(() => false);

    if (!exists) {
      await fs.mkdir(fixturesDir, { recursive: true });
      await fs.writeFile(fixturePath, `${JSON.stringify(att, null, 2)}\n`);
      throw new Error(
        `Wrote new fixture to ${fixturePath} — review and re-run the test to commit it.`,
      );
    }

    const saved = JSON.parse(await fs.readFile(fixturePath, "utf8")) as {
      pubkey: string;
      composeHash: string;
      quote: {
        quote: string;
        event_log: string;
        report_data: string;
        vm_config: string;
      };
    };

    // Top-level key set is fixed.
    expect(Object.keys(saved).sort()).toEqual(["composeHash", "pubkey", "quote"]);

    // pubkey stable across runs against the same simulator/key path.
    if (saved.pubkey !== att.pubkey) {
      throw new Error(`fixture mismatch at $.pubkey: saved=${saved.pubkey} live=${att.pubkey}`);
    }

    // composeHash stable under same simulator config (typically "").
    if (saved.composeHash !== att.composeHash) {
      throw new Error(
        `fixture mismatch at $.composeHash: saved=${saved.composeHash} live=${att.composeHash}`,
      );
    }

    // vm_config stable (typically "" under simulator).
    if (saved.quote.vm_config !== att.quote.vm_config) {
      throw new Error(
        `fixture mismatch at $.quote.vm_config: saved=${saved.quote.vm_config} live=${att.quote.vm_config}`,
      );
    }

    // quote.quote is nonce-bound: bytes may drift, but length must match.
    expect(typeof saved.quote.quote).toBe("string");
    if (saved.quote.quote.length !== att.quote.quote.length) {
      throw new Error(
        `fixture mismatch at $.quote.quote: saved.length=${saved.quote.quote.length} live.length=${att.quote.quote.length}`,
      );
    }

    expect(typeof saved.quote.event_log).toBe("string");
    expect(typeof saved.quote.report_data).toBe("string");
  });
});
