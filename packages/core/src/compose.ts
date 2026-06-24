// ComposeSource — pluggable provider of a deployment's `app_compose` text and
// its compose-hash, for Layer A verification.
//
// Layer A asks: "is the code measured into the TDX quote (`compose_hash`) the
// code I expect?" Answering it needs the expected `app_compose` text from a
// source whose authenticity you trust. This module abstracts WHERE that text
// comes from behind one interface, so the trust model is explicit per impl:
//
//   - InfoEndpointComposeSource — pulls it from the node's own `GET /info`.
//     TEMPORARY / DEV-ONLY. The node reports its OWN compose, so this is
//     self-attested and is NOT a trust anchor: a malicious node returns a
//     compose that matches its own forged quote. Useful only for
//     recompute-and-match-self sanity during development.
//   - RegistryComposeSource — pulls it from an external, node-independent
//     source (e.g. a GitHub-hosted, pinned/signed compose registry). This is
//     the real Layer A anchor: comparing the node's attested `compose_hash` to
//     a hash derived from an independently-sourced compose is meaningful
//     because the node cannot forge that source. Not yet implemented.
//
// compose_hash is ALWAYS `sha256(utf8(app_compose))` as bare lowercase hex,
// matching dstack's rule exactly — the raw file bytes are hashed verbatim,
// with no canonicalization / re-serialization.

import { bytesToHex } from "@noble/hashes/utils.js";

import { ComposeSourceNotImplemented, MalformedInfoResponse } from "./errors";
import { sha256 } from "./preimage";

/**
 * Compute the dstack compose-hash of an `app_compose` string:
 * `sha256(utf8(appCompose))` as bare lowercase hex. No canonicalization —
 * dstack hashes the raw file bytes verbatim.
 */
export function computeComposeHash(appCompose: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(appCompose)));
}

/**
 * Source of a deployment's `app_compose` text (and its compose-hash).
 *
 * The interface is trust-agnostic; each implementation documents its own trust
 * level. `getComposeHash()` MUST equal `computeComposeHash(getAppCompose())` —
 * implementations recompute locally and never trust a self-reported hash.
 */
export interface ComposeSource {
  /** The raw `app_compose` text (the verbatim `app-compose.json` content). */
  getAppCompose(): Promise<string>;
  /** `sha256(utf8(appCompose))` as bare lowercase hex. */
  getComposeHash(): Promise<string>;
}

export interface InfoEndpointComposeSourceOptions {
  /** Optional `fetch` override — primarily for tests. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * TEMPORARY / DEV-ONLY {@link ComposeSource} that pulls `app_compose` from the
 * node's own unauthenticated `GET /info` endpoint (`tcb_info.app_compose`).
 *
 * NOT A TRUST ANCHOR. `/info` is self-reported by the node under verification:
 * it can prove the node is internally consistent (its reported compose hashes
 * to its attested `compose_hash`), but it can NEVER prove authenticity — a
 * malicious node returns a compose that matches its own forged quote. Use only
 * for development / sanity checks. Production Layer A trust requires
 * {@link RegistryComposeSource}.
 */
export class InfoEndpointComposeSource implements ComposeSource {
  private readonly url: string;
  private readonly fetchImpl: typeof fetch;

  constructor(url: string, opts: InfoEndpointComposeSourceOptions = {}) {
    if (!/^https?:\/\//.test(url)) {
      throw new TypeError(
        `InfoEndpointComposeSource: url must start with http:// or https:// (got: ${url})`,
      );
    }
    this.url = url;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
  }

  async getAppCompose(): Promise<string> {
    const resp = await this.fetchImpl(`${this.url}/info`);
    const body = (await resp.json()) as unknown;
    return narrowInfoAppCompose(body);
  }

  async getComposeHash(): Promise<string> {
    return computeComposeHash(await this.getAppCompose());
  }
}

export interface RegistryComposeSourceOptions {
  /** External source the node does NOT control (e.g. a raw GitHub URL). */
  source: string;
  /** Optional pinned ref (commit / tag) for reproducibility. */
  ref?: string;
  /** Optional expected compose-hash to assert the fetched compose against. */
  expectedComposeHash?: string;
  /** Optional `fetch` override — primarily for tests. */
  fetch?: typeof fetch;
}

/**
 * FUTURE Layer A trust anchor: fetches the expected `app_compose` from an
 * external, node-independent source (e.g. a GitHub-hosted, pinned/signed
 * compose registry) so the node's attested `compose_hash` can be checked
 * against a hash derived from a source the node cannot forge.
 *
 * Not yet implemented — tracked by the compose-hash registry anchor work
 * (append-only signed shape locked, storage open). Both methods reject with
 * {@link ComposeSourceNotImplemented} until the registry lands.
 */
export class RegistryComposeSource implements ComposeSource {
  constructor(private readonly opts: RegistryComposeSourceOptions) {}

  async getAppCompose(): Promise<string> {
    throw new ComposeSourceNotImplemented(
      `RegistryComposeSource(source=${this.opts.source}) is not implemented yet`,
    );
  }

  async getComposeHash(): Promise<string> {
    throw new ComposeSourceNotImplemented(
      `RegistryComposeSource(source=${this.opts.source}) is not implemented yet`,
    );
  }
}

/**
 * Defensive narrowing of a `GET /info` body to its `tcb_info.app_compose`
 * string. Reports a field-path reason on any missing/wrong-typed field.
 */
function narrowInfoAppCompose(body: unknown): string {
  if (body === null || typeof body !== "object") {
    throw new MalformedInfoResponse("response is not a JSON object");
  }
  const obj = body as Record<string, unknown>;
  if (obj.tcb_info === null || typeof obj.tcb_info !== "object") {
    throw new MalformedInfoResponse(
      "tcb_info" in obj ? "tcb_info must be an object" : "missing field: tcb_info",
    );
  }
  const tcb = obj.tcb_info as Record<string, unknown>;
  if (typeof tcb.app_compose !== "string") {
    throw new MalformedInfoResponse(
      "app_compose" in tcb
        ? "tcb_info.app_compose must be string"
        : "missing field: tcb_info.app_compose",
    );
  }
  return tcb.app_compose;
}
