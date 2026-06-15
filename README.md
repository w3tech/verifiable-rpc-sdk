# @ankr/verifiable-rpc-client

TypeScript client for **ANKR verifiable RPC**: call a blockchain RPC and get back signed results — each response carries a cryptographic proof that it was produced by a specific, approved blockchain client (exact image, exact version, exact configuration) running unmodified inside a trusted execution environment. No trust in the operator, no trust in the network, no "did this node lie to me" question. The signature verifies or it doesn't.

Two ways to use it:

1. **Ethers.js provider.** Swap your `JsonRpcProvider` for one backed by `VerifierClient` and every contract read / `getBalance` / `getBlock` you already make now arrives with a verified signature — your application code doesn't change. Same idea for viem (`custom` transport) or raw `fetch` flows.
2. **Verify signatures yourself.** Import the primitives — `buildPreImage`, `fetchAttestation`, the typed error classes — and verify responses captured by your own HTTP client, off-chain pipeline, log archive, or audit script. The SDK gives you the building blocks; you decide where verification runs.

---

## What is verified / What is NOT verified

Read this before you rely on the signature for anything. The trust boundary this SDK enforces today is **narrower** than full remote attestation, and being honest about the gap is a hard requirement — overclaiming would give you false confidence.

### What IS verified

For every **HTTP JSON-RPC** response that reaches your code (`getBalance`, `call`, `getBlock`, `getLogs`, batch results — everything that funnels through the adapter's single HTTP chokepoint), the SDK enforces, fail-closed, that the response is:

- **Signed** — the `vRPC-Signature` is a valid Ed25519 signature, and
- **Untampered** — it verifies over the canonical 80-byte pre-image `chain_id ‖ sha256(request_body) ‖ sha256(response_body) ‖ timestamp_ms`, so any mutation of the request OR the response body (in transit, by the proxy, anywhere) fails as `BadSignature`, and
- **Fresh** — the `vRPC-Timestamp` is inside the replay window (default 60s), so a captured-and-replayed old response is rejected as `StaleTimestamp`, and
- **Correctly bound** — against the **chain id you pinned** (a wrong/substituted chain binds a different pre-image → `BadSignature`) and against the **signing key** that produced the signature. In the recommended shark-only flow you additionally correlate that signing key against the serving node's attestation pubkey (`anchorTrust` / `verifyAttestationCorrelation`), and against the **pinned compose-hash** when you supply one.

A response that fails any of these never reaches your application code in the default `strict` mode — the typed `VerificationError` is thrown instead.

### What is NOT verified

- **Full TDX remote attestation is NOT performed.** The SDK fetches and *parses* the TDX quote (`Attestation.quote.quote` is the raw TD report + PCK cert chain) but it does **not** cryptographically verify that quote against the **Intel PCK root**, nor decode/check MRTD / RTMR / TCB level. **A forged quote would pass at this boundary** (a forged TDX quote is not detected) — the SDK does not yet prove the quote chains to an Intel root. Full quote verification is **deferred to the next milestone**.
- **The composeHash registry anchor is NOT delivered.** Going from a quote's `composeHash` to "this is the exact image/code I trust" needs an **independent, pinned/signed registry** the node cannot forge (`RegistryComposeSource`). That registry does not exist yet (`RegistryComposeSource` throws `ComposeSourceNotImplemented`; `InfoEndpointComposeSource` is dev-only and self-reported — NOT a trust anchor). Also **deferred to the next milestone** (C4 / DEC-03).
- **WebSocket push streams are NOT verified.** `eth_subscribe` / WS push bypasses the HTTP signing chokepoint — the sidecar signs HTTP responses only. WS is unverified; use HTTP for anything you need a signature on.
- **ENS off-chain reads are NOT verified.** ENS CCIP-Read, avatar, and IPFS resolution fetch data from **off-chain gateways** outside the signed RPC path. Those bytes are unverified even when the on-chain RPC legs around them are signed.

In short: **verifiable here means signed + untampered + fresh + correctly bound, replay-checked — NOT full TDX quote attestation.** Treat the signature as proof that *a key you correlated* produced *exactly these bytes* — not yet as proof of *which enclave image* holds that key. That last step is the deferred registry/attestation work.

---

## Install

```bash
# npm
npm install @ankr/verifiable-rpc-client

# pnpm
pnpm add @ankr/verifiable-rpc-client

# bun
bun add @ankr/verifiable-rpc-client

# yarn
yarn add @ankr/verifiable-rpc-client
```

> The package is currently `private: true` in this repo while the API stabilises; publishing to npm is tracked as a follow-up. Until then install directly from a git ref:
>
> ```bash
> npm install github:w3tech/verifiable-rpc-sdk
> ```

---

## Quick start

```ts
import { VerifierClient } from "@ankr/verifiable-rpc-client";

// Before — plain ethers provider, no verification:
// import { JsonRpcProvider } from "ethers";
// const client = new JsonRpcProvider("https://your-sidecar.example", 1);

// After — same URL + chain id, every response now signature-checked:
const client = new VerifierClient("https://your-sidecar.example", {
  chainId: 1n,                  // EVM chain id, as bigint
  replayWindowMs: 60_000,       // optional — default 60s
});

const block = await client.call<string>("eth_blockNumber", []);

console.log(block.result);                  // "0x1234..."
console.log(block.verification.pubkeyHex);  // "0x<32-byte ed25519 pubkey>"
console.log(block.verification.timestampMs);// 1_700_000_000_000n
```

`block.result` is the JSON-RPC `result` field, already type-narrowed by the generic parameter. If the signature fails to verify, or the timestamp is outside the replay window, or a required header is missing, `call` throws a typed error — see [Error handling](#error-handling).

### Recommended integration path — shark-only flow

The default way to consume verifiable RPC in production is **entirely through the shark proxy**: shark is the only client-facing URL. You make a signed call, read the serving node's id off the response, then fetch *that* node's attestation back through shark and correlate it against the response pubkey.

```ts
import {
  VerifierClient,
  fetchAttestationViaShark,
  verifyAttestationCorrelation,
  AttestationNodeNotFoundError,
} from "@ankr/verifiable-rpc-client";

const sharkBase = "https://rpc.ankr.com"; // shark proxy base — the only client-facing URL
const chain = "arbitrum";                  // <chain>_vrpc route segment

// 1. Signed call through shark. A successful return IS the Ed25519 verification.
const client = new VerifierClient(`${sharkBase}/${chain}_vrpc`, { chainId: 42161n, apiKey });
const r = await client.call<string>("eth_blockNumber", []);

// 2. Read the serving node's id and the pubkey to correlate against.
const nodeId = r.nodeId;                       // from the vRPC-NodeId response header
const expectedPubkey = r.verification.pubkeyHex;

// 3. Fetch THAT node's attestation back through shark, with a fresh 32-byte nonce.
const nonce = crypto.getRandomValues(new Uint8Array(32));
const attestation = await fetchAttestationViaShark({ sharkBase, chain, nodeId, nonce, apiKey });

// 4. Correlate: throws AttestationCorrelationError unless attestation.pubkey === vRPC-Pubkey.
verifyAttestationCorrelation(attestation, r);
```

**Why the `node_id` hop needs no trust.** Routing the attestation request by `node_id` does not require trusting shark's routing: `verifyAttestationCorrelation` enforces `attestation.pubkey === vRPC-Pubkey`, so a wrong or substituted node can only *fail* the correlation — it can never spoof a pubkey it doesn't hold the signing key for.

**No-fallback 404 semantics.** A stale or unknown `node_id` returns `404` and throws `AttestationNodeNotFoundError` — the SDK does **not** retry or fall back to another node. Treat it as "re-issue the RPC call to get a fresh `nodeId`", not as a transient error to retry against the same id.

`examples/07-attestation-via-shark.ts` runs this full loop (plus the typed-404 negative path) against the live stage shark.

### Fetch a TDX attestation quote DIRECT from a node (debugging only)

> **Not the recommended client path.** Hitting a node's `/attestation` directly bypasses shark and the `node_id` correlation hop. Use it only for local sidecar debugging or when you already hold a node's direct URL; production integrations should use the shark-only flow above.

```ts
const nonce = crypto.getRandomValues(new Uint8Array(32));
const attestation = await client.fetchAttestation(nonce);

console.log(attestation.pubkey);             // "0x<same pubkey as on signed responses>"
console.log(attestation.composeHash);        // "<app-compose.json content hash>"
console.log(attestation.quote.quote);        // bare hex — the raw TDX quote
console.log(attestation.quote.event_log);    // bare hex — runtime event log
console.log(attestation.quote.report_data);  // bare hex — REPORTDATA = pubkey ‖ nonce
```

`fetchAttestation` does **not** verify the TDX quote bytes themselves — only parses them. To go from the quote to "yes, this is the image I trust" you also need a compose-hash registry; that piece is tracked as separate work and is not in this SDK.

### Resolve the expected compose (`ComposeSource`)

Going from a quote's `composeHash` to "this is the code I trust" (Layer A) means comparing it against the `app_compose` you *expect*, fetched from a source you trust. `ComposeSource` abstracts where that expected `app_compose` comes from:

```ts
import { InfoEndpointComposeSource, computeComposeHash } from "@ankr/verifiable-rpc-client";

// DEV-ONLY: pull the node's self-reported compose from GET /info.
const dev = new InfoEndpointComposeSource(sidecarUrl);
const appCompose = await dev.getAppCompose(); // verbatim app-compose.json text
const hash = await dev.getComposeHash();      // sha256(utf8(appCompose)), bare hex
```

`computeComposeHash(text)` is `sha256(utf8(text))` as bare lowercase hex — dstack's exact rule, no canonicalization.

**Trust model — read this.** `InfoEndpointComposeSource` is **dev-only and NOT a trust anchor**: `/info` is self-reported by the node under verification, so it can only prove the node is *internally consistent* (its reported compose hashes to its attested `composeHash`) — never that the compose is *authentic*. A malicious node returns a compose that matches its own forged quote.

Real Layer A trust needs an **independent** source the node cannot forge — a pinned/signed external compose registry (e.g. GitHub). That is `RegistryComposeSource`, which currently throws `ComposeSourceNotImplemented` pending the registry (DEC-03).

---

## Integrating with ethers v6

The SDK doesn't ship an `ethers` adapter, but `ethers.FetchRequest.registerGetUrl` makes wrapping it a few lines:

```ts
import { ethers } from "ethers";
import { VerifierClient, type VerifiedResponse } from "@ankr/verifiable-rpc-client";

function makeVerifiedProvider(sidecarUrl: string, chainId: bigint) {
  const client = new VerifierClient(sidecarUrl, { chainId });

  // ethers parses JSON-RPC for us; we just need to intercept the raw POST,
  // run it through the verifier, and hand the original body back.
  const provider = new ethers.JsonRpcProvider(sidecarUrl, Number(chainId), {
    batchMaxCount: 1,           // disable batching — VerifierClient signs per-call
    staticNetwork: true,
  });

  // Override the transport so the verifier sees every request.
  provider._send = async (payload) => {
    const calls = Array.isArray(payload) ? payload : [payload];
    return Promise.all(
      calls.map(async (req) => {
        const verified: VerifiedResponse<unknown> = await client.call(
          req.method,
          (req.params as unknown[]) ?? [],
        );
        return { jsonrpc: "2.0", id: req.id, result: verified.result };
      }),
    );
  };

  return provider;
}

const provider = makeVerifiedProvider("https://your-sidecar.example", 1n);
const balance = await provider.getBalance("0x000…");
```

Every `provider.*` call now goes through `VerifierClient.call` underneath — ethers sees a normal `JsonRpcProvider`, you get cryptographic proof that the result came from the enclave.

A similar pattern works for **viem** via `custom` transport: wrap `client.call` in a function that matches viem's `Transport` signature and pass it to `createPublicClient`.

---

## Lower level: verify responses yourself

If you'd rather drive HTTP with your own client and only borrow the verification primitives:

```ts
import { buildPreImage, BadSignature, MissingHeader } from "@ankr/verifiable-rpc-client";
import { verifyAsync } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";

async function verifyResponse(
  chainId: bigint,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
  headers: Headers,
): Promise<void> {
  const sigHex = headers.get("vRPC-Signature");
  const pubkeyHex = headers.get("vRPC-Pubkey");
  const timestampMs = headers.get("vRPC-Timestamp");
  if (!sigHex || !pubkeyHex || !timestampMs) {
    throw new MissingHeader(!sigHex ? "vRPC-Signature" : !pubkeyHex ? "vRPC-Pubkey" : "vRPC-Timestamp");
  }

  const preImage = buildPreImage(chainId, requestBody, responseBody, BigInt(timestampMs));

  const sig = hexToBytes(sigHex.slice(2));
  const pubkey = hexToBytes(pubkeyHex.slice(2));
  const ok = await verifyAsync(sig, preImage, pubkey);

  if (!ok) {
    throw new BadSignature({
      signatureHex: sigHex,
      pubkeyHex,
      preImageSha256: sha256(preImage),
    });
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
```

This gives you exactly what `VerifierClient.call` does internally, minus the JSON-RPC envelope and replay window. Useful if you want to verify responses captured offline, or wire the verifier into a non-HTTP transport.

The pre-image layout is fixed: `chain_id (8B LE) || sha256(request_body) (32B) || sha256(response_body) (32B) || timestamp_ms (8B LE)` — 80 bytes total. The Rust sidecar produces byte-identical output and the SDK's `tests/preimage.test.ts` pins this against a known vector.

### Transport encoding (gzip vs identity)

Sidecar **v0.2.0** signs the content-decoded (plaintext) body, so the signature verifies whether the client requested `gzip` or `identity` — the `response_body` leg of the pre-image is the decoded JSON, not the compressed wire bytes. A standard auto-decoding HTTP client (Bun/Node `fetch`, ethers, viem) therefore verifies on either path with no special handling: it gunzips before you hash. `examples/05-gzip-transport.ts` proves this against the live node — the signature verifies over the decoded body and the negative control over the compressed bytes fails.

`VerifierClient` still pins `accept-encoding: identity` as **defense-in-depth** (it keeps the hashed bytes byte-identical to the wire bytes and avoids relying on the proxy's re-encoding), but correctness no longer depends on it. If you drive `fetch` yourself with `accept-encoding: gzip`, hash the decoded body.

---

## Error handling

Every failure is a typed subclass of `VerificationError`:

| Class | When |
|-------|------|
| `MissingHeader` | A required `vRPC-*` header is absent on a signed response |
| `MalformedHeader` | A header is present but wrong shape (bad hex, wrong length, non-numeric timestamp) |
| `BadSignature` | Ed25519 verification failed — the response body, headers, or pubkey don't match the signature |
| `StaleTimestamp` | The `vRPC-Timestamp` is outside the client's replay window (skew attached for debugging) |
| `InvalidNonce` | `fetchAttestation` called with a nonce that isn't exactly 32 bytes |
| `MalformedAttestationResponse` | The `/attestation` body is missing required fields or has the wrong shape |

All six extend `VerificationError`, which extends `Error`. Each carries a discriminator `kind` field for exhaustive switching:

```ts
import { VerificationError } from "@ankr/verifiable-rpc-client";

try {
  const r = await client.call("eth_blockNumber", []);
} catch (err) {
  if (err instanceof VerificationError) {
    switch (err.kind) {
      case "BadSignature":     /* attested upstream lied or wire mangled */ break;
      case "StaleTimestamp":   /* clock skew — check your system clock */    break;
      case "MissingHeader":    /* sidecar didn't sign the response — misconfigured? */ break;
      case "MalformedHeader":  /* version mismatch between sidecar and SDK */ break;
      // ...
    }
  } else {
    throw err;  // network errors, JSON parse errors, etc.
  }
}
```

---

## API surface

```ts
// High-level client
class VerifierClient {
  constructor(url: string, opts: { chainId: bigint; replayWindowMs?: number; fetch?: typeof fetch });
  call<T = unknown>(method: string, params: unknown[]): Promise<VerifiedResponse<T>>;
  fetchAttestation(nonce: Uint8Array): Promise<Attestation>;
}

interface VerifiedResponse<T> {
  result: T;
  raw: { request: Uint8Array; response: Uint8Array };
  verification: {
    signatureHex: string;       // 0x + 128 hex
    pubkeyHex: string;          // 0x + 64 hex
    timestampMs: bigint;
    preImageSha256: Uint8Array; // 32 bytes
  };
}

interface Attestation {
  quote: GetQuoteResponse;   // { quote, event_log, report_data, vm_config } — bare hex
  pubkey: string;             // 0x + 64 hex
  composeHash: string;        // app-compose.json content hash
}

// Standalone helpers
function fetchAttestation(sidecarUrl: string, nonce: Uint8Array): Promise<Attestation>;
function buildPreImage(
  chainId: bigint,
  requestBody: Uint8Array,
  responseBody: Uint8Array,
  timestampMs: bigint,
): Uint8Array;  // exactly 80 bytes

// Error classes
class VerificationError extends Error { readonly kind: "MissingHeader" | "MalformedHeader" | "BadSignature" | "StaleTimestamp" | "InvalidNonce" | "MalformedAttestationResponse"; }
class MissingHeader extends VerificationError { headerName: string; }
class MalformedHeader extends VerificationError { headerName: string; value: string; reason: string; }
class BadSignature extends VerificationError { signatureHex: string; pubkeyHex: string; preImageSha256: Uint8Array; }
class StaleTimestamp extends VerificationError { observedMs: bigint; nowMs: bigint; skewMs: bigint; allowedWindowMs: number; }
class InvalidNonce extends VerificationError { reason: string; }
class MalformedAttestationResponse extends VerificationError { reason: string; }
```

---

## Development

Local development uses Bun:

```bash
bun install
bun test          # unit tests (38 tests, no external deps)
bun run typecheck # tsc --noEmit
bun run lint      # biome check
```

Integration tests require a built sidecar binary + the Phala dstack simulator — see [`AGENTS.md`](./AGENTS.md) for the env vars.

---

## Companion repo

- [`w3tech/verifiable-rpc-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar) — Rust sidecar that produces the signed responses + TDX attestation quotes. The SDK pairs with sidecar `v0.2.0` (signature over the content-decoded body; the `v0.1.0` wire contract is forward-compatible on the identity path).

## License

TBD.
