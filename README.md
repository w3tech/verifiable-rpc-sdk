# @ankr/verifiable-rpc-client

TypeScript client for **ANKR verifiable RPC**: call a blockchain RPC and get back signed results — each response carries a cryptographic proof that it was produced by a specific, approved blockchain client (exact image, exact version, exact configuration) running unmodified inside a trusted execution environment. No trust in the operator, no trust in the network, no "did this node lie to me" question. The signature verifies or it doesn't.

Two ways to use it:

1. **Ethers.js provider.** Swap your `JsonRpcProvider` for one backed by `VerifierClient` and every contract read / `getBalance` / `getBlock` you already make now arrives with a verified signature — your application code doesn't change. Same idea for viem (`custom` transport) or raw `fetch` flows.
2. **Verify signatures yourself.** Import the primitives — `buildPreImage`, `fetchAttestation`, the typed error classes — and verify responses captured by your own HTTP client, off-chain pipeline, log archive, or audit script. The SDK gives you the building blocks; you decide where verification runs.

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

### Fetch a TDX attestation quote

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

- [`w3tech/verifiable-rpc-sidecar`](https://github.com/w3tech/verifiable-rpc-sidecar) — Rust sidecar that produces the signed responses + TDX attestation quotes. The SDK pairs with sidecar [`v0.1.0`](https://github.com/w3tech/verifiable-rpc-sidecar/releases/tag/v0.1.0).

## License

TBD.
