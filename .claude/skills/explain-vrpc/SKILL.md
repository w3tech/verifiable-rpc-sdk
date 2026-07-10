---
name: explain-vrpc
description: >-
  Explain Ankr's verifiable RPC (vRPC) to a user: what it is and why it exists,
  Intel TDX and Phala dstack, the attestation sidecar and what its /attestation
  endpoint returns, the trust model (why a client need not trust Ankr),
  and how this SDK (vrpc-core + the verifier) checks a response. Use when a user
  asks what vRPC / verifiable RPC is, how response verification works, what the
  sidecar returns, what Intel TDX or Phala dstack are, or how to verify a vRPC
  response. Agent-facing knowledge: relay it in plain language, cite the linked
  sources, and never invent facts.
allowed-tools:
  - Read
  - Grep
  - WebFetch
---

# Explain vRPC (verifiable RPC)

## How to use this skill (read first — you are an agent, not the end reader)

This file is written for **you, the agent**. The human asking is usually
non-expert. Your job: read the relevant section below, then explain it to the
user in plain language at the depth they asked for.

Rules:

- **Do not invent.** Every claim here is grounded either in this repo's code
  (paths like `packages/core/src/verify.ts`) or in an official external source
  (the **Sources** section). If the user pushes past what is written here, fetch
  a cited source with `WebFetch` or `Read` the named file — do not guess.
- **Cite when it helps.** Offer the user the official links (Intel TDX, Phala
  dstack) when they want to go deeper.
- **Be honest about maturity.** vRPC's signing/verification path is real and
  fail-closed today; verification of the full attestation chain of trust is still
  in development. Say so plainly if asked, but lead with what works, not with
  caveats.
- **Verify before you assert repo specifics.** Header names, byte layouts, and
  verification steps below are exact as of this branch; if a user needs to act
  on them, confirm against the cited file.

Repos: SDK = `github.com/w3tech/verifiable-rpc-sdk` (this repo). Sidecar =
`github.com/w3tech/verifiable-rpc-sidecar`.

---

## 1. What vRPC is, and why · Intel TDX · Phala dstack

**vRPC (verifiable RPC)** makes every JSON-RPC response carry a cryptographic
proof that it came from an **approved, unmodified blockchain node running inside
a hardware enclave**, and was not altered in transit. The client checks that
proof on every response and **fails closed** — if the proof is missing or wrong,
the call throws and no unverified data is returned. (SDK `README.md`; engine
`packages/core/README.md`.)

Why it exists: normally an RPC user has to *trust the provider* to return honest
chain data. vRPC removes that trust requirement — see §3.

**Intel TDX (Trust Domain Extensions)** is Intel's CPU-level Trusted Execution
Environment (TEE). It runs a VM (a "trust domain") in hardware-isolated, encrypted
memory that the host OS/hypervisor cannot read or tamper with, and it can produce
a hardware-signed **attestation quote** measuring exactly what code is running.
This is the hardware root of trust under vRPC. (Official: Intel TDX overview —
see Sources.)

**Phala dstack** is an open framework that runs ordinary container workloads
inside Intel TDX confidential VMs and exposes the TDX attestation + key-management
plumbing to the app (quotes, measurement registers RTMR0–3, a per-app derived key,
the `app-compose` deployment manifest). vRPC's node runs as a dstack app; the
sidecar (§2) talks to dstack to get its signing key and attestation quotes.
Production runs on real Intel TDX hardware via dstack; local development uses the
**dstack simulator**, which exposes the same socket interface. (Sidecar
`README.md`; dstack docs — see Sources.)

---

## 2. The sidecar — how it works and what it returns

The **sidecar** (`verifiable-rpc-sidecar`, a Rust service in a separate repo; this
SDK targets its `v0.5.0` wire contract — SDK `>=0.3.0` requires sidecar
`>=0.5.0`) sits
in front of the real blockchain node's HTTP endpoint **inside the TDX confidential
VM**. It proxies RPC traffic and signs every response with a TDX-attested key.
It listens on plain HTTP. (`src/config.rs`, `src/server.rs`.)

### Per-response signing (the proxy path)

For every proxied RPC response, the sidecar adds three headers
(`src/proxy.rs:211-213`):

- **`vRPC-Signature`** — `0x` + 64-byte **Ed25519** signature.
- **`vRPC-Pubkey`** — `0x` + 32-byte Ed25519 verifying key.
- **`vRPC-Timestamp`** — Unix milliseconds when the sidecar signed.

The signature is over a **104-byte canonical pre-image** (`src/signing.rs`):

| bytes   | content                              |
|---------|--------------------------------------|
| `[0..32]`   | `sha256(utf8(chain_id))` (32 bytes) |
| `[32..64]`  | `sha256(request_body)` (32 bytes)  |
| `[64..96]`  | `sha256(response_body)` (32 bytes) |
| `[96..104]` | `timestamp_ms` (u64, little-endian)|

The `chain_id` is a **string** — the exact value the sidecar is configured with
(decimal for EVM chains, e.g. `"42161"`; the exact configured string for non-EVM
chains, e.g. TON's global id `"-239"` or Stellar's network id — the sha256 of its
mainnet passphrase, a 64-char hex string).

The signature covers the **content-decoded (plaintext)** response body: the
sidecar forces `Accept-Encoding: identity` upstream to get plaintext, signs that,
then re-compresses for the client. So the signature verifies whether the client
asked for gzip or identity. The request body is forwarded byte-for-byte, never
mutated. (`src/proxy.rs`, sidecar `README.md`.)

The signing key is an **Ed25519** key derived from dstack at boot; it is the key
whose pubkey ends up bound into the attestation quote. (`src/main.rs`,
`src/signing.rs`.)

### `GET /attestation?nonce=<hex>`

Caller supplies a fresh 32-byte `nonce` (hex, with or without `0x`). The sidecar
asks dstack for a **fresh** TDX quote bound to that nonce (no quote caching) and
returns JSON (`src/attestation.rs`):

- **`quote`** — the TDX quote object (`quote`, `event_log`, `report_data`,
  `vm_config` as bare hex).
- **`pubkey`** — `0x` + 32-byte Ed25519 key (the same key that signs responses).
- **`composeHash`** — sha256 digest of `app_compose`.
- **`app_compose`** — the **raw verbatim `app-compose.json` text** (the *preimage*
  of `composeHash`).

Inside the quote, **`report_data` is 64 bytes**: `[0:32]` = the signing **pubkey**,
`[32:64]` = the caller's **nonce** (`src/attestation.rs`). This is what binds the
signing key and freshness into hardware. Missing/malformed nonce → `400`. The
`/attestation` endpoint carries **no** `vRPC-*` headers (it is not proxied RPC).

Key relationship (raw bytes, **no canonicalization** — dstack hashes verbatim):

```
sha256(utf8(app_compose)) == composeHash
```

> **Nonce freshness is the caller's responsibility.** The sidecar does not police
> reused nonces; the SDK generates a fresh random 32-byte nonce per attestation
> fetch (§4) so a man-in-the-middle cannot replay an old quote.

---

## 3. Trust model — why you need not trust Ankr

Ankr is a blockchain RPC provider: it proxies client requests across **many
backend nodes** (load-balanced, multi-region). Normally that means the client
must *trust Ankr* to (a) route to an honest node and (b) not alter the response.

vRPC **moves the trust boundary off Ankr and onto the node + dstack + Intel TDX
hardware.** The response is signed *inside* the TDX enclave by a key that exists
only there; the proof travels with the response. The client verifies it locally.
Concretely, a verified response proves it was produced by a **specific, approved,
unmodified upstream image** running in a genuine TDX TEE — regardless of how many
proxy hops (Ankr's included) it passed through. A compromised, mis-routed, or
man-in-the-middle node cannot forge a valid signature, because it does not hold
the enclave's key. (Sidecar `README.md`; SDK `README.md`.)

So: **you don't have to trust the operator; you verify the math.** The operator
becomes untrusted infrastructure.

**Honest scope of the trust shift (today).** The per-response signature +
freshness + chain binding are fully enforced and fail-closed (§4), and the node's
claimed `app_compose` is checked against its `compose_hash`. Verification of the
**full attestation chain of trust** is still in development — see Phala's
[chain-of-trust guide](https://docs.phala.com/phala-cloud/attestation/chain-of-trust)
for the complete set of links a TDX deployment can prove. Lead with the
guarantee; mention the in-development scope only if the user asks how far the
proof goes.

---

## 4. The SDK — what it does, core + verifier, and how to verify a response

### What it is

A TypeScript SDK that connects to the vRPC API and verifies the proof on every
response **for you**. It's a one-line drop-in: replace your ethers or viem client
with the vRPC client and every call keeps working — now verified, fail-closed,
over the exact node-signed bytes, before you ever see the data. Packages
(`@w3tech.io/*`):

- **`vrpc-core`** — transport-agnostic Ed25519 verification engine (no
  blockchain-client deps; lightweight crypto via `@noble/ed25519` + `@noble/hashes`,
  plus `lru-cache` and the internal `@w3tech.io/dstack-verify` module). Owns the
  pre-image, signature check, replay window, attestation fetch/correlation, and
  the typed error family.
- **`vrpc-ethers`** — `VrpcProvider`, an ethers v6 `JsonRpcProvider` drop-in that
  verifies each response in `_send` before `JSON.parse`.
- **`vrpc-viem`** — `vrpcHttp()`, a verifiable drop-in for viem's `http()`
  transport.
- **`dstack-verify`** — the dstack/TDX attestation-verification module.

The user passes **one URL** (e.g. `https://rpc.ankr.com/<chain>`); the SDK derives
the RPC leg (`_vrpc`) and attestation leg (`_vrpc/attestation`) itself via
`deriveVrpcUrls()` — no separate base URL/slug to configure
(`packages/core/src/vrpc-url.ts`).

### How `core` + the verifier work (the order matters)

`vrpc-core`'s `verifyResponse()` does the per-response crypto
(`packages/core/src/verify.ts`, `preimage.ts`):

1. Read headers `vRPC-Signature`, `vRPC-Pubkey`, `vRPC-Timestamp`
   (+ optional `vRPC-NodeId`); missing → `MissingHeader`.
2. Validate shapes (`signature` `0x`+128 hex, `pubkey` `0x`+64 hex, timestamp
   decimal); malformed → `MalformedHeader`.
3. Rebuild the **same 104-byte pre-image** the sidecar signed (§2 table).
4. Ed25519-verify the signature over that pre-image (`@noble/ed25519`); fail →
   `BadSignature`.
5. Check `vRPC-Timestamp` is inside the replay window — done *after* signature
   verify, so a tampered timestamp fails at the crypto layer; stale →
   `StaleTimestamp`.

`TrustedVerifier.verify()` wraps that and adds attestation + key trust, in order
(`packages/core/src/trusted-verifier.ts`):

1. `verifyResponse()` (the Ed25519 check above).
2. If the signer pubkey is already in the verified cache and still fresh → return
   (skip re-attestation).
3. Read the `nodeId` from the response (`vRPC-NodeId`) — present and required to
   route the fetch when reached via Ankr's multi-node proxy; absent for a single
   direct node.
4. Generate a fresh random 32-byte nonce.
5. `fetchAttestation()` → `GET /attestation?nonce=<bare-hex>[&node_id=<id>]`.
6. **Correlation:** assert the attestation's `pubkey` equals the response signer's
   pubkey (the attested key actually signed your data).
7. Map to an `AttestationBundle` (incl. the node's `app_compose`) + build the
   policy.
8. `verifyDstackAttestation(bundle, policy)` (see below).
9. Cache the pubkey **only after** verification resolves (fail-closed), for a
   bounded time, so later responses from the same key skip re-attestation.

`dstack-verify`'s `verifyDstackAttestation(bundle, policy): Promise<void>` —
resolves on success, throws `AttestationError(chkId, detail)` on failure
(`packages/dstack-verify/src/verify.ts`):

- **CHK-A1 (real, unconditional):** `report_data[0:32] == expectedPubkey` (binds
  the signing key — defeats swapped-key / wrong-node) **and**
  `report_data[32:64] == expectedNonce` (freshness / anti-replay). Runs first,
  unconditionally.
- **CHK-A2 (real):** verifies the node's claimed `app_compose` against its
  `compose_hash` (`sha256(utf8(app_compose)) == compose_hash`).

Verification of the **full attestation chain of trust** inside this SDK is still
in development. See Phala's
[chain-of-trust guide](https://docs.phala.com/phala-cloud/attestation/chain-of-trust)
for the complete set of links a TDX deployment can prove.

This is not a data gap — the sidecar already returns the raw TDX quote (plus the
event log), so the full chain **can be verified today** with an independent tool.
Phala ships a standalone **dstack-verifier** (an HTTP service + CLI that does DCAP
quote verification, event-log / RTMR replay, OS-image and compose-hash checks);
run it against the sidecar's quote rather than waiting on this SDK's verifier:
<https://github.com/Dstack-TEE/dstack/tree/master/verifier>.

**Maturity (state plainly only if asked, don't dwell):** the signing/verification
path (Ed25519 signature, freshness, chain binding, key correlation, CHK-A1, CHK-A2)
is implemented and fail-closed today. Together with the mandatory, always-on cloud
hardware-signature check (a `HardwareVerifier` that delegates the quote verdict to Phala's hosted endpoint
and binds it to the signer + compose hash), this implements the **minimal end-to-end
verification** flow of Phala's
[verification guide](https://docs.phala.com/phala-cloud/attestation/verification-guide).
Verification of the **full attestation chain of trust** is still in development — the SDK
is working toward it (local DCAP quote verification, RTMR replay, TCB-status policy; see
the chain-of-trust guide, linked in §3 and Sources). (SDK `README.md`,
`packages/core/README.md`, `packages/dstack-verify/README.md`.)

**vRPC does NOT work over WebSocket.** The adapters and the whole verified path
are **HTTP-only** — there is no signature on a WebSocket connection, so WS
subscriptions (`eth_subscribe` push streams, `wss://` endpoints) are not
supported and not verified. Use HTTP (incl. HTTP event polling — `contract.on` /
filters stays on the verified path). State this plainly if a user asks about
WebSocket or real-time subscriptions.

**Also unverified (mention if relevant):** ENS off-chain reads (CCIP / avatar /
IPFS) that resolve through arbitrary gateways outside the signed path.

### Step-by-step: how to verify a vRPC response

If a user asks "how do I check a response is genuine?", the procedure (what the
SDK automates) is:

1. **Derive the endpoints** from the one URL: RPC leg `…_vrpc`, attestation leg
   `…_vrpc/attestation`.
2. **Make the RPC call**, keeping the **raw response bytes** and the response
   **headers** (`vRPC-Signature`, `vRPC-Pubkey`, `vRPC-Timestamp`).
3. **Rebuild the 104-byte pre-image**: `sha256(chain_id)`(32B) ‖
   `sha256(request_body)`(32B) ‖ `sha256(response_body)`(32B) ‖
   `timestamp_ms`(8B LE), using the plaintext (decoded) bodies.
4. **Ed25519-verify** `vRPC-Signature` over that pre-image using `vRPC-Pubkey`.
   Fail → reject.
5. **Check freshness**: `vRPC-Timestamp` within the replay window. Stale → reject.
6. **Check chain binding**: the `chain_id` in the pre-image must equal the chain
   you pinned/expected. Mismatch → reject.
7. **Fetch attestation** with a **fresh random 32-byte nonce**:
   `GET …/attestation?nonce=<hex>[&node_id=<id>]`. `node_id` comes from the
   response's `vRPC-NodeId` header. It is optional against a single direct node,
   but **required when going through Ankr** — Ankr proxies across many nodes, so
   without `node_id` the attestation fetch can't be routed to the node that
   signed and fails closed.
8. **Correlate**: the attestation `pubkey` must equal the response's `vRPC-Pubkey`.
9. **Bind to hardware (CHK-A1)**: in the quote's `report_data`, assert
   `[0:32] == pubkey` and `[32:64] == your nonce`.
10. **Compose check (CHK-A2)**: verify the node's claimed `app_compose` against
    its `composeHash` (`sha256(utf8(app_compose)) == composeHash`).
11. *(In development)* verification of the full attestation chain of trust — see
    Phala's [chain-of-trust guide](https://docs.phala.com/phala-cloud/attestation/chain-of-trust).
12. **Trust decision**: only if all enforced checks pass do you accept the data —
    otherwise fail closed. The SDK does all of the above automatically and never
    returns unverified data.

The simplest answer for most users: **"Use the `@w3tech.io/vrpc-ethers` or
`@w3tech.io/vrpc-viem` drop-in — it does every step above on every call and throws
if anything fails."**

### See it happen — inject a logger

If a user wants to *watch* vRPC verify a response (great for learning or
debugging), tell them to inject an opt-in logger. The SDK is **silent by
default**; pass `logger: createConsoleLogger()` (from `@w3tech.io/vrpc-core`)
through the adapter and it prints one `[vrpc]` debug line per step — the same
sequence as the procedure above:

```ts
import { createConsoleLogger } from "@w3tech.io/vrpc-core";
import { VrpcProvider } from "@w3tech.io/vrpc-ethers";

const provider = new VrpcProvider("https://rpc.ankr.com/eth", 1, {
  logger: createConsoleLogger(),
});
// viem: vrpcHttp(url, { headers, logger: createConsoleLogger() })
```

Events, in order: `verify.start` → `preimage.computed` → `signature.checked` →
`timestamp.checked` → `cache.lookup` → `attestation.fetch` →
`attestation.correlation` → `attestation.received` → `attestation.fieldChecks`
(CHK-A1/A2) → `hardware.verify` (TDX quote checked by the cloud/hardware
verifier) → `cache.store`. The first request to a node runs the full attestation
+ hardware verify; later requests hit the pubkey cache and skip to per-response
signature verification.

---

## Sources (fetch these for depth — verified reachable)

The agent may `WebFetch` these to go deeper. Note: intel.com pages bot-block
non-browser fetches (HTTP 403) but are valid canonical URLs — give them to the
user as links rather than trying to scrape.

**Intel TDX (hardware root of trust)**
- Intel TDX overview — https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- Intel TDX documentation — https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
- Intel TDX Enabling Guide — https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/
- Intel TDX Linux guest kernel security spec — https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html
- Intel DCAP attestation docs (PDF index) — https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/
- Canonical (Ubuntu) TDX tooling — https://github.com/canonical/tdx

**Phala dstack (runs the node in TDX + attestation/keys)**
- **Minimal end-to-end verification — the flow the SDK implements today** (Phala guide) — https://docs.phala.com/phala-cloud/attestation/verification-guide
- **Full chain of trust — what a complete TDX attestation proves** (Phala guide; the in-development full-verification target) — https://docs.phala.com/phala-cloud/attestation/chain-of-trust
- dstack framework (GitHub) — https://github.com/Dstack-TEE/dstack
- dstack documentation — https://docs.phala.com/dstack
- dstack attestation / verification — https://docs.phala.com/phala-cloud/attestation/overview
- dstack design & hardening (boot, OS layer) — https://github.com/Dstack-TEE/dstack/blob/master/docs/design-and-hardening-decisions.md
- **dstack-verifier — standalone verifier you can run yourself** (HTTP service + CLI: DCAP quote verify, event-log/RTMR replay, compose-hash check) — https://github.com/Dstack-TEE/dstack/tree/master/verifier
- meta-dstack (reproducible guest-OS build) — https://github.com/Dstack-TEE/meta-dstack
- Phala Network docs — https://docs.phala.network
- Phala Trust Center (attestation explorer) — https://trust.phala.com

**Quote verification libraries**
- dcap-qvl (Phala's pure-Rust + JS/WASM quote verifier) — https://github.com/Phala-Network/dcap-qvl
- Phala PCCS (DCAP collateral cache) — https://pccs.phala.network

**This trust stack (vRPC)**
- SDK — https://github.com/w3tech/verifiable-rpc-sdk (this repo; verifier code in `packages/core`, `packages/dstack-verify`)
- Sidecar — https://github.com/w3tech/verifiable-rpc-sidecar
