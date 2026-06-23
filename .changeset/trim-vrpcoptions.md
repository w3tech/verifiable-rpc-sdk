---
"@ankr.com/vrpc-core": minor
"@ankr.com/vrpc-ethers": minor
"@ankr.com/vrpc-viem": minor
---

Trim the options surface to only knobs that do something in v6.0.

- Removed `allowlist`, `tcb`, `pccsUrl` from `VrpcOptions` (ethers), `VrpcHttpOptions` (viem), and `TrustedVerifierOptions` (core). The v6.0 mock `verifyDstackAttestation` branches solely on `allowInsecureMock` and ignores all three, so exposing them implied trust-policy enforcement that does not happen. `buildVerifyPolicy` now defaults the policy internally (`EMPTY_ALLOWLIST` + default TCB). v7.0 reintroduces these options (consumer-pinned anchors) when the real verifier needs them — re-adding optional fields is non-breaking.
- Removed the redundant `headers` option from ethers `VrpcOptions`: set auth on the `FetchRequest` you pass as the URL (`req.setHeader("x-api-key", …)`), which already covers both the RPC POST and the internal attestation fetch. viem and core keep `headers` (their native header vector).

Migration: if you passed `allowlist`/`tcb`/`pccsUrl`, drop them (they were no-ops). For ethers auth, use the `FetchRequest` header instead of `headers`.
