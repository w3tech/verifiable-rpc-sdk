---
"@ankr.com/vrpc-core": minor
"@ankr.com/vrpc-ethers": minor
"@ankr.com/vrpc-viem": minor
---

Remove the `apiKey` option from all SDK options (`VrpcOptions`, `VrpcHttpOptions`, `VerifierClientOptions`, `TrustedVerifierOptions`, `AnchorTrustOptions`, `FetchAttestationOptions`).

Auth now flows exclusively through the native header mechanism, which already reaches BOTH the RPC leg and the internal attestation leg — `apiKey` was a redundant parallel path.

Migration (replace `apiKey: key` with the header form):

- **ethers** — set it on the `FetchRequest` you pass as the URL:
  `const req = new FetchRequest(url); req.setHeader("x-api-key", key); new VrpcProvider(req, chainId)`.
- **viem / core** — pass `headers`:
  `vrpcHttp(url, { chainId, headers: { "x-api-key": key } })`, `new VerifierClient(url, { chainId, headers: { "x-api-key": key } })`, `anchorTrust({ ..., headers: { "x-api-key": key } })`, `fetchAttestation({ ..., headers: { "x-api-key": key } })`.

No behavior change otherwise: a consumer who moves `x-api-key` into headers/FetchRequest gets identical wire behavior on both legs.
