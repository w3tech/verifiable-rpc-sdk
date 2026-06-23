---
"@ankr.com/vrpc-core": minor
---

`deriveVrpcUrls` now supports the public `rpc.ankr.com/<chain>/<key>` URL form (API key as a path segment after the chain): `_vrpc` is inserted on the **chain** segment and any trailing segments (the key) are preserved — `https://rpc.ankr.com/arbitrum/<key>` → rpc `https://rpc.ankr.com/arbitrum_vrpc/<key>`, attestation `https://rpc.ankr.com/arbitrum_vrpc/<key>/attestation`. Previously `_vrpc` was appended to the end of the URL, mangling the key.

The existing single-segment form (`https://host/<chain>` → `<chain>_vrpc`) and the `_vrpc` dup-guard are unchanged. A root URL with no path (a direct node, `http://host:port`) now derives `/_vrpc` instead of producing an invalid URL.
