// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// vrpc-core walkthrough: the verification engine the ethers/viem adapters wrap,
// used directly so you can see each step of the trust chain — raw verify
// primitives first (steps 1-4), then the TrustedVerifier one-shot (step 5).
import crypto from "node:crypto";

import {
  BadSignature,
  deriveVrpcUrls,
  fetchAttestation,
  TrustedVerifier,
  verifyAttestationCorrelation,
  verifyResponse,
} from "@w3tech.io/vrpc-core";

const URL = "https://rpc.ankr.com/arbitrum_vrpc/123456";
const CHAIN_ID = "42161";

async function main() {
  // 1 — make a request; the node attaches vRPC-Signature/Timestamp/Pubkey headers
  // (signed inside the TEE).
  const requestBytes = new TextEncoder().encode(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_getBlockByNumber",
      params: ["latest", false],
    }),
  );
  const res = await fetch(URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBytes,
  });
  const responseBytes = new Uint8Array(await res.arrayBuffer());

  // 2 — verify the Ed25519 signature over the canonical pre-image.
  const verified = await verifyResponse(requestBytes, responseBytes, res.headers, {
    chainId: CHAIN_ID,
  });

  // 3 — fail-closed: flip one byte and re-verify → BadSignature.
  const tampered = Uint8Array.from(responseBytes);
  const mid = tampered.length >> 1;
  tampered[mid] = (tampered[mid] ?? 0) ^ 0xff;
  await verifyResponse(requestBytes, tampered, res.headers, { chainId: CHAIN_ID }).then(
    () => {
      throw new Error("tampered response unexpectedly verified");
    },
    (err) => {
      if (!(err instanceof BadSignature)) throw err;
    },
  );

  // 4 — anchor the signing key to the TEE: the attestation pubkey must equal the
  // key that signed our response.
  const attestation = await fetchAttestation({
    attestationUrl: `${URL}/attestation`,
    nonce: crypto.randomBytes(32),
  });
  verifyAttestationCorrelation(attestation, verified.verification.pubkeyHex);

  // 5 — the everyday seam (what the ethers/viem adapters construct):
  // signature + replay + lazy attestation + mandatory hardware verify,
  // cached per pubkey. Reuses the step-1 bytes — no extra fetch.
  const { attestationUrl } = deriveVrpcUrls(URL);
  const tv = new TrustedVerifier({ chainId: CHAIN_ID, attestationUrl });
  const pair = await tv.verify(requestBytes, responseBytes, res.headers);

  console.log({
    signer: verified.verification.pubkeyHex,
    attested: attestation.pubkey,
    trustedVerifierPubkey: pair.verification.pubkeyHex,
  });
}

main();
