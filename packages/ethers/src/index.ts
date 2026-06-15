// @ankr.com/vrpc-ethers — ethers v6 adapter (STUB).
//
// The VrpcProvider adapter (an ethers JsonRpcApiProvider whose _send override
// feeds raw request + raw response bytes into vrpc-core's verify seam) lands in
// Phase 30. This phase ships only the package skeleton + dependency-isolation
// manifest: ethers is a peerDependency (consumer-supplied, single instance),
// and all verification logic is reused from @ankr.com/vrpc-core — never copied.
//
// Re-export the verification-error base from core so the workspace link is real
// and the stub is buildable without importing ethers.
export { VerificationError } from "@ankr.com/vrpc-core";
