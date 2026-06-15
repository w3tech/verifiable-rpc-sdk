// @ankr.com/vrpc-viem — viem adapter (STUB).
//
// The vrpcHttp transport (a viem custom transport that hands raw request +
// raw response bytes to vrpc-core's verify seam) lands in Phase 31. This phase
// ships only the package skeleton + dependency-isolation manifest: viem is a
// peerDependency (consumer-supplied, single instance), and all verification
// logic is reused from @ankr.com/vrpc-core — never copied.
//
// Re-export the verification-error base from core so the workspace link is real
// and the stub is buildable without importing viem.
export { VerificationError } from "@ankr.com/vrpc-core";
