// Placeholder surface — verification logic lands in Phase 19, attestation in Phase 20.

export interface VerifierClientOptions {
  replayWindowMs?: number;
  fetch?: typeof fetch;
}

export interface GetQuoteResponse {
  quote: string;
  event_log: string;
  report_data: string;
  vm_config: string;
}

export interface Attestation {
  quote: GetQuoteResponse;
  pubkey: string;
  composeHash: string;
}

export interface VerifiedResponse<T> {
  result: T;
  verification: {
    sigBytes: Uint8Array;
    pubkeyHex: string;
    timestampMs: number;
    preImageSha256: Uint8Array;
  };
}

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }

  static missingHeader(name: string): VerificationError {
    return new VerificationError(`missing header: ${name}`);
  }

  static malformedHeader(name: string): VerificationError {
    return new VerificationError(`malformed header: ${name}`);
  }

  static badSignature(): VerificationError {
    return new VerificationError("bad signature");
  }

  static staleTimestamp(): VerificationError {
    return new VerificationError("stale timestamp");
  }
}

export class VerifierClient {
  private readonly url: string;
  private readonly opts: VerifierClientOptions;

  constructor(url: string, opts?: VerifierClientOptions) {
    if (!/^https?:\/\//.test(url)) {
      throw new TypeError(`VerifierClient: url must start with http:// or https:// (got: ${url})`);
    }
    this.url = url;
    this.opts = opts ?? {};
  }

  async call<T>(method: string, params: unknown[]): Promise<VerifiedResponse<T>> {
    throw new Error(
      `not yet implemented — Phase 19 (url=${this.url}, method=${method}, params.length=${params.length})`,
    );
  }

  async fetchAttestation(nonce: Uint8Array): Promise<Attestation> {
    throw new Error(
      `not yet implemented — Phase 20 (url=${this.url}, nonce.length=${nonce.length}, replayWindowMs=${this.opts.replayWindowMs ?? "default"})`,
    );
  }
}
