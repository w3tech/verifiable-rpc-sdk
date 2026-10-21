// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// Ankr Confidential RPC client that loads its crypto on first use.

import type { InnerRequest } from "./bhttp";
import type {
  ConfidentialClient,
  ConfidentialClientOptions,
  ConfidentialInfo,
  ConfidentialResponse,
} from "./confidential-client";
import { InternalError } from "./errors";
import { checkOptions } from "./options";

/**
 * A `ConfidentialClient` whose code, crypto included, is loaded on the first `request` or `ready`.
 * Options are checked at construction; a failed load is `InternalError` with `executed: "no"` and is retried on the next call.
 */
export class LazyConfidentialClient {
  readonly #options: ConfidentialClientOptions;
  #client: ConfidentialClient | undefined;
  #loading: Promise<ConfidentialClient> | undefined;

  constructor(options: ConfidentialClientOptions) {
    checkOptions({
      url: options.url,
      chainId: options.chainId,
      headers: options.headers,
      replayWindowMs: options.replayWindowMs,
      pubkeyCacheTtlMs: options.pubkeyCacheTtlMs,
    });
    this.#options = options;
  }

  async request(
    inner: InnerRequest,
    options?: { signal?: AbortSignal },
  ): Promise<ConfidentialResponse> {
    return (await this.#load()).request(inner, options);
  }

  async ready(options?: { signal?: AbortSignal }): Promise<ConfidentialInfo> {
    return (await this.#load()).ready(options);
  }

  getConfidentialInfo(): ConfidentialInfo | undefined {
    return this.#client?.getConfidentialInfo();
  }

  #load(): Promise<ConfidentialClient> {
    if (this.#client !== undefined) return Promise.resolve(this.#client);
    this.#loading ??= import("./confidential-client").then(
      ({ ConfidentialClient }) => {
        this.#client = new ConfidentialClient(this.#options);
        return this.#client;
      },
      (cause: unknown) => {
        this.#loading = undefined;
        const err = new InternalError({ cause });
        err.executed = "no";
        throw err;
      },
    );
    return this.#loading;
  }
}
