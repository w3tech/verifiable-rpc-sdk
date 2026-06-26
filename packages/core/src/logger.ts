// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Web3 Technologies, Inc.
// The opt-in debug-logger seam for the vRPC SDK.
//
// The SDK is SILENT by default: nothing is emitted unless a caller injects a
// Logger. The seam is a single `debug` method (one narration level); errors keep
// throwing typed errors (the throw path is never replaced by a log). No external
// dependency is taken — the interface is our own and the convenience helper uses
// only the built-in `console`.

/** Minimal opt-in debug logger. Inject to narrate the verify flow; default is a no-op (silent). */
export interface Logger {
  /**
   * Debug-level narration. MUST NOT throw and MUST NOT be relied upon for
   * control flow — it is observability only, never part of the verify decision.
   * `event` is a stable dotted name (e.g. "verify.start"); `data` is a flat,
   * already-redacted/truncated field bag — callers never pass raw secrets.
   */
  debug(event: string, data?: Record<string, unknown>): void;
}

/**
 * Default no-op logger: a frozen singleton, referenced by identity for the
 * silent-path guard (`logger !== defaultLogger`). The SDK uses this whenever no
 * logger is injected, so the default path stays silent and allocation-free.
 */
export const defaultLogger: Logger = Object.freeze({ debug: () => {} });

const OK = "✅";
const FAIL = "❌";
const WAIT = "⏳";
const SKIP = "⏭️";
const HEADER = `${"─".repeat(8)} Response vRPC verify ${"─".repeat(8)}`;
const FOOTER = "─".repeat(HEADER.length);

/**
 * Convenience console logger — a pretty, verify-flow-aware `console.debug` sink.
 * NEVER wired by default: callers opt in by passing it as `logger`.
 *
 * It renders each response verification as a bordered block with logical sections
 * (inputs → response checks → pubkey/attestation → cache) and ✅/❌/⏳ markers.
 * Output is STREAMED (one line per event, never buffered), so a verify that throws
 * mid-flow (bad signature / stale timestamp) still shows its partial block — the
 * failing check prints its ❌ line and the closing border before the throw.
 * The only cross-event state is the compose hash (stashed from `attestation.received`
 * for the field-check line) and is reset on every `verify.start`. Intended for
 * sequential demo/dev narration; parallel verifies may interleave. Unknown events
 * fall back to a raw `[vrpc] <event>` line.
 */
export function createConsoleLogger(): Logger {
  let composeHash: string | undefined;
  const out = (line = ""): void => {
    console.debug(line);
  };
  return {
    debug(event, data) {
      const d = (data ?? {}) as Record<string, unknown>;
      switch (event) {
        case "verify.start": {
          composeHash = undefined;
          out();
          out(HEADER);
          out(" Inputs");
          out(`   req bytes:  ${d.req}`);
          out(`   res bytes:  ${d.res}`);
          out("   vRPC headers:");
          for (const [k, v] of Object.entries((d.headers as Record<string, string>) ?? {})) {
            out(`     ${k}  ${v}`);
          }
          break;
        }
        case "preimage.computed":
          out(`   pre-image:  ${d.preImageSha256}`);
          break;
        case "signature.checked":
          out("");
          out(" Response checks");
          out(`   ${d.ok ? OK : FAIL} Signature`);
          if (d.ok === false) out(FOOTER);
          break;
        case "timestamp.checked":
          out(
            `   ${d.withinWindow ? OK : FAIL} Timestamp (skew ${d.skewMs}ms, window ${d.replayWindowMs}ms)`,
          );
          if (d.withinWindow === false) out(FOOTER);
          break;
        case "cache.lookup":
          out("");
          if (d.hit) {
            out(` ${OK} Pubkey known — using cache, skip attestation`);
            out(FOOTER);
          } else {
            out(` ${WAIT} Pubkey unknown — fetching attestation`);
            out("");
            out(" Attestation checks");
          }
          break;
        case "attestation.fetch":
          // silent: the "fetching attestation" line already printed at cache.lookup (miss)
          break;
        case "attestation.correlation":
          out(`   ${d.match ? OK : FAIL} Pubkeys match`);
          break;
        case "attestation.received":
          composeHash = d.composeHash as string | undefined;
          break;
        case "attestation.fieldChecks":
          out(`   ${OK} reportData binding`);
          if (d.chkA2 === "ok") {
            out(
              `   ${OK} App compose match${composeHash ? ` (${composeHash.slice(0, 12)}…)` : ""}`,
            );
          } else {
            out(`   ${SKIP} App compose (${d.chkA2})`);
          }
          break;
        case "hardware.verify":
          if (d.quoteVerified) {
            out(`   ${OK} Hardware quote verified (${d.verifier})`);
          }
          break;
        case "cache.store":
          out("");
          out(` ${OK} Pubkey saved to cache (ttl ${d.ttlMs}ms)`);
          out(FOOTER);
          break;
        default:
          out(`[vrpc] ${event}${Object.keys(d).length > 0 ? ` ${JSON.stringify(d)}` : ""}`);
      }
    },
  };
}

/**
 * Wrap an injected logger so a throwing `debug()` can never break verification.
 * Applied ONCE at construction (not per call): the wrapper swallows any throw
 * from `inner.debug`, upholding the never-throw contract even for a buggy logger.
 */
export function safeLogger(inner: Logger): Logger {
  return {
    debug(event, data) {
      try {
        inner.debug(event, data);
      } catch {
        // Swallow — logging must never break verification.
      }
    },
  };
}
