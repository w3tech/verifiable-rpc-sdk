// 03 — fetchAttestation + parse + SPEC-04 report_data binding.
//
// Calls GET /attestation?nonce=<32B hex>, then performs the two cheap
// consistency checks the SDK does NOT do for you:
//   - report_data must equal pubkey || nonce (SPEC-04 byte binding — this is
//     what stops C3, an attestation that isn't bound to anything)
//   - event_log entry where event=="compose-hash" must equal top-level
//     composeHash (the sidecar must agree with itself about which compose it
//     thinks it's running)
//
// The TDX quote itself is NOT verified against Intel's PCK roots — that's a
// registry-v1 follow-up (DEC-03 still open). Surfaced here for human eyes only.

import { fetchAttestation } from "@ankr.com/vrpc-core";
import { assert, header, kv, PINNED_COMPOSE_HASH, URL } from "./shared.ts";

header("03 — fetchAttestation + parse + report_data binding");

const nonce = crypto.getRandomValues(new Uint8Array(32));
const att = await fetchAttestation(URL, nonce);

kv("pubkey", att.pubkey);
kv("composeHash (response)", att.composeHash);
kv("composeHash (pinned)  ", PINNED_COMPOSE_HASH);
kv(
  "composeHash match?",
  att.composeHash === PINNED_COMPOSE_HASH ? "YES" : "NO — sidecar redeployed?",
);
kv("vm_config", att.quote.vm_config);

// SPEC-04 byte binding: report_data == pubkey || nonce (each 32 bytes, hex-encoded, no 0x prefix).
const nonceHex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join("");
const pubkeyBare = att.pubkey.startsWith("0x") ? att.pubkey.slice(2) : att.pubkey;
const expectedReportData = (pubkeyBare + nonceHex).toLowerCase();
assert(
  att.quote.report_data.toLowerCase() === expectedReportData,
  `report_data binding failed:\n  got:      ${att.quote.report_data}\n  expected: ${expectedReportData}`,
);
kv("report_data binding (pubkey || nonce)", "OK");

// event_log: assert compose-hash event payload matches top-level composeHash.
const events = JSON.parse(att.quote.event_log) as Array<{
  event: string;
  event_payload: string;
}>;
const composeEvent = events.find((e) => e.event === "compose-hash");
assert(composeEvent !== undefined, "no compose-hash event found in event_log");
assert(
  composeEvent.event_payload === att.composeHash,
  `event_log compose-hash payload (${composeEvent.event_payload}) != top-level composeHash (${att.composeHash})`,
);
kv("event_log compose-hash matches top-level", "OK");

// Surface a few interesting events for visibility.
for (const want of ["app-id", "instance-id", "mr-kms", "os-image-hash"]) {
  const ev = events.find((e) => e.event === want);
  if (ev) kv(`event_log.${want}`, ev.event_payload);
}

console.log(
  "\nPASS — attestation fetched, parsed, report_data bound to nonce, compose-hash consistent.",
);
