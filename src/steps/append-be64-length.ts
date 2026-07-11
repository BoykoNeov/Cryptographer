/**
 * Append-be64-length — port-native length-suffix primitive (universal-port
 * plan Phase 2 Slice 2.4, 2026-05-24).
 *
 * Appends an 8-byte big-endian encoding of `(lengthSource.length * 8)` —
 * the bit-length of the original message — to the `data` input. Output =
 * `data || BE64(lengthSource.length * 8)`.
 *
 * **Two input ports by design.** SHA-256 padding (FIPS 180-4 §5.1.1)
 * requires appending the bit-length of the ORIGINAL message, not the
 * already-padded length. The natural port-native expression is:
 *
 *   `data`         ← post-padding bytes (from `pad-with-byte@1`)
 *   `length-source`← original (unpadded) message
 *
 * The spec wires both: `data` reads from the padded chain; `length-
 * source` reads from the pre-padding message directly. Decoupling
 * "what to extend" from "what to encode the length of" via a separate
 * input port is the universal-port answer to FIPS 180-4's
 * length-of-the-original-message requirement.
 *
 * **Why BE64 (8 bytes) and not BE128.** SHA-256 / SHA-224 / MD5 / SHA-1
 * all use a 64-bit length suffix. SHA-512 / SHA-384 use a 128-bit
 * suffix; when SHA-512 lands (Phase 2c+) a sibling
 * `append-be128-length@1` primitive ships then. Splitting per-width
 * mirrors `add-mod-32@1` / `add-mod-64@1`'s width-specific split and
 * the per-width word-codec helpers in `src/core/word-codec.ts`.
 *
 * **Bit-length safety.** Max practical input length is bounded by JS's
 * `Uint8Array` (~2^32 - 1 bytes), so `length * 8` fits well within
 * `Number.MAX_SAFE_INTEGER` (2^53 - 1). The implementation converts to
 * `bigint` before encoding because `encodeBE64` consumes `bigint` — that
 * conversion is cheap and keeps the encoder API uniform across widths.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract: 2 static input ports (the count
 * doesn't vary with params), 1 static output port; polymorphic
 * byteLength on input ports (run-time-determined) and on the output
 * port (since output length = data.length + 8 is run-time-determined).
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { encodeBE64 } from "../core/word-codec";

// ─── Port names — exported so a spec-builder doesn't typo the string ──────

export const APPEND_BE64_DATA_PORT = "data";
export const APPEND_BE64_LENGTH_SOURCE_PORT = "length-source";
export const APPEND_BE64_OUTPUT_PORT = "output";

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Static both sides — port count is fixed (2 in, 1 out). Polymorphic
 * `byteLength` on all three ports because (a) input lengths are
 * run-time, (b) output length = `data.length + 8` is run-time.
 */
export const appendBe64LengthPortContract: PortContract = {
  inputs: new Map([
    [APPEND_BE64_DATA_PORT, { layout: "raw" }],
    [APPEND_BE64_LENGTH_SOURCE_PORT, { layout: "raw" }],
  ]),
  outputs: new Map([[APPEND_BE64_OUTPUT_PORT, { layout: "raw" }]]),
};

export const appendBe64Length: PortedExecutor = (inputs, _params, _ctx) => {
  const data = inputs.get(APPEND_BE64_DATA_PORT);
  const lengthSource = inputs.get(APPEND_BE64_LENGTH_SOURCE_PORT);
  if (data === undefined) {
    throw new Error(`append-be64-length: missing required input port '${APPEND_BE64_DATA_PORT}'`);
  }
  if (lengthSource === undefined) {
    throw new Error(
      `append-be64-length: missing required input port '${APPEND_BE64_LENGTH_SOURCE_PORT}'`,
    );
  }

  // bit-length of the ORIGINAL message (lengthSource), not the padded
  // data. Convert to bigint at the boundary — `encodeBE64`'s signature is
  // bigint-only (per word-codec.ts Slice 2.2 rationale: JS number ops
  // truncate to 32-bit, so 64-bit encoding goes through bigint).
  const bitLength = BigInt(lengthSource.length) * 8n;

  const out = new Uint8Array(data.length + 8);
  out.set(data, 0);
  encodeBE64(out, data.length, bitLength);

  return new Map([[APPEND_BE64_OUTPUT_PORT, out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const appendBe64LengthDoc: StepDocumentation = {
  name: "Append BE64 length suffix",
  summary:
    "Appends the original message's bit-length as an 8-byte suffix — the final step of SHA-256-style padding.",
  detail: `# Append BE64 length suffix

Appends an 8-byte number recording the **bit-length of the original message**
to the data. The output is 8 bytes longer than the input.

## Math

\`\`\`
bitLength = (original message length in bytes) × 8     (as a 64-bit number)
output    = data || bitLength
\`\`\`

## Why two inputs

SHA-256 — like every hash in its family — ends its padding by recording the
length of the **original** message, not the padded one. So this step takes
two inputs: \`data\` is the already-padded message, and \`length-source\` is
the original message, used only to measure its length. Recording the original
length is a defense against certain forgery attacks, so the hash commits to
exactly how many bytes it saw.

## Where it fits

- **SHA-256 / SHA-224 / SHA-1**: the message-length suffix (FIPS 180-4 §5.1.1).
- **MD5**: the same suffix (RFC 1321 §3.2).

## Example (SHA-256 padding of "abc")

\`\`\`
length-source: 61 62 63                           (3 bytes)
data:          61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00                          (56 bytes)
output:        61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 18  (64 bytes)
                                                            ^^
                                                            BE64(24)
\`\`\`

\`24 = 3 × 8\` (3-byte message, 8 bits per byte). The last 8 bytes hold that
number, \`00 00 00 00 00 00 00 18\`.`,
  params: new Map(),
  references: [
    "FIPS 180-4 §5.1.1 (SHA-256 / SHA-224 padding — bit-length suffix)",
    "RFC 1321 §3.2 (MD5 padding — same shape)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
