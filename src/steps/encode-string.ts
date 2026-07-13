/**
 * encode-string — NIST SP 800-185 §2.3.2 `encode_string`, 2026-07-13.
 *
 * **What it does.** Length-prefixes a byte string so it becomes self-describing:
 *
 * ```
 *   encode_string(S) = left_encode(8 · len(S)) || S
 * ```
 *
 * The prefix is `left_encode` of the length **in BITS** (`8 · len`), not bytes —
 * this is the single most common cSHAKE/KMAC implementation bug, because a
 * byte-length prefix passes every structural check and still yields a wrong
 * digest. This step reads the actual input length at run time, so it is correct
 * for a string of any length.
 *
 * **Where it fits.** cSHAKE encodes its two customization strings — the function
 * name `N` and the customization `S` — then `bytepad`s the pair into the sponge
 * prefix. KMAC additionally encodes its **key** the same way. Every field that
 * enters the sponge as "a string of some length" goes through `encode_string`
 * first, so the boundaries between key, customization, and message are
 * unambiguous.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Both ports `layout:"raw"` — the input is a string of
 * any length and the output length (prefix + input) depends on it, so neither
 * byteLength is known at spec time.
 */

import { leftEncode } from "../core/sp800-185";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Port contract + executor ─────────────────────────────────────────────

export const encodeStringPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const encodeString: PortedExecutor = (inputs, _params, _ctx) => {
  const s = inputs.get("input");
  if (s === undefined) {
    throw new Error("encode-string: missing required input port 'input'");
  }
  const prefix = leftEncode(8 * s.length); // BIT length — the SP 800-185 footgun
  const out = new Uint8Array(prefix.length + s.length);
  out.set(prefix, 0);
  out.set(s, prefix.length);
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const encodeStringDoc: StepDocumentation = {
  name: "encode_string (SP 800-185)",
  summary:
    "Length-prefixes a byte string with its bit-length so field boundaries inside the sponge are unambiguous.",
  detail: `# encode_string (NIST SP 800-185 §2.3.2)

Turns a byte string into a **self-describing** field by prepending its length:

\`\`\`
encode_string(S) = left_encode(8 · len(S)) || S
\`\`\`

## The bit-length footgun

The prefix encodes the length **in bits** — \`8 · len(S)\` — not in bytes. A
byte-length prefix is the classic cSHAKE/KMAC bug: it looks right, passes
structural tests, and silently produces the wrong digest. For a 15-byte string
the prefix is \`left_encode(120)\`; for an empty string it is
\`left_encode(0) = 01 00\`.

## Why length-prefix at all

cSHAKE and KMAC concatenate several distinct fields — a function name, a
customization string, a key, the message — and feed the result into the same
sponge. Without a self-describing length, two different \`(N, S)\` splits could
produce the **same** absorbed bytes and therefore the same output. Prefixing
each field with its bit-length makes that impossible: the boundaries are
recoverable, so the domain separation is total (SP 800-185 §3.2).`,
  references: ["NIST SP 800-185 §2.3.2 (encode_string)", "NIST SP 800-185 §2.3.1 (left_encode)"],
  // No `shapeContract` — port-native steps describe their surface via PortContract.
};
