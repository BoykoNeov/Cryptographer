/**
 * bytepad — NIST SP 800-185 §2.3.3 `bytepad`, 2026-07-13.
 *
 * **What it does.** Prefixes a byte string with `left_encode(w)` and zero-pads
 * the result up to a whole multiple of `w` bytes:
 *
 * ```
 *   bytepad(X, w) = left_encode(w) || X || 0…0   (padded to a multiple of w)
 * ```
 *
 * where `w` is the sponge **rate in bytes** (168 for the 128-strength
 * functions, 136 for the 256-strength ones). The `left_encode(w)` prefix records
 * the block size the string was padded to, and the trailing zeros make the
 * padded string align exactly to a rate boundary.
 *
 * **Why cSHAKE/KMAC need it.** cSHAKE absorbs its customization block —
 * `bytepad(encode_string(N) || encode_string(S), rate)` — as a *whole number of
 * rate blocks* **before** the message. Aligning to the rate means the message
 * bytes always start at the beginning of a fresh sponge block, which is what
 * makes the customization a clean prefix rather than something interleaved with
 * the message. KMAC does the same for its key: `bytepad(encode_string(K), rate)`.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Both ports `layout:"raw"` — the output length is
 * `input.length` rounded up to a multiple of `w` (plus the prefix), so it is not
 * known at spec time.
 */

import { leftEncode } from "../core/sp800-185";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly w: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("bytepad: params must be an object");
  }
  const p = params as Record<string, Json>;
  const w = p.w;
  if (typeof w !== "number" || !Number.isInteger(w) || w < 1) {
    throw new Error(
      `bytepad: params.w must be a positive integer (block size in bytes, e.g. 168), got ${String(w)}`,
    );
  }
  return { w };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const bytepadPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const bytepad: PortedExecutor = (inputs, params, _ctx) => {
  const { w } = readParams(params);
  const x = inputs.get("input");
  if (x === undefined) {
    throw new Error("bytepad: missing required input port 'input'");
  }
  const prefix = leftEncode(w); // records the block size the string is aligned to
  const bodyLen = prefix.length + x.length;
  // Zero-pad up to the next multiple of w. When bodyLen is already a multiple,
  // no zeros are added (SP 800-185 bytepad adds the minimum needed).
  const rem = bodyLen % w;
  const padLen = rem === 0 ? 0 : w - rem;
  const out = new Uint8Array(bodyLen + padLen); // trailing bytes default to 0
  out.set(prefix, 0);
  out.set(x, prefix.length);
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const bytepadDoc: StepDocumentation = {
  name: "bytepad (SP 800-185)",
  summary:
    "Prefixes a string with its block size and zero-pads it to a whole number of sponge rate blocks.",
  detail: `# bytepad (NIST SP 800-185 §2.3.3)

Aligns a byte string to a whole number of sponge blocks:

\`\`\`
bytepad(X, w) = left_encode(w) || X || 0…0
\`\`\`

The \`left_encode(w)\` prefix records the block size \`w\` (the sponge **rate in
bytes** — 168 for the 128-strength functions, 136 for the 256-strength ones),
and enough zero bytes are appended so the total length is an exact multiple of
\`w\`. If the string already lands on a boundary, no zeros are added.

## Why align to the rate

cSHAKE absorbs a **customization block** —
\`bytepad(encode_string(N) || encode_string(S), rate)\` — before the message.
Padding it up to a whole number of rate blocks means the message always begins
at the start of a fresh sponge block, so the customization is a clean prefix
rather than something that shares a block with the first message bytes. KMAC
uses the same trick to absorb its key: \`bytepad(encode_string(K), rate)\`.`,
  params: new Map([
    [
      "w",
      "Block size in bytes to align to — the sponge rate (168 for cSHAKE128/KMAC128, 136 for the 256-strength variants).",
    ],
  ]),
  references: ["NIST SP 800-185 §2.3.3 (bytepad)", "NIST SP 800-185 §2.3.1 (left_encode)"],
  // No `shapeContract` — port-native steps describe their surface via PortContract.
};
