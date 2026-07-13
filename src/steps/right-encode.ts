/**
 * right-encode — NIST SP 800-185 §2.3.1 `right_encode`, 2026-07-13.
 *
 * **What it does.** A zero-input constant emitter that outputs `right_encode`
 * of its `value` param:
 *
 * ```
 *   right_encode(x) = x_as_n_bytes_big_endian || byte(n)
 * ```
 *
 * — the byte count `n` comes **last** (the mirror of `left_encode`). E.g.
 * `right_encode(0) = 00 01`, `right_encode(256) = 01 00 02`.
 *
 * **Where it fits.** KMAC appends `right_encode(L)` to its input, where `L` is
 * the requested output length **in bits**. Binding the output length into the
 * hashed input is what stops a KMAC tag from being reinterpreted at a different
 * length — a 256-bit tag and the first 256 bits of a 512-bit tag are guaranteed
 * different. The XOF variant **KMACXOF** appends `right_encode(0)` instead,
 * signalling "no committed length" so the output can be squeezed arbitrarily.
 * The builder sets `value = outputBytes · 8` for KMAC and `0` for KMACXOF.
 *
 * **Why a step (vs. `constant-load@1`).** Functionally this could be a
 * constant-load of the precomputed bytes, but a dedicated step keeps the
 * relationship "this field encodes the output length L" visible and coupled to
 * the editable output-length control — editing L re-derives the encoding rather
 * than leaving a stale magic constant.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Zero input ports; the single `output` port's
 * byteLength is a function of `value`, known at spec time.
 */

import { rightEncode } from "../core/sp800-185";
import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly value: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("right-encode: params must be an object");
  }
  const p = params as Record<string, Json>;
  const value = p.value;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(
      `right-encode: params.value must be a non-negative integer (the length in bits to encode), got ${String(value)}`,
    );
  }
  return { value };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Zero input ports (like `constant-load@1`); output byteLength resolves at
 * spec time from `value` via function form, useful for editor coercion glyphs.
 */
export const rightEncodePortContract: PortContract = {
  inputs: new Map(),
  outputs: (params: Json) => {
    const { value } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength: rightEncode(value).length };
    return new Map([["output", shape]]);
  },
};

export const rightEncodeStep: PortedExecutor = (_inputs, params, _ctx) => {
  const { value } = readParams(params);
  return new Map([["output", rightEncode(value)]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const rightEncodeDoc: StepDocumentation = {
  name: "right_encode (SP 800-185)",
  summary:
    "Emits the length value encoded with its byte-count suffix — KMAC's output-length commitment.",
  detail: `# right_encode (NIST SP 800-185 §2.3.1)

Encodes a non-negative integer as a self-describing byte string with the length
byte **last**:

\`\`\`
right_encode(x) = x_as_n_bytes_big_endian || byte(n)
\`\`\`

So \`right_encode(0) = 00 01\` and \`right_encode(256) = 01 00 02\` (256 needs 2
bytes, \`01 00\`, then the count \`02\`). It is the mirror of \`left_encode\`,
which puts the count first.

## Where KMAC uses it

KMAC appends \`right_encode(L)\` to its input, where **L is the output length in
bits**. Committing the length inside the hashed input is what makes KMAC
**length-binding**: a 256-bit tag is not a prefix of a 512-bit tag for the same
key and message, so an attacker can't truncate or extend a tag by
reinterpreting its length.

The XOF variant **KMACXOF** appends \`right_encode(0)\` instead — the "0"
signals no committed length, so the output can be squeezed to any length like a
plain XOF. That single value is the only difference between KMAC and KMACXOF.`,
  params: new Map([
    [
      "value",
      "The non-negative integer to encode — for KMAC, the output length in bits (bytes × 8); 0 for the KMACXOF variant.",
    ],
  ]),
  references: ["NIST SP 800-185 §2.3.1 (right_encode)", "NIST SP 800-185 §4 (KMAC)"],
  // No `shapeContract` — port-native steps describe their surface via PortContract.
};
