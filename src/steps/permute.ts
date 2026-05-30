/**
 * permute — port-native byte-permutation primitive
 * (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * `output[i] = input[indices[i]]` — a pure gather. The output length is
 * `indices.length`; each index addresses a source byte. One raw input port
 * `input`, one raw output port `output`.
 *
 * **The byte-native replacement for `generic.shift-rows@1`.** The legacy
 * step consumed/emitted a `MatrixState` (PortContract `layout:
 * "matrix-cm-4x4"`) and cyclically shifted each row. AES ShiftRows is just
 * a fixed permutation of the 16 state bytes; expressed on a flat
 * `Uint8Array` it is exactly this gather. The round builder computes the
 * 16-element index array from the shift schedule under the column-major
 * convention (`index i ↔ row i mod 4, col ⌊i/4⌋`):
 *
 *   ShiftRows forward:  out[r+4c] = in[r + 4·((c + shift[r]) mod 4)]
 *   ⇒ indices[r+4c] = r + 4·((c + shift[r]) mod 4)
 *
 * Forward and inverse ShiftRows are just different index arrays — no
 * "inverse permute" step type, and (unlike SubBytes/MixColumns) no
 * cross-mode mirror button, because the permutation is structural data the
 * builder derives, not a user-edited algebraic table.
 *
 * **Generic by design.** Nothing here is AES-specific — any byte
 * permutation (a transposition, a bit-reversal-of-bytes, a future cipher's
 * P-box over whole bytes) plugs in its own `indices`.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Static port maps with `layout:"raw"` (no param
 * dependence) so the A4 anti-creep contract's kitchen-sink param resolution
 * never needs an `indices` entry. The output byteLength is left polymorphic
 * (it equals `indices.length`, but declaring it would force function-form
 * resolution that the A4 kitchen-sink doesn't cover; AES is 16→16 so the
 * wiring resolves the concrete length).
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly indices: readonly number[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("permute: params must be an object");
  }
  const p = params as Record<string, Json>;
  const indices = p.indices;
  if (!Array.isArray(indices) || indices.length < 1) {
    throw new Error("permute: params.indices must be a non-empty array of source byte positions");
  }
  for (const idx of indices) {
    if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0) {
      throw new Error("permute: every index must be a non-negative integer");
    }
  }
  return { indices: indices as readonly number[] };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Static maps, `layout:"raw"` on both sides — keeps the leaf off the A4
 * `NON_BYTES_ALLOWLIST`. Output byteLength polymorphic (= indices.length,
 * resolved by wiring).
 */
export const permutePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const permute: PortedExecutor = (inputs, params, _ctx) => {
  const { indices } = readParams(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error('permute: input port "input" is not wired');
  }
  const out = new Uint8Array(indices.length);
  for (let i = 0; i < indices.length; i++) {
    const src = indices[i] as number;
    if (src >= input.length) {
      throw new Error(
        `permute: index ${src} (output position ${i}) is out of range for a ${input.length}-byte input`,
      );
    }
    out[i] = input[src] as number;
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const permuteDoc: StepDocumentation = {
  name: "Permute",
  summary:
    "Reorder bytes by a fixed index map: output[i] = input[indices[i]]. Port-native byte gather.",
  detail: `# Permute

Pure byte permutation (a gather). The output byte at position \`i\` is the
input byte at position \`indices[i]\`:

\`\`\`
output[i] = input[indices[i]]
\`\`\`

The output length equals \`indices.length\`. Each index addresses one source
byte; an index out of range for the wired input throws.

## Where it fits

In **AES** this is **ShiftRows** (FIPS-197 §5.1.2) and its inverse
(§5.3.1). AES state is a 4×4 column-major byte matrix (byte index
\`i ↔ row i mod 4, col ⌊i/4⌋\`); ShiftRows cyclically shifts row \`r\` left by
\`shift[r]\`, which on the flat byte array is the fixed gather

\`\`\`
indices[r + 4·c] = r + 4·((c + shift[r]) mod 4)
\`\`\`

ShiftRows spreads bytes **between** columns; MixColumns then diffuses
**within** each column. Forward and inverse ShiftRows differ only in the
index array (the inverse shifts right by the same amounts).

## Why it matters

Permutations contribute **diffusion** — alone they don't add confusion (no
non-linearity), but combined with a substitution and a mixing step they
ensure a single input-byte change propagates across the whole block within
a couple of rounds.

## Errors

- Throws if \`params.indices\` is missing/empty or contains a non-integer or
  negative entry.
- Throws if the \`input\` port is not wired.
- Throws at run time if any index addresses past the end of the input.`,
  params: new Map([
    [
      "indices",
      "Array of source byte positions. output[i] = input[indices[i]]; output length = indices.length. AES ShiftRows derives this from the per-row shift schedule under the column-major convention.",
    ],
  ]),
  references: ["FIPS-197 §5.1.2 (ShiftRows)", "FIPS-197 §5.3.1 (InvShiftRows)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
