/**
 * gf-matrix-multiply — port-native GF(2⁸) column-mixing primitive
 * (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * Treats the input as N consecutive 4-byte **columns** (column-major: bytes
 * `4c..4c+3` are column `c`) and multiplies each column by a fixed 4×4
 * matrix over GF(2⁸):
 *
 *   out[r + 4c] = ⊕_k  gfMul(matrix[r][k], in[k + 4c])
 *
 * One raw input port `input`, one raw output port `output`; output length
 * equals input length. Input length must be a multiple of 4. For AES the
 * input is 16 bytes = 4 columns.
 *
 * **The byte-native replacement for `generic.mix-columns@1`.** The legacy
 * step consumed/emitted a `MatrixState` (PortContract `layout:
 * "matrix-cm-4x4"`) and did the same per-column GF multiply. This primitive
 * does the identical arithmetic on a flat `Uint8Array`. GF math stays inside
 * the executor (the "medium primitive" granularity chosen for B1) rather
 * than decomposing into per-element `gf-mul` + `xor` — that finer
 * decomposition would explode the leaf count (~16 multiplies + 4 XORs per
 * column × every round) and is out of B1 scope.
 *
 * **Forward AND inverse.** AES MixColumns uses the `{1,2,3}` matrix;
 * InvMixColumns uses the `{9,11,13,14}` matrix. Same primitive, matrix
 * differs. The cross-mode mirror (class-2 inverse, computed by
 * `gfMatInverse4x4`) operates on `params.matrix`, re-pointed here from
 * `generic.mix-columns@1` in Slice B1.2.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Static port maps with `layout:"raw"` (no param
 * dependence) so the A4 anti-creep contract's kitchen-sink param resolution
 * never needs a `matrix` entry. Reuses `gfMul` from `core/state/matrix.ts`
 * (the GF(2⁸) multiply over the AES polynomial x⁸+x⁴+x³+x+1).
 */

import { gfMul } from "../core/state/matrix";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly matrix: readonly (readonly number[])[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("gf-matrix-multiply: params must be an object");
  }
  const p = params as Record<string, Json>;
  const matrix = p.matrix;
  if (!Array.isArray(matrix) || matrix.length !== 4) {
    throw new Error("gf-matrix-multiply: params.matrix must be a 4×4 array");
  }
  for (const row of matrix) {
    if (!Array.isArray(row) || row.length !== 4) {
      throw new Error("gf-matrix-multiply: params.matrix must be a 4×4 array");
    }
  }
  return { matrix: matrix as readonly (readonly number[])[] };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Static maps, `layout:"raw"` on both sides — keeps the leaf off the A4
 * `NON_BYTES_ALLOWLIST`. Output byteLength polymorphic (= input length).
 */
export const gfMatrixMultiplyPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const gfMatrixMultiply: PortedExecutor = (inputs, params, _ctx) => {
  const { matrix } = readParams(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error('gf-matrix-multiply: input port "input" is not wired');
  }
  if (input.length % 4 !== 0) {
    throw new Error(
      `gf-matrix-multiply: input length ${input.length} is not a multiple of 4 (expected N columns of 4 bytes)`,
    );
  }
  const columns = input.length / 4;
  const out = new Uint8Array(input.length);
  for (let c = 0; c < columns; c++) {
    for (let r = 0; r < 4; r++) {
      let acc = 0;
      const row = matrix[r] as readonly number[];
      for (let k = 0; k < 4; k++) {
        acc ^= gfMul(row[k] ?? 0, input[k + 4 * c] as number);
      }
      out[r + 4 * c] = acc & 0xff;
    }
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const gfMatrixMultiplyDoc: StepDocumentation = {
  name: "GF Matrix Multiply",
  summary:
    "Mixes each group of 4 bytes by multiplying it against a fixed 4×4 matrix in GF(2⁸) — AES's MixColumns.",
  detail: `# GF Matrix Multiply

Treats the input as N consecutive **columns** of 4 bytes each (column-major:
bytes \`4c..4c+3\` form column \`c\`) and multiplies every column by a fixed
4×4 matrix over **GF(2⁸)** — the finite field of 256 elements, using the
irreducible polynomial \`x⁸ + x⁴ + x³ + x + 1\`.

## Math

For each column \`c\` and output row \`r\`:

\`\`\`
out[r + 4c] = ⊕_k  gfMul(matrix[r][k], in[k + 4c])      (k = 0..3)
\`\`\`

Addition in GF(2⁸) is XOR; multiplication is polynomial multiplication mod
the AES reduction polynomial.

## Where it fits

In **AES** this is **MixColumns** (FIPS-197 §5.1.3). The forward matrix is
mostly small constants \`{1,2,3}\`:

\`\`\`
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
\`\`\`

The inverse (**InvMixColumns**, §5.3.3) uses \`{9,11,13,14}\`. Both are MDS
(maximum-distance-separable) matrices — a change to a single input byte
changes **all four** output bytes of its column.

## Why it matters

This is the column-level **diffusion** step. ShiftRows spreads bytes
between columns; MixColumns then spreads each column's content across all
four of its bytes. Together they give full diffusion within two AES rounds.
**Try it:** replace the matrix with the identity and AES collapses to
SubBytes + ShiftRows + key XOR — breakable by hand.`,
  params: new Map([
    [
      "matrix",
      "The 4×4 mixing matrix, given row by row (each coefficient 0–255). Forward AES uses {1,2,3} entries; the inverse used for decryption uses {9,11,13,14}.",
    ],
  ]),
  references: [
    "FIPS-197 §5.1.3 (MixColumns)",
    "FIPS-197 §5.3.3 (InvMixColumns)",
    "FIPS-197 §4.2 (GF(2⁸) arithmetic)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
