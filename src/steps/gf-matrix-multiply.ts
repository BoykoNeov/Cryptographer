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

import { gfMul, gfMulPoly } from "../core/state/matrix";
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

// ─── @2 — generalized over an arbitrary GF(2⁸) field polynomial ─────────────
//
// `@1` hardcodes AES's field (`gfMul`, polynomial 0x11B). Twofish's MDS matrix
// lives over a DIFFERENT field, GF(2⁸)/0x169, so it needs a modulus param.
// Rather than fork `@1` (AES depends on its hardcoded field and its
// AES-MixColumns-specific doc), `@2` adds a `fieldModulus` param backed by
// `gfMulPoly`. `@1` is left untouched. The default 0x11B gives byte-for-byte
// parity with `@1`, so `@2` is a strict generalization.

type ParamsV2 = {
  readonly matrix: readonly (readonly number[])[];
  readonly fieldModulus: number;
};

const readParamsV2 = (params: Json): ParamsV2 => {
  const { matrix } = readParams(params); // reuse the 4×4 validation
  const p = params as Record<string, Json>;
  const fm = p.fieldModulus;
  if (fm !== undefined && (typeof fm !== "number" || !Number.isInteger(fm) || fm < 0x100)) {
    throw new Error(
      "gf-matrix-multiply@2: params.fieldModulus must be a 9-bit reduction polynomial (≥ 0x100), e.g. 0x169",
    );
  }
  return { matrix, fieldModulus: (fm as number | undefined) ?? 0x11b };
};

/** Shares `@1`'s static raw-port contract — same surface, different field. */
export const gfMatrixMultiplyV2PortContract: PortContract = gfMatrixMultiplyPortContract;

export const gfMatrixMultiplyV2: PortedExecutor = (inputs, params, _ctx) => {
  const { matrix, fieldModulus } = readParamsV2(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error('gf-matrix-multiply@2: input port "input" is not wired');
  }
  if (input.length % 4 !== 0) {
    throw new Error(
      `gf-matrix-multiply@2: input length ${input.length} is not a multiple of 4 (expected N columns of 4 bytes)`,
    );
  }
  // 0x11B → delegate to the fast AES path (identical result); any other field
  // uses the parameterized reducer.
  const mul =
    fieldModulus === 0x11b ? gfMul : (a: number, b: number) => gfMulPoly(a, b, fieldModulus);
  const columns = input.length / 4;
  const out = new Uint8Array(input.length);
  for (let c = 0; c < columns; c++) {
    for (let r = 0; r < 4; r++) {
      let acc = 0;
      const row = matrix[r] as readonly number[];
      for (let k = 0; k < 4; k++) {
        acc ^= mul(row[k] ?? 0, input[k + 4 * c] as number);
      }
      out[r + 4 * c] = acc & 0xff;
    }
  }
  return new Map([["output", out]]);
};

export const gfMatrixMultiplyV2Doc: StepDocumentation = {
  name: "GF Matrix Multiply (any field)",
  summary:
    "Mixes each group of 4 bytes by a fixed 4×4 matrix in a chosen GF(2⁸) field — Twofish's MDS uses field 0x169.",
  detail: `# GF Matrix Multiply (any field)

Same column mixing as the AES-field version, but the **finite field** is a
parameter. Treats the input as N columns of 4 bytes each and multiplies every
column by a fixed 4×4 matrix over **GF(2⁸)**, reducing with the polynomial you
supply as \`fieldModulus\`:

\`\`\`
out[r + 4c] = ⊕_k  gfMul(matrix[r][k], in[k + 4c])      (k = 0..3)
\`\`\`

Addition in GF(2⁸) is XOR; multiplication is polynomial multiplication modulo
\`fieldModulus\`.

## Where it fits — Twofish MDS

Twofish's diffusion layer is an **MDS matrix** over the field
\`x⁸ + x⁶ + x⁵ + x³ + 1\` (= \`0x169\`), a different field from AES's
\`0x11B\`:

\`\`\`
[01 EF 5B 5B]
[5B EF EF 01]
[EF 5B 01 EF]
[EF 01 EF 5B]
\`\`\`

It is applied inside the **g function** to the four key-dependent S-box
outputs, spreading each byte's influence across the whole 32-bit word. Setting
\`fieldModulus\` to \`0x11B\` reproduces AES's MixColumns exactly, so this one
step covers both ciphers.

## Why a separate field matters

The choice of reduction polynomial changes the multiplication table entirely —
the same matrix over the wrong field gives wrong (and non-MDS) results. **Try
it:** switch \`fieldModulus\` to \`0x11B\` with the Twofish matrix and the
cipher breaks, because the g function no longer matches the key schedule that
built the S-boxes.`,
  params: new Map([
    [
      "matrix",
      "The 4×4 mixing matrix, given row by row (each coefficient 0–255). Twofish's MDS uses {01, EF, 5B} entries.",
    ],
    [
      "fieldModulus",
      "The GF(2⁸) reduction polynomial as a 9-bit number: 0x169 for Twofish's MDS, 0x11B for AES. Defaults to 0x11B.",
    ],
  ]),
  references: [
    "Twofish specification §4.3.2 (MDS matrix, GF(2⁸)/0x169)",
    "FIPS-197 §4.2 (GF(2⁸) arithmetic)",
  ],
};
