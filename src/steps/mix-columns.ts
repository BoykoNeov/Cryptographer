import { gfMul, matAt, setMatAt } from "../core/state/matrix";
import type { Json, MatrixState, StepDocumentation, StepExecutor } from "../core/types";

/**
 * Multiply each column of the 4x4 state by a 4x4 GF(2^8) matrix.
 * AES forward: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
 * Inverse: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]].
 *
 * params: { matrix: number[4][4] }  // row-major coefficients
 */
export const mixColumns: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("mix-columns expects matrix4x4-bytes state");
  }
  const m = readMatrix(params);
  const next = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      let acc = 0;
      const row = m[r] as readonly number[];
      for (let k = 0; k < 4; k++) {
        acc ^= gfMul(row[k] ?? 0, matAt(state, k, c));
      }
      setMatAt(next, r, c, acc);
    }
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const mixColumnsDoc: StepDocumentation = {
  name: "Mix Columns",
  summary: "Multiply each column of the state by a 4×4 matrix in GF(2^8).",
  detail: `## Mix Columns

Each of the four columns of the state is treated as a 4-byte vector and
multiplied by a fixed 4×4 matrix. Arithmetic is over **GF(2^8)** — the
finite field of 256 elements — using the irreducible polynomial
\`x^8 + x^4 + x^3 + x + 1\`.

Standard AES forward matrix is mostly small constants \`{1, 2, 3}\`:

\`\`\`
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
\`\`\`

The inverse direction uses \`{9, 11, 13, 14}\`. Both are MDS matrices —
maximum-distance-separable — meaning a change to a single input byte
guarantees changes in **all four** output bytes.

**Why it matters:** this is the column-level **diffusion** step. ShiftRows
spread bytes between columns; MixColumns then spreads each column's
content across all four bytes within it. Together they ensure full
diffusion within two rounds of AES.

**Try it:** replace the matrix with the identity and run encryption. AES
becomes nothing more than SubBytes + ShiftRows + key XOR — a much weaker
cipher, breakable by hand on a couple of round outputs.`,
  params: new Map([
    [
      "matrix",
      "Row-major 4×4 array of GF(2^8) coefficients (0..255). Forward AES uses {1,2,3} entries; inverse uses {9,11,13,14}.",
    ],
  ]),
  references: [
    "FIPS-197 §5.1.3 (MixColumns)",
    "FIPS-197 §5.3.3 (InvMixColumns)",
    "FIPS-197 §4.2 (GF(2^8) arithmetic)",
  ],
};

const readMatrix = (params: Json): readonly (readonly number[])[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("matrix" in params)
  ) {
    throw new Error("mix-columns requires params.matrix");
  }
  const matrix = (params as { matrix: unknown }).matrix;
  if (!Array.isArray(matrix) || matrix.length !== 4) {
    throw new Error("matrix must be a 4x4 array");
  }
  for (const row of matrix) {
    if (!Array.isArray(row) || row.length !== 4) {
      throw new Error("matrix must be a 4x4 array");
    }
  }
  return matrix as readonly (readonly number[])[];
};
