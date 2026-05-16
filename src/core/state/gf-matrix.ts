/**
 * GF(2^8) matrix algebra: multiplicative inverse + 4×4 matrix inverse
 * via Gauss-Jordan elimination over the AES finite field.
 *
 * The MixColumns step holds its mixing matrix as a parameter (so users
 * can edit it and experiment). To offer "Sync inverse MixColumns to
 * counterpart" as a cross-mode mirror affordance (the class-2 inverse-
 * mirror operation that pairs `AES_MIX_MATRIX` ↔ `AES_INV_MIX_MATRIX`),
 * we need to invert an arbitrary user-edited 4×4 over GF(2^8) — not just
 * recognize the canonical pair. This module provides both pieces:
 *
 *   • `gfInverse(a)` — the multiplicative inverse of `a` ∈ 1..255 in the
 *     AES polynomial field. Backed by a lazily-built 256-entry lookup
 *     table (one-time O(256^2) cost the first time it's called, all
 *     subsequent lookups O(1)). `gfInverse(0)` throws — zero has no
 *     inverse, and the singular-matrix path should detect it before
 *     reaching here.
 *   • `gfMatInverse4x4(M)` — Gauss-Jordan elimination on the augmented
 *     `[M | I]` 4×8 matrix using `gfMul` / `gfInverse` for row scaling
 *     and `^` (XOR) as the field "addition." Throws if `M` is singular
 *     over GF(2^8); the catch path is the disabled-button gating signal
 *     for the Sync row (`ParamEditor.tsx` → `SyncMixColumnsRow`).
 *
 * **Why not lookup-only:** the canonical AES_INV_MIX_MATRIX is one
 * specific table; the user can edit the matrix freely (the project's
 * "cipher is data" stance), so we need to invert arbitrary 4×4s, not
 * just the canonical one. A hard-coded lookup would defeat the
 * pedagogical point.
 *
 * **Field reminder:** GF(2^8) addition IS XOR (no carries). Subtraction
 * IS XOR (its own inverse). Multiplication is via the irreducible
 * polynomial x^8 + x^4 + x^3 + x + 1 (FIPS-197 §4.2), implemented by
 * `gfMul` in `matrix.ts`. Imported, not re-implemented.
 */

import { gfMul } from "./matrix";

// Lazy cache. Populated on first `gfInverse` call by an O(255^2) brute-
// force loop (a × b for all pairs until product = 1). Fits in memory
// trivially (256 bytes). The build is gated behind module-level
// `let inverseTable | null` so test runs that never touch this module
// don't pay the cost.
let inverseTable: Uint8Array | null = null;

const buildInverseTable = (): Uint8Array => {
  // inverseTable[a] = the unique b ∈ 1..255 with gfMul(a, b) === 1.
  // inverseTable[0] is left as 0 — gfInverse throws before reaching it,
  // and 0 has no multiplicative inverse in any field.
  const table = new Uint8Array(256);
  for (let a = 1; a < 256; a++) {
    for (let b = 1; b < 256; b++) {
      if (gfMul(a, b) === 1) {
        table[a] = b;
        break;
      }
    }
  }
  return table;
};

/**
 * Multiplicative inverse of `a` in GF(2^8) under the AES polynomial.
 * Throws on `a === 0` (zero has no inverse).
 *
 * Spot-check known values: `gfInverse(1) === 1`, `gfInverse(2) === 0x8d`
 * (because `xtime(0x8d) = (0x1a XOR 0x1b) = 0x01`).
 */
export const gfInverse = (a: number): number => {
  const byte = a & 0xff;
  if (byte === 0) {
    throw new Error("gfInverse: zero has no multiplicative inverse in GF(2^8)");
  }
  if (inverseTable === null) inverseTable = buildInverseTable();
  return inverseTable[byte] ?? 0;
};

/**
 * Gauss-Jordan inverse of a 4×4 matrix over GF(2^8).
 *
 * Algorithm — straight from any linear-algebra text, with field
 * operations swapped for GF(2^8):
 *   1. Form the augmented `[M | I]` 4×8 matrix.
 *   2. For each column `c` ∈ 0..3:
 *      a. Find a row `r` ≥ `c` with a nonzero entry in column `c`
 *         (the "pivot"). Swap rows if `r !== c`. If no such row
 *         exists, the matrix is singular — throw.
 *      b. Scale row `c` by `gfInverse(pivot)` so its column-`c`
 *         entry becomes 1.
 *      c. For every other row `r' !== c`: if column-`c` entry of
 *         `r'` is nonzero, add (XOR) `gfMul(entry, row c)` to row `r'`
 *         to zero out column `c` in that row.
 *   3. After all four pivots, the left half is the identity and the
 *      right half is `M⁻¹`. Return the right half.
 *
 * Throws on singular `M` (no pivot found in some column). The caller
 * catches the throw and disables the Sync button — there's no "Repair"
 * affordance for a 4×4 matrix the way there is for an S-box (a user
 * has to edit cells back to invertibility by hand).
 *
 * KAT: `gfMatInverse4x4(AES_MIX_MATRIX) === AES_INV_MIX_MATRIX`
 * byte-for-byte (pinned by tests).
 */
export const gfMatInverse4x4 = (M: readonly (readonly number[])[]): number[][] => {
  if (M.length !== 4) {
    throw new Error(`gfMatInverse4x4: expected 4 rows, got ${M.length}`);
  }
  // Build the augmented matrix as a mutable 4×8. Mask each input byte to
  // stay in 0..255 — protects against accidentally passing 16-bit values
  // from an upstream typo.
  const aug: number[][] = [];
  for (let r = 0; r < 4; r++) {
    const row = M[r];
    if (!row || row.length !== 4) {
      throw new Error(`gfMatInverse4x4: row ${r} must have 4 columns, got ${row?.length}`);
    }
    const wide = new Array<number>(8).fill(0);
    for (let c = 0; c < 4; c++) wide[c] = (row[c] ?? 0) & 0xff;
    wide[4 + r] = 1; // identity in the right half
    aug.push(wide);
  }

  for (let c = 0; c < 4; c++) {
    // Find a pivot row at or below row c with a nonzero entry in column c.
    let pivotRow = -1;
    for (let r = c; r < 4; r++) {
      if ((aug[r]?.[c] ?? 0) !== 0) {
        pivotRow = r;
        break;
      }
    }
    if (pivotRow === -1) {
      throw new Error(`gfMatInverse4x4: matrix is singular over GF(2^8) (no pivot in column ${c})`);
    }
    // Swap rows so the pivot lives on the diagonal.
    if (pivotRow !== c) {
      const tmp = aug[c];
      const other = aug[pivotRow];
      if (tmp && other) {
        aug[c] = other;
        aug[pivotRow] = tmp;
      }
    }

    // Scale row c so its column-c entry becomes 1.
    const rowC = aug[c];
    if (!rowC) throw new Error("gfMatInverse4x4: row vanished mid-elimination (impossible)");
    const pivot = rowC[c] ?? 0;
    const pivotInv = gfInverse(pivot);
    for (let k = 0; k < 8; k++) {
      rowC[k] = gfMul(rowC[k] ?? 0, pivotInv);
    }

    // Eliminate column c from every other row.
    for (let r = 0; r < 4; r++) {
      if (r === c) continue;
      const rowR = aug[r];
      if (!rowR) continue;
      const factor = rowR[c] ?? 0;
      if (factor === 0) continue;
      for (let k = 0; k < 8; k++) {
        rowR[k] = (rowR[k] ?? 0) ^ gfMul(factor, rowC[k] ?? 0);
      }
    }
  }

  // Extract the right half — that's the inverse.
  const inv: number[][] = [];
  for (let r = 0; r < 4; r++) {
    const row = aug[r];
    if (!row) throw new Error("gfMatInverse4x4: row vanished post-elimination (impossible)");
    inv.push([row[4] ?? 0, row[5] ?? 0, row[6] ?? 0, row[7] ?? 0]);
  }
  return inv;
};

/**
 * Cheap 4×4 multiplication over GF(2^8). Used by tests to verify
 * round-trip `M · M⁻¹ = I`; the production code path doesn't multiply
 * matrices (the runtime's `mixColumns` step multiplies matrix × column,
 * not matrix × matrix). Export keeps the test file from re-implementing
 * the same nine lines.
 */
export const gfMatMul4x4 = (
  A: readonly (readonly number[])[],
  B: readonly (readonly number[])[],
): number[][] => {
  const out: number[][] = [];
  for (let r = 0; r < 4; r++) {
    const row: number[] = [0, 0, 0, 0];
    for (let c = 0; c < 4; c++) {
      let acc = 0;
      for (let k = 0; k < 4; k++) {
        acc ^= gfMul(A[r]?.[k] ?? 0, B[k]?.[c] ?? 0);
      }
      row[c] = acc;
    }
    out.push(row);
  }
  return out;
};
