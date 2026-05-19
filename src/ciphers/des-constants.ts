/**
 * DES (Data Encryption Standard) tables and S-boxes from FIPS 46-3.
 *
 * All bit indices in these tables are FIPS-style: 1-indexed, MSB-first
 * within each byte. The companion helpers in `src/steps/des-bit-ops.ts`
 * (`readFipsBit`, `fipsPermute`) honor that convention; consumers should
 * NOT mix these tables with Serpent's LSB-first `applyBitPermutation`.
 *
 * The values are copied verbatim from FIPS 46-3 (Data Encryption Standard,
 * withdrawn 2005) and cross-checked against the Phase-1 verification oracle
 * at `scripts/verify-des.mjs`, which produced `tests/fixtures/des-kat.json`.
 *
 * Notes on each table:
 *   • IP — Initial Permutation, 64 → 64 bits. Output bit `i+1` reads
 *     input bit `IP[i]`. The oracle's KAT pins this.
 *   • FP — Final Permutation = IP^-1, 64 → 64 bits.
 *   • E  — Expansion, 32 → 48 bits. Each output bit comes from one of the
 *     32 input bits; some input bits feed two output positions (the source
 *     of DES's diffusion).
 *   • P  — Post-S-box permutation, 32 → 32 bits.
 *   • PC-1 — Permuted Choice 1, 64 → 56 bits. The 8 parity bits (positions
 *     8, 16, 24, 32, 40, 48, 56, 64) are dropped — never referenced by any
 *     entry in PC-1.
 *   • PC-2 — Permuted Choice 2, 56 → 48 bits. Picks the 48 bits of K_i
 *     from C_i || D_i after each per-round shift.
 *   • SHIFTS — per-round left-shift amounts on the 28-bit C, D halves.
 *     Cumulative total over 16 rounds = 28, so C_16 = C_0 (the key
 *     schedule cycles).
 *   • SBOX — 8 substitution boxes; each is 4 rows × 16 cols of 4-bit
 *     values. For 6-bit input b1..b6: row = `(b1 << 1) | b6`, column =
 *     `(b2 << 3) | (b3 << 2) | (b4 << 1) | b5`. The 8 S-boxes operate
 *     in parallel on the 8 6-bit groups of the 48-bit S-box input.
 *
 * The tables are exposed as plain `number[]` / `number[][][]` arrays so a
 * `CipherSpec` JSON document can carry them as params. The step types
 * (`des.s-boxes@1`, `des.initial-permutation@1`, …) take the table as a
 * param rather than referencing this module — keeps the spec self-contained
 * for save/load and lets a user pedagogically experiment with non-standard
 * tables in the editor.
 */

// IP — Initial Permutation (64 → 64). FIPS 46-3 Table 1.
export const DES_IP: readonly number[] = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
  56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
  45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

// FP = IP^-1 — Final Permutation (64 → 64). FIPS 46-3 Table 2 (IP^-1).
export const DES_FP: readonly number[] = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
  5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
  42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

// E — Expansion (32 → 48). FIPS 46-3 Table E (Bit-Selection Table).
export const DES_E: readonly number[] = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
  20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

// P — Post-S-box permutation (32 → 32). FIPS 46-3 Table P.
export const DES_P: readonly number[] = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
  30, 6, 22, 11, 4, 25,
];

// PC-1 — Permuted Choice 1 (64 → 56). FIPS 46-3 Table PC-1. Drops the 8
// parity bits (positions 8, 16, 24, 32, 40, 48, 56, 64 — never appear in
// this table). Output is conceptually C0 (first 28 bits) || D0 (next 28).
export const DES_PC1: readonly number[] = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
  52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
  13, 5, 28, 20, 12, 4,
];

// PC-2 — Permuted Choice 2 (56 → 48). FIPS 46-3 Table PC-2. Picks 48 bits
// of K_i from C_i || D_i (after the per-round left shifts). The 56-bit
// input is treated as a flat sequence: bit 1 = first bit of C_i, bit 29 =
// first bit of D_i.
export const DES_PC2: readonly number[] = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
  31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

// Per-round left-shift amounts on the 28-bit C, D halves. FIPS 46-3
// Table on page 21. Cumulative = 28, so C_16 = C_0 (the key schedule cycles
// back to its starting position after the full 16 rounds).
export const DES_SHIFTS: readonly number[] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/**
 * 8 substitution boxes from FIPS 46-3 Appendix A. Each S-box maps 6 bits
 * to 4 bits. Indexed `DES_SBOXES[s][row][col]`:
 *   • `s` ∈ 0..7 — which S-box (S1..S8).
 *   • `row` ∈ 0..3 — `(b1 << 1) | b6` (outer two bits of the 6-bit input).
 *   • `col` ∈ 0..15 — `(b2 << 3) | (b3 << 2) | (b4 << 1) | b5` (inner four).
 *
 * The output is a 4-bit value, written MSB-first into the corresponding
 * 4-bit slot of the 32-bit S-box-output buffer.
 *
 * These tables are the **only** nonlinear component of DES; everything else
 * (E, P, IP, FP, the XOR with K) is linear over GF(2). Replacing them
 * (educational experimentation in the editor) breaks the cipher's security
 * but not its structure — the trace still runs cleanly.
 */
export const DES_SBOXES: readonly (readonly (readonly number[])[])[] = [
  // S1
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],
  // S2
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],
  // S3
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],
  // S4
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],
  // S5
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],
  // S6
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],
  // S7
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],
  // S8
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],
];

/**
 * FIPS 46-3 Appendix B — the standard "ground-truth" test vector. Plaintext
 * `0123456789abcdef` under key `133457799bbcdff1` produces ciphertext
 * `85e813540f0ab405`. The same vector drives `tests/fixtures/des-kat.json`'s
 * first entry; pinning it here keeps the spec file self-documenting.
 */
export const DES_FIPS_APPENDIX_B = {
  plaintext: "0123456789abcdef",
  key: "133457799bbcdff1",
  ciphertext: "85e813540f0ab405",
} as const;
