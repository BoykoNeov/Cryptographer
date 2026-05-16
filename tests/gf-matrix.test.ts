/**
 * GF(2^8) matrix algebra tests for `src/core/state/gf-matrix.ts`.
 *
 * Tests are layered so a failure isolates the bug:
 *   1. `gfMul` (already shipped) sanity-check against published pairs —
 *      catches the "wrong irreducible polynomial" failure mode in milliseconds.
 *   2. `gfInverse` spot-checks against known pairs + the field property
 *      (every nonzero `a` has a unique `b` with `a·b = 1`).
 *   3. `gfMatInverse4x4` Known-Answer Test: invert `AES_MIX_MATRIX` and
 *      assert byte-for-byte equality with `AES_INV_MIX_MATRIX` (FIPS-197
 *      §5.3.3). This is the test the whole module exists to pass.
 *   4. Round-trip property: for several random invertible 4×4s, assert
 *      `M · M⁻¹ = I`. Catches subtle Gauss-Jordan bugs (wrong row swap,
 *      missing pivot scale) that the canonical KAT might miss because
 *      AES_MIX_MATRIX has a special structure.
 *   5. Singular matrices throw — this is the gating signal the UI relies
 *      on to disable the Sync button.
 */

import { AES_INV_MIX_MATRIX, AES_MIX_MATRIX } from "@/ciphers/aes-constants";
import { gfInverse, gfMatInverse4x4, gfMatMul4x4 } from "@/core/state/gf-matrix";
import { gfMul } from "@/core/state/matrix";
import { describe, expect, it } from "vitest";

describe("gfMul sanity (precondition for gfInverse correctness)", () => {
  // The KAT that confirms the AES irreducible polynomial is the one
  // implemented. If the polynomial were wrong (e.g. someone swapped in
  // x^8 + x^4 + x^3 + x^2 + 1), `gfInverse` would still build a
  // self-consistent table but it would be the WRONG table — and the
  // matrix-inverse KAT would fail with hard-to-read off-by-bits errors.
  // This test catches the polynomial-mix-up in five seconds.
  it("gfMul(2, 0x8d) === 1 (the textbook GF(2^8) pair under the AES polynomial)", () => {
    expect(gfMul(2, 0x8d)).toBe(1);
  });

  it("gfMul(1, x) === x for several x (multiplicative identity)", () => {
    for (const x of [0x00, 0x01, 0x57, 0xff]) {
      expect(gfMul(1, x)).toBe(x);
    }
  });
});

describe("gfInverse — multiplicative inverse over GF(2^8)", () => {
  it("gfInverse(1) === 1 (self-inverse identity)", () => {
    expect(gfInverse(1)).toBe(1);
  });

  it("gfInverse(2) === 0x8d (the other half of the gfMul KAT)", () => {
    expect(gfInverse(2)).toBe(0x8d);
  });

  // The field property — every nonzero element has a unique inverse. If
  // any `a` fails this, the inverseTable was built incorrectly.
  it("for every a ∈ 1..255: gfMul(a, gfInverse(a)) === 1", () => {
    for (let a = 1; a < 256; a++) {
      const inv = gfInverse(a);
      expect(gfMul(a, inv)).toBe(1);
    }
  });

  // The inverse must itself be in the nonzero range. (A bug that
  // mapped some `a` to 0 would silently break Gauss-Jordan later.)
  it("gfInverse never returns 0", () => {
    for (let a = 1; a < 256; a++) {
      expect(gfInverse(a)).toBeGreaterThan(0);
    }
  });

  it("gfInverse(0) throws", () => {
    expect(() => gfInverse(0)).toThrow(/zero/i);
  });

  // Inverse is its own inverse — same as in any field, dispels any
  // doubt about the table being asymmetric (inverseTable[a] = b but
  // inverseTable[b] !== a would corrupt round-trip multiplications).
  it("gfInverse is involutive: gfInverse(gfInverse(a)) === a", () => {
    for (let a = 1; a < 256; a++) {
      expect(gfInverse(gfInverse(a))).toBe(a);
    }
  });
});

describe("gfMatInverse4x4 — the KAT this whole module exists to pass", () => {
  // FIPS-197 §5.3.3: the InvMixColumns matrix IS the GF(2^8) inverse of
  // the MixColumns matrix. If our inverter is correct, applying it to
  // AES_MIX_MATRIX must produce AES_INV_MIX_MATRIX byte-for-byte. No
  // floating-point comparison nonsense — this is integer arithmetic in
  // a finite field.
  it("gfMatInverse4x4(AES_MIX_MATRIX) === AES_INV_MIX_MATRIX (FIPS-197 §5.3.3)", () => {
    const inv = gfMatInverse4x4(AES_MIX_MATRIX);
    expect(inv).toEqual(AES_INV_MIX_MATRIX.map((row) => [...row]));
  });

  // And the reverse direction. If MixColumns is M and InvMixColumns is
  // M⁻¹, then inverting InvMixColumns must give back M. (Both matrices
  // are published; both should be the inverse of each other in this
  // field. A directional bug in row reduction would let one direction
  // pass while breaking the other.)
  it("gfMatInverse4x4(AES_INV_MIX_MATRIX) === AES_MIX_MATRIX (involution)", () => {
    const inv = gfMatInverse4x4(AES_INV_MIX_MATRIX);
    expect(inv).toEqual(AES_MIX_MATRIX.map((row) => [...row]));
  });

  // M · M⁻¹ = I for the canonical pair. Multiplying via `gfMatMul4x4`
  // exercises a different code path (no row reduction) and double-checks
  // the inverter via independent math.
  it("AES_MIX_MATRIX · AES_INV_MIX_MATRIX === I (under GF(2^8) multiplication)", () => {
    const product = gfMatMul4x4(AES_MIX_MATRIX, AES_INV_MIX_MATRIX);
    expect(product).toEqual([
      [1, 0, 0, 0],
      [0, 1, 0, 0],
      [0, 0, 1, 0],
      [0, 0, 0, 1],
    ]);
  });
});

describe("gfMatInverse4x4 — round-trip property on diverse matrices", () => {
  // Random-ish 4×4s that we KNOW are invertible (the canonical AES pair
  // plus a few transforms that preserve invertibility — multiplying every
  // entry by a nonzero scalar keeps the determinant nonzero). For each,
  // assert `M · M⁻¹ = I`. Catches Gauss-Jordan bugs that the
  // canonical-only KAT might miss because AES_MIX_MATRIX has a special
  // circulant structure.
  const identity4x4 = [
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
  ];

  const cases: { label: string; matrix: readonly (readonly number[])[] }[] = [
    { label: "identity (trivial — pinning the easy case)", matrix: identity4x4 },
    { label: "AES_MIX_MATRIX (circulant — the canonical case)", matrix: AES_MIX_MATRIX },
    {
      label: "AES_INV_MIX_MATRIX (circulant — the inverse of the canonical)",
      matrix: AES_INV_MIX_MATRIX,
    },
    {
      label: "diagonal {2,3,4,5} (non-trivial pivots in every column)",
      matrix: [
        [2, 0, 0, 0],
        [0, 3, 0, 0],
        [0, 0, 4, 0],
        [0, 0, 0, 5],
      ],
    },
    {
      label: "lower-triangular with mixed pivots (forces row-swap-free reduction)",
      matrix: [
        [3, 0, 0, 0],
        [7, 5, 0, 0],
        [9, 2, 0xa, 0],
        [4, 0xb, 6, 0xd],
      ],
    },
  ];

  for (const { label, matrix } of cases) {
    it(`round-trip: ${label} satisfies M · M⁻¹ = I`, () => {
      const inv = gfMatInverse4x4(matrix);
      const product = gfMatMul4x4(matrix, inv);
      expect(product).toEqual(identity4x4);
    });
  }
});

describe("gfMatInverse4x4 — singular matrices throw (the UI gating signal)", () => {
  // An all-zero row makes the matrix non-invertible regardless of field —
  // there's no row that has a nonzero pivot for that column when it
  // surfaces (every row at or below has 0 in that column).
  it("all-zero row throws", () => {
    const singular = [
      [1, 2, 3, 4],
      [0, 0, 0, 0],
      [5, 6, 7, 8],
      [9, 0xa, 0xb, 0xc],
    ];
    expect(() => gfMatInverse4x4(singular)).toThrow(/singular/i);
  });

  // Two identical rows make the matrix singular over any field
  // (row1 - row2 = 0 means there's no full-rank pivot sequence). In
  // GF(2^8) "subtraction" is XOR, so two equal rows XOR to a zero row
  // during reduction.
  it("two identical rows throws", () => {
    const singular = [
      [1, 2, 3, 4],
      [5, 6, 7, 8],
      [1, 2, 3, 4],
      [9, 0xa, 0xb, 0xc],
    ];
    expect(() => gfMatInverse4x4(singular)).toThrow(/singular/i);
  });

  // The 4×4 zero matrix has no pivot at all in column 0 — catches the
  // first-column-singular branch.
  it("zero matrix throws", () => {
    const zero = [
      [0, 0, 0, 0],
      [0, 0, 0, 0],
      [0, 0, 0, 0],
      [0, 0, 0, 0],
    ];
    expect(() => gfMatInverse4x4(zero)).toThrow(/singular/i);
  });
});

describe("gfMatInverse4x4 — input-shape validation", () => {
  it("rejects a non-4-row matrix", () => {
    expect(() =>
      gfMatInverse4x4([
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
      ]),
    ).toThrow(/4 rows/i);
  });

  it("rejects a non-4-column row", () => {
    expect(() =>
      gfMatInverse4x4([
        [1, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
      ]),
    ).toThrow(/4 columns/i);
  });
});
