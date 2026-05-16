/**
 * Pure-function tests for the S-box validation helpers in
 * `src/ui/components/sbox-validation.ts`. These run in vitest's node
 * environment — no DOM — so they're fast and we KAT them against
 * simple, hand-checkable inputs rather than a 256-entry table.
 *
 * The helpers are size-parameterized (length determines the expected
 * permutation range `0..N-1`), so we exercise both small N (mirroring
 * Serpent's 4-bit S-box) and larger N (mirroring AES's 8-bit case).
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import {
  collisionGroupsByIndex,
  countRedundantDuplicates,
  findDuplicateIndices,
  repairToPermutation,
} from "@/ui/components/sbox-validation";
import { describe, expect, it } from "vitest";

describe("findDuplicateIndices", () => {
  it("returns an empty set for an already-bijective table", () => {
    // A simple identity permutation over 0..15: no duplicates anywhere.
    const identity = Array.from({ length: 16 }, (_, i) => i);
    expect(findDuplicateIndices(identity).size).toBe(0);
  });

  it("returns an empty set for the canonical AES S-box", () => {
    // AES_SBOX is the published FIPS-197 table and is a permutation of
    // 0..255 by construction. If this ever fails, the constant has been
    // corrupted.
    expect(findDuplicateIndices(AES_SBOX).size).toBe(0);
  });

  it("returns every index of a 2-cell collision", () => {
    // Indices 0 and 2 both hold value 3; both should be flagged.
    const values = [3, 5, 3, 0];
    const dupes = findDuplicateIndices(values);
    expect(dupes.has(0)).toBe(true);
    expect(dupes.has(2)).toBe(true);
    expect(dupes.has(1)).toBe(false);
    expect(dupes.has(3)).toBe(false);
  });

  it("flags every cell of a 3-way collision", () => {
    // Three indices share value 7 → all three flagged, the lone 1 is not.
    const values = [7, 1, 7, 7];
    const dupes = findDuplicateIndices(values);
    expect(dupes.has(0)).toBe(true);
    expect(dupes.has(2)).toBe(true);
    expect(dupes.has(3)).toBe(true);
    expect(dupes.has(1)).toBe(false);
  });
});

describe("countRedundantDuplicates", () => {
  it("is 0 for a bijection", () => {
    const identity = Array.from({ length: 16 }, (_, i) => i);
    expect(countRedundantDuplicates(identity)).toBe(0);
  });

  it("counts (k - 1) per collision group", () => {
    // One pair (2 cells, value 3) → 1 redundant cell.
    // One triple (3 cells, value 7) → 2 redundant cells.
    // Total: 3 redundant cells.
    const values = [3, 7, 3, 7, 7, 1];
    expect(countRedundantDuplicates(values)).toBe(3);
  });

  it("matches the user's mental model: 'how many cells need to change?'", () => {
    // If every cell holds 0, every cell except the first is redundant.
    const allZero = new Array<number>(8).fill(0);
    expect(countRedundantDuplicates(allZero)).toBe(7);
  });
});

describe("collisionGroupsByIndex", () => {
  it("maps each duplicate index to the full collision group", () => {
    const values = [3, 1, 3, 7, 7, 7];
    const groups = collisionGroupsByIndex(values);

    // Two collision groups: {0, 2} for value 3, and {3, 4, 5} for value 7.
    expect(groups.get(0)).toEqual([0, 2]);
    expect(groups.get(2)).toEqual([0, 2]);
    expect(groups.get(3)).toEqual([3, 4, 5]);
    expect(groups.get(4)).toEqual([3, 4, 5]);
    expect(groups.get(5)).toEqual([3, 4, 5]);

    // Lone value 1 isn't a collision — index 1 has no entry.
    expect(groups.has(1)).toBe(false);
  });
});

describe("repairToPermutation", () => {
  it("is the identity on a table that is already a permutation", () => {
    // Property: if input is already in 0..N-1 bijectively, output
    // equals input (modulo array identity — it's always a fresh copy).
    const input = [4, 2, 7, 0, 1, 5, 6, 3];
    const output = repairToPermutation(input);
    expect(output).toEqual(input);
    // Always a fresh array (callers rely on reference identity).
    expect(output).not.toBe(input);
  });

  it("fills a single duplicate with the missing value", () => {
    // `1` is missing; the second `0` should be replaced with it.
    expect(repairToPermutation([0, 0, 2, 3])).toEqual([0, 1, 2, 3]);
  });

  it("keeps the leftmost occurrence of each duplicate (leftmost wins)", () => {
    // Value 3 appears at indices 1 and 3. Leftmost (1) keeps its 3;
    // rightmost (3) takes the missing value (0).
    expect(repairToPermutation([2, 3, 1, 3])).toEqual([2, 3, 1, 0]);
  });

  it("consumes missing values in ascending order", () => {
    // All zeros over length 4 → missing = {1, 2, 3}.
    // Leftmost wins: index 0 keeps 0, indices 1,2,3 receive 1,2,3.
    expect(repairToPermutation([0, 0, 0, 0])).toEqual([0, 1, 2, 3]);
  });

  it("handles a multi-group collision", () => {
    // Value 0 appears twice (idx 0, 3); value 7 appears twice (idx 4, 5).
    // Missing values: {1, 5} in ascending order.
    // Walk: keep idx0=0, keep idx1=2, keep idx2=3, idx3 dup → 1,
    //       idx4=7 keep, idx5=7 dup → 5, idx6=4 keep, idx7=6 keep.
    expect(repairToPermutation([0, 2, 3, 0, 7, 7, 4, 6])).toEqual([0, 2, 3, 1, 7, 5, 4, 6]);
  });

  it("produces a permutation of 0..N-1 even for pathological input", () => {
    // Property test: every cell holds the same out-of-range value.
    // The repair must still produce a valid permutation of 0..7.
    const pathological = new Array<number>(8).fill(999);
    const repaired = repairToPermutation(pathological);
    expect(repaired.length).toBe(8);
    expect(new Set(repaired)).toEqual(new Set([0, 1, 2, 3, 4, 5, 6, 7]));
  });

  it("scales to AES's 256-entry case", () => {
    // Build a sabotaged copy of AES_SBOX with one duplicate, repair it,
    // confirm we get back a permutation of 0..255.
    const sabotaged = AES_SBOX.slice();
    sabotaged[0x10] = sabotaged[0x00] ?? 0; // force a collision
    const repaired = repairToPermutation(sabotaged);
    expect(repaired.length).toBe(256);
    expect(new Set(repaired).size).toBe(256);
    // And every value in 0..255 appears exactly once.
    for (let v = 0; v < 256; v++) {
      expect(repaired.includes(v)).toBe(true);
    }
  });
});
