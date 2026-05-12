/**
 * Serpent S-box round-trip tests.
 *
 * Each of the 8 Serpent S-boxes must be a permutation of {0,…,15}, and the
 * paired inverse table must invert it exactly. These are cheap properties
 * to verify and they catch a transcription typo in `SERPENT_SBOXES`
 * loudly: a duplicate or out-of-range entry shows up immediately as a
 * round-trip failure.
 *
 * Also pins one entry per forward S-box against a known value (taken from
 * the Anderson/Biham/Knudsen appendix) so a wholesale table swap can't
 * pass the roundtrip while still being wrong.
 */

import { SERPENT_INV_SBOXES, SERPENT_SBOXES } from "@/ciphers/serpent-constants";
import { describe, expect, it } from "vitest";

describe("Serpent S-boxes — structural properties", () => {
  it("ships 8 forward S-boxes and 8 inverse S-boxes", () => {
    expect(SERPENT_SBOXES.length).toBe(8);
    expect(SERPENT_INV_SBOXES.length).toBe(8);
  });

  it.each([0, 1, 2, 3, 4, 5, 6, 7])("S_%d is a 16-entry permutation of {0..15}", (i) => {
    const sbox = SERPENT_SBOXES[i];
    expect(sbox).toBeDefined();
    if (!sbox) return;
    expect(sbox.length).toBe(16);
    // Every value in 0..15 must appear exactly once.
    const sorted = [...sbox].sort((a, b) => a - b);
    expect(sorted).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
  });

  it.each([0, 1, 2, 3, 4, 5, 6, 7])("S_%d ∘ S_%d^{-1} = identity", (i) => {
    const sbox = SERPENT_SBOXES[i];
    const inv = SERPENT_INV_SBOXES[i];
    if (!sbox || !inv) return;
    for (let x = 0; x < 16; x++) {
      const sx = sbox[x] ?? 0;
      expect(inv[sx]).toBe(x);
    }
  });

  it.each([0, 1, 2, 3, 4, 5, 6, 7])(
    "S_%d^{-1} ∘ S_%d = identity (double-check the other side)",
    (i) => {
      const sbox = SERPENT_SBOXES[i];
      const inv = SERPENT_INV_SBOXES[i];
      if (!sbox || !inv) return;
      for (let y = 0; y < 16; y++) {
        const iy = inv[y] ?? 0;
        expect(sbox[iy]).toBe(y);
      }
    },
  );

  // Pin one entry per forward S-box so a wholesale table swap (where every
  // sbox got replaced with a different permutation) can't pass the
  // structural checks above.
  it("pins specific entries against the Anderson/Biham/Knudsen tables", () => {
    expect(SERPENT_SBOXES[0]?.[0]).toBe(3); // S_0[0] = 3
    expect(SERPENT_SBOXES[1]?.[0]).toBe(15); // S_1[0] = 15
    expect(SERPENT_SBOXES[2]?.[0]).toBe(8); // S_2[0] = 8
    expect(SERPENT_SBOXES[3]?.[0]).toBe(0); // S_3[0] = 0
    expect(SERPENT_SBOXES[4]?.[0]).toBe(1); // S_4[0] = 1
    expect(SERPENT_SBOXES[5]?.[0]).toBe(15); // S_5[0] = 15
    expect(SERPENT_SBOXES[6]?.[0]).toBe(7); // S_6[0] = 7
    expect(SERPENT_SBOXES[7]?.[0]).toBe(1); // S_7[0] = 1
  });
});
