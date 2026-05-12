/**
 * Serpent IP/FP round-trip tests.
 *
 * IP and FP are mutual inverses (one is `output_bit[i] = input_bit[IP[i]]`,
 * the other is the inverse permutation). Pinning this property catches:
 *  - Transcription typos in either table (a swapped pair shows up
 *    immediately as a non-identity round-trip).
 *  - Bit-numbering convention mismatches between the step executor and
 *    the table — if my IP/FP tables were intended for MSB-first bytes
 *    but my executor reads LSB-first, the round-trip would still pass
 *    (both directions use the same wrong convention) BUT cross-checks
 *    against the cipher KAT would not. The structural test is necessary
 *    but not sufficient — the KAT test is what nails down convention.
 */

import { SERPENT_FP, SERPENT_IP } from "@/ciphers/serpent-constants";
import { applyBitPermutation } from "@/steps/serpent-bit-ops";
import { describe, expect, it } from "vitest";

describe("Serpent IP/FP — structural properties", () => {
  it("both tables have 128 entries", () => {
    expect(SERPENT_IP.length).toBe(128);
    expect(SERPENT_FP.length).toBe(128);
  });

  it("IP and FP are mutual inverses (IP[FP[i]] === i for all i)", () => {
    for (let i = 0; i < 128; i++) {
      const fp_i = SERPENT_FP[i] ?? 0;
      expect(SERPENT_IP[fp_i]).toBe(i);
    }
  });

  it("FP[IP[i]] === i for all i (other direction)", () => {
    for (let i = 0; i < 128; i++) {
      const ip_i = SERPENT_IP[i] ?? 0;
      expect(SERPENT_FP[ip_i]).toBe(i);
    }
  });

  it("both tables are permutations of {0..127}", () => {
    const ipSorted = [...SERPENT_IP].sort((a, b) => a - b);
    const fpSorted = [...SERPENT_FP].sort((a, b) => a - b);
    const expected = Array.from({ length: 128 }, (_, i) => i);
    expect(ipSorted).toEqual(expected);
    expect(fpSorted).toEqual(expected);
  });

  it("applying IP then FP to a random state returns the original state", () => {
    // Deterministic "random" pattern so the test is reproducible.
    const original = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      original[i] = (i * 17 + 3) & 0xff;
    }
    const afterIP = applyBitPermutation(original, SERPENT_IP);
    const afterFP = applyBitPermutation(afterIP, SERPENT_FP);
    expect(Array.from(afterFP)).toEqual(Array.from(original));
  });

  it("applying FP then IP to a random state returns the original state", () => {
    const original = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      original[i] = (i * 31 + 11) & 0xff;
    }
    const afterFP = applyBitPermutation(original, SERPENT_FP);
    const afterIP = applyBitPermutation(afterFP, SERPENT_IP);
    expect(Array.from(afterIP)).toEqual(Array.from(original));
  });

  it("pinned IP entries (sanity check the table itself)", () => {
    // From the reference C source: IP[0..3] = 0, 32, 64, 96.
    // These are the source bit positions for output bits 0..3 — the
    // four-way interleaving that aligns bits for the bitsliced S-box layer.
    expect(SERPENT_IP[0]).toBe(0);
    expect(SERPENT_IP[1]).toBe(32);
    expect(SERPENT_IP[2]).toBe(64);
    expect(SERPENT_IP[3]).toBe(96);
    expect(SERPENT_IP[4]).toBe(1);
    expect(SERPENT_IP[127]).toBe(127);
  });

  it("pinned FP entries (sanity check the inverse)", () => {
    expect(SERPENT_FP[0]).toBe(0);
    expect(SERPENT_FP[1]).toBe(4);
    expect(SERPENT_FP[2]).toBe(8);
    expect(SERPENT_FP[127]).toBe(127);
  });
});
