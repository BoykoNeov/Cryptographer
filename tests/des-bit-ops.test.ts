/**
 * Unit tests for `src/steps/des-bit-ops.ts` — the FIPS-style (MSB-first,
 * 1-indexed) bit helpers. The DES cipher KAT in `des-vectors.test.ts`
 * already pins these indirectly, but a focused unit test catches
 * subtle off-by-one bugs at the helper level before they cascade into
 * confusing cipher mismatches.
 */

import {
  bitsToFipsBytes,
  fipsBytesToBits,
  fipsPermute,
  readFipsBit,
  rotateBitsLeft,
} from "@/steps/des-bit-ops";
import { describe, expect, it } from "vitest";

describe("readFipsBit — MSB-first, 1-indexed", () => {
  // 0xAA = 10101010. Bit 1 = MSB = 1; bit 2 = 0; bit 3 = 1; …; bit 8 = LSB = 0.
  const buf = new Uint8Array([0xaa, 0x55]);
  it("bit 1 = MSB of byte 0", () => expect(readFipsBit(buf, 1)).toBe(1));
  it("bit 8 = LSB of byte 0", () => expect(readFipsBit(buf, 8)).toBe(0));
  it("bit 9 = MSB of byte 1 (0x55 = 01010101 → MSB = 0)", () =>
    expect(readFipsBit(buf, 9)).toBe(0));
  it("bit 16 = LSB of byte 1 (0x55 → LSB = 1)", () => expect(readFipsBit(buf, 16)).toBe(1));
});

describe("bitsToFipsBytes / fipsBytesToBits — round-trip", () => {
  it("8 bits round-trip to a single byte (MSB-first)", () => {
    const bits = [1, 0, 1, 0, 1, 0, 1, 0];
    const bytes = bitsToFipsBytes(bits);
    expect(bytes.length).toBe(1);
    expect(bytes[0]).toBe(0xaa);
    expect(fipsBytesToBits(bytes, 8)).toEqual(bits);
  });

  it("48 bits round-trip to a 6-byte buffer (DES round-key length)", () => {
    // A pattern with distinct bytes so off-by-one in packing surfaces.
    const expected = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
    const bits = fipsBytesToBits(expected, 48);
    const out = bitsToFipsBytes(bits);
    expect(out.length).toBe(6);
    expect(Array.from(out)).toEqual(Array.from(expected));
  });
});

describe("fipsPermute — applies a permutation table", () => {
  it("identity permutation = identity", () => {
    const buf = new Uint8Array([0xde, 0xad]);
    const idTable = Array.from({ length: 16 }, (_, i) => i + 1);
    const out = fipsPermute(buf, idTable, 16);
    expect(out.length).toBe(2);
    expect(Array.from(out)).toEqual([0xde, 0xad]);
  });

  it("reverse-bits permutation reverses an 8-bit input", () => {
    // input 0xC0 = 11000000 → reversed = 00000011 = 0x03
    const reverseTable = [8, 7, 6, 5, 4, 3, 2, 1];
    const out = fipsPermute(new Uint8Array([0xc0]), reverseTable, 8);
    expect(out[0]).toBe(0x03);
  });

  it("throws when table.length !== outLen", () => {
    expect(() => fipsPermute(new Uint8Array([0]), [1, 2], 3)).toThrow();
  });
});

describe("rotateBitsLeft — cyclic shift used in the DES key schedule", () => {
  it("shift by 0 is identity", () => {
    const bits = [1, 0, 1, 0, 0, 1];
    expect(rotateBitsLeft(bits, 0, 6)).toEqual(bits);
  });

  it("shift by 1 on length-4 [1,0,0,0] → [0,0,0,1]", () => {
    expect(rotateBitsLeft([1, 0, 0, 0], 1, 4)).toEqual([0, 0, 0, 1]);
  });

  it("shift by N is identity for length-N input", () => {
    const bits = [1, 1, 0, 1, 0, 1];
    expect(rotateBitsLeft(bits, 6, 6)).toEqual(bits);
  });
});
