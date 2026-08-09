/**
 * Tests for `shift-bits-left@1` — the fourth foundational port-native ARX
 * primitive (2026-08-09, for MT19937's tempering).
 *
 * Two concerns, paralleling `shift-bits-right.test.ts`:
 *   1. Pure executor unit tests — hand-derived KATs across all four
 *      `wordBits ∈ {8, 16, 32, 64}`, plus identity, multi-word, the
 *      `bits ≥ wordBits` short-circuit, and the zero-fill-at-the-BOTTOM
 *      property that distinguishes SHL from ROL.
 *   2. The signed-integer trap that is unique to the left-handed direction
 *      (see the `shl32` note below) — JS bitwise operators return SIGNED
 *      32-bit values, so `1 << 31` is negative and a missing `>>> 0` would
 *      corrupt exactly the words whose top bit lands set.
 *
 * KAT derivation: hand-derived from `SHL(w, n, B) = (w << n) & (2^B − 1)`.
 *
 * Direct executor calls, no `runSpec` — the same posture the rotate/shift
 * siblings take. MT19937's end-to-end wiring is covered by
 * `tests/mt19937-kat.test.ts`.
 */

import { shiftBitsLeft } from "@/steps/shift-bits-left";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callShl = (inputBytes: readonly number[], bits: number, wordBits: number): number[] => {
  const out = shiftBitsLeft(
    new Map([["input", Uint8Array.from(inputBytes)]]),
    { bits, wordBits },
    undefined as never,
  );
  const bytes = out.get("output");
  if (bytes === undefined) throw new Error("shift-bits-left produced no output port");
  return Array.from(bytes);
};

describe("shift-bits-left@1 — the executor", () => {
  it("shifts a 32-bit word left, dropping the bits that fall off the top", () => {
    // 0x12345678 << 4 = 0x123456780, truncated to 32 bits = 0x23456780.
    expect(callShl([0x12, 0x34, 0x56, 0x78], 4, 32)).toEqual([0x23, 0x45, 0x67, 0x80]);
  });

  it("zero-fills the BOTTOM, which is what distinguishes it from a rotation", () => {
    // A rotation would wrap 0xf0's top nibble round to the bottom, giving 0x0f.
    // A shift drops it and fills with zeros.
    expect(callShl([0xf0], 4, 8)).toEqual([0x00]);
    expect(callShl([0xff], 4, 8)).toEqual([0xf0]);
  });

  it("is the identity at bits = 0", () => {
    expect(callShl([0xde, 0xad, 0xbe, 0xef], 0, 32)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("zeroes the word when bits >= wordBits (the short-circuit)", () => {
    // JS `<<` truncates the shift amount modulo 32, so a raw `x << 32` would
    // return `x` unchanged. The executor short-circuits before reaching the
    // helper — the same hazard, and the same guard, as the right-handed step.
    expect(callShl([0xff, 0xff, 0xff, 0xff], 32, 32)).toEqual([0x00, 0x00, 0x00, 0x00]);
    expect(callShl([0xff, 0xff, 0xff, 0xff], 99, 32)).toEqual([0x00, 0x00, 0x00, 0x00]);
    expect(callShl([0xff], 8, 8)).toEqual([0x00]);
  });

  it("survives the signed-32 trap when the result's top bit lands set", () => {
    // 0x00000001 << 31 = 0x80000000, which JS's `<<` yields as the NEGATIVE
    // number -2147483648. Without the `>>> 0` in `shl32`, encoding that would
    // go wrong. This is the one asymmetry with the right-handed sibling, where
    // `>>>` is already unsigned.
    expect(callShl([0x00, 0x00, 0x00, 0x01], 31, 32)).toEqual([0x80, 0x00, 0x00, 0x00]);
    expect(callShl([0x00, 0x00, 0x00, 0x03], 31, 32)).toEqual([0x80, 0x00, 0x00, 0x00]);
  });

  it("shifts each word of a multi-word input independently", () => {
    // No carry crosses the word boundary: the second word's top byte does NOT
    // leak into the first word's bottom.
    expect(callShl([0x00, 0x01, 0xff, 0x02], 8, 16)).toEqual([0x01, 0x00, 0x02, 0x00]);
  });

  it("handles all four word widths", () => {
    expect(callShl([0x01], 1, 8)).toEqual([0x02]);
    expect(callShl([0x00, 0x01], 1, 16)).toEqual([0x00, 0x02]);
    expect(callShl([0x00, 0x00, 0x00, 0x01], 1, 32)).toEqual([0x00, 0x00, 0x00, 0x02]);
    expect(callShl([0, 0, 0, 0, 0, 0, 0, 0x01], 1, 64)).toEqual([0, 0, 0, 0, 0, 0, 0, 0x02]);
  });

  it("truncates at the top for 64-bit words too (the bigint path)", () => {
    // 0x8000000000000000 << 1 must be 0, not 2^64 — bigint `<<` grows without
    // bound, so the mask AFTER the shift is what keeps it a 64-bit word.
    expect(callShl([0x80, 0, 0, 0, 0, 0, 0, 0], 1, 64)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("rejects an input length that is not a multiple of the word size", () => {
    expect(() => callShl([0x01, 0x02, 0x03], 1, 32)).toThrow(/not a multiple of word size/);
  });

  it("rejects malformed params rather than coercing them", () => {
    expect(() => callShl([0x01], -1, 8)).toThrow(/params.bits must be a non-negative integer/);
    expect(() => callShl([0x01], 1, 24)).toThrow(/params.wordBits must be 8, 16, 32, or 64/);
  });

  it("reproduces MT19937's two tempering shifts", () => {
    // The forcing function, checked against hand arithmetic: for the twisted
    // word 0x9b0e2d3a, (y << 7) & 0x9d2c5680 and (y << 15) & 0xefc60000.
    const y = 0x9b0e2d3a;
    const shl7 = ((y << 7) >>> 0) & 0x9d2c5680;
    const shl15 = ((y << 15) >>> 0) & 0xefc60000;
    const be = (w: number): number[] => [
      (w >>> 24) & 0xff,
      (w >>> 16) & 0xff,
      (w >>> 8) & 0xff,
      w & 0xff,
    ];
    const got7 = callShl(be(y), 7, 32);
    const got15 = callShl(be(y), 15, 32);
    expect(got7.map((b, i) => b & (be(0x9d2c5680)[i] as number))).toEqual(be(shl7));
    expect(got15.map((b, i) => b & (be(0xefc60000)[i] as number))).toEqual(be(shl15));
  });
});
