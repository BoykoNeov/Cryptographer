/**
 * Tests for `shift-bits-right@1` — third foundational port-native ARX
 * primitive (universal-port plan **Phase 2 Slice 2.5**, 2026-05-25).
 *
 * Three concerns, paralleling `rotate-bits-right.test.ts`:
 *   1. Pure executor unit tests — hand-derived KATs across all four
 *      `wordBits ∈ {8, 16, 32, 64}` plus identity, multi-word, the
 *      `bits ≥ wordBits` short-circuit edge case, and the all-zero-fill
 *      property unique to SHR (a property ROR doesn't have).
 *   2. Off-flag dispatch error: a single-leaf spec wiring this step type
 *      under `portedDispatchEnabled: false` throws the
 *      "requires portedDispatchEnabled: true" error.
 *   3. On-flag dispatch error: same spec under `portedDispatchEnabled:
 *      true` throws the "requires spec edge-wiring (Slice 2.6+)" error.
 *      Mirrors the rotate-bits-right@1 guard exactly — port-native step
 *      types without `meta` are unreachable via the dispatch path until
 *      SHA-256 lands.
 *
 * KAT derivation: hand-derived from `SHR(w, n, B) = (w >> n) & (2^B - 1)`.
 * Sign-extension gotcha note from Slice 2.3 still applies in the helpers
 * (`shr32` does `(x >>> 0) >>> n` to defend against signed input); the
 * tests use Uint8Array inputs which decode unsigned automatically.
 *
 * Direct executor calls — no `runSpec` for the KAT suite — for the same
 * reason as rotate-bits-right.test.ts: port-native steps are unreachable
 * via the dispatch path today and forcing them through runSpec would
 * require a legacy-stub registry, defeating Slice 2.1a's widening.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, StepContext } from "@/core/types";
import { shiftBitsRight } from "@/steps/shift-bits-right";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callShr = (
  inputBytes: readonly number[],
  bits: number,
  wordBits: 8 | 16 | 32 | 64,
): number[] => {
  const inputs = new Map([["input", new Uint8Array(inputBytes)]]);
  // Synthetic ctx — executor doesn't read aux/stepId/path; matches the
  // rotate-bits-right.test.ts stand-in.
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = shiftBitsRight(inputs, { bits, wordBits }, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("shift-bits-right: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("shift-bits-right@1 — executor (direct invocation)", () => {
  describe("identity (shift by 0)", () => {
    it("wordBits=32, single word", () => {
      expect(callShr([0x12, 0x34, 0x56, 0x78], 0, 32)).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("wordBits=8, single byte", () => {
      expect(callShr([0xa5], 0, 8)).toEqual([0xa5]);
    });

    it("wordBits=64, single word", () => {
      expect(callShr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0, 64)).toEqual([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      ]);
    });
  });

  describe("KAT — wordBits=32", () => {
    it("0x12345678 SHR 2 = 0x048D159E (low 2 bits drop, top zero-fill)", () => {
      // 0x12345678 = 0001 0010 0011 0100 0101 0110 0111 1000
      // Low 2 bits = 00 (drop).
      // After shift: 0000 0100 1000 1101 0001 0101 1001 1110 = 0x048D159E
      // (Identical to ROR 2 in this case because the dropped bits were 0 —
      //  the SHR-vs-ROR divergence shows up only when low bits are 1.)
      expect(callShr([0x12, 0x34, 0x56, 0x78], 2, 32)).toEqual([0x04, 0x8d, 0x15, 0x9e]);
    });

    it("0x12345679 SHR 2 = 0x048D159E (low 2 bits dropped — DIVERGES from ROR)", () => {
      // Same input pattern but low byte is 0x79 instead of 0x78. The low 2
      // bits are now 01 (instead of 00).
      // SHR: those bits DROP; top zero-fills → 0x048D159E (same as above).
      // ROR(0x12345679, 2) would wrap low 2 bits "01" to top 2 bits "01" →
      //   0x048D159E | 0x40000000 = 0x448D159E. THIS is the SHR/ROR split.
      // The composition KAT in tests/sha256-helpers.test.ts (Slice 2.5
      // sigma functions) is the load-bearing place this divergence
      // matters — pinning it here makes a future regression localizable.
      expect(callShr([0x12, 0x34, 0x56, 0x79], 2, 32)).toEqual([0x04, 0x8d, 0x15, 0x9e]);
    });

    it("0x80000001 SHR 1 = 0x40000000 (low bit drops, top zero-fills — NOT wraps)", () => {
      // The contrast with ROR is sharpest here: low bit "1" DROPS instead
      // of wrapping to position 31. Top bit becomes 0 (zero-fill), not 1
      // (rotated-in).
      expect(callShr([0x80, 0x00, 0x00, 0x01], 1, 32)).toEqual([0x40, 0x00, 0x00, 0x00]);
    });

    it("0xFFFFFFFF SHR 8 = 0x00FFFFFF (top byte zero-fills)", () => {
      // All-ones input shifted right by a byte: top byte becomes 0x00,
      // demonstrating the zero-fill semantic. ROR(0xFFFFFFFF, 8) =
      // 0xFFFFFFFF (a no-op for all-ones under rotation).
      expect(callShr([0xff, 0xff, 0xff, 0xff], 8, 32)).toEqual([0x00, 0xff, 0xff, 0xff]);
    });

    it("SHA-256 σ0 SHR 3 of 0x6A09E667 (H_0) = 0x0D413CCC", () => {
      // 0x6A09E667 = 0110 1010 0000 1001 1110 0110 0110 0111
      // SHR 3:      0000 1101 0100 0001 0011 1100 1100 1100 = 0x0D413CCC
      // Hand-derive: drop low 3 bits "111", zero-fill top 3 bits.
      // This is the SHR³ term of σ0(H_0) — load-bearing for the Slice 2.5
      // composition KAT.
      expect(callShr([0x6a, 0x09, 0xe6, 0x67], 3, 32)).toEqual([0x0d, 0x41, 0x3c, 0xcc]);
    });

    it("SHA-256 σ1 SHR 10 of 0xBB67AE85 (H_1) = 0x002ED9EB", () => {
      // 0xBB67AE85 shifted right by 10 positions; top 10 bits zero-fill.
      // Hand-derive: 0xBB67AE85 = 0b10111011_01100111_10101110_10000101.
      //   >> 10 = 0b00000000_00101110_11011001_11101011 (32-bit unsigned)
      //         = 0x002ED9EB
      // The SHR¹⁰ term of σ1(H_1) — load-bearing for Slice 2.5.
      expect(callShr([0xbb, 0x67, 0xae, 0x85], 10, 32)).toEqual([0x00, 0x2e, 0xd9, 0xeb]);
    });
  });

  describe("KAT — wordBits=16", () => {
    it("0x1234 SHR 4 = 0x0123 (top nibble zero-fills)", () => {
      // Low nibble 0x4 drops; top nibble zero-fills.
      // ROR(0x1234, 4) = 0x4123 (wraps the 0x4 to top).
      expect(callShr([0x12, 0x34], 4, 16)).toEqual([0x01, 0x23]);
    });

    it("0x8001 SHR 1 = 0x4000 (low bit drops)", () => {
      // ROR(0x8001, 1) = 0xC000; SHR drops the low 1 so result is 0x4000.
      expect(callShr([0x80, 0x01], 1, 16)).toEqual([0x40, 0x00]);
    });
  });

  describe("KAT — wordBits=8", () => {
    it("0x12 SHR 4 = 0x01 (top nibble zero-fills)", () => {
      // ROR(0x12, 4) = 0x21 (nibble swap); SHR drops low nibble → 0x01.
      expect(callShr([0x12], 4, 8)).toEqual([0x01]);
    });

    it("0xFF SHR 1 = 0x7F (top bit zero-fills)", () => {
      expect(callShr([0xff], 1, 8)).toEqual([0x7f]);
    });
  });

  describe("KAT — wordBits=64", () => {
    it("0x123456789ABCDEF0 SHR 8 = 0x00123456789ABCDE (top byte zero-fills)", () => {
      // ROR by 8 wraps low byte 0xF0 to top; SHR drops it and zero-fills.
      expect(callShr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 8, 64)).toEqual([
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
      ]);
    });

    it("0xFFFFFFFFFFFFFFFF SHR 32 = 0x00000000FFFFFFFF (top half zero-fills)", () => {
      // BigInt path: validates `shr64` and the 64-bit width bookkeeping.
      // ROR(0xFFFFFFFFFFFFFFFF, 32) = 0xFFFFFFFFFFFFFFFF (no-op for all
      // ones); SHR zero-fills the top half.
      expect(callShr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 32, 64)).toEqual([
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
      ]);
    });
  });

  describe("multi-word — each word shifts independently (no cross-word bleed)", () => {
    it("two 32-bit words SHR 4: each word loses its low nibble", () => {
      // Word 0: 0x12345678 SHR 4 = 0x01234567
      // Word 1: 0x9ABCDEF0 SHR 4 = 0x09ABCDEF
      // Critical: the dropped nibble from word 1 does NOT cross into word
      // 0's high bits (that's a bug we explicitly check against — flat
      // byte buffer arithmetic could mis-treat the whole buffer as one
      // big number).
      expect(callShr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 4, 32)).toEqual([
        0x01, 0x23, 0x45, 0x67, 0x09, 0xab, 0xcd, 0xef,
      ]);
    });

    it("four 16-bit words SHR 4, each shifted independently", () => {
      // 0x1234 → 0x0123, 0x5678 → 0x0567, 0x9ABC → 0x09AB, 0xDEF0 → 0x0DEF.
      expect(callShr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 4, 16)).toEqual([
        0x01, 0x23, 0x05, 0x67, 0x09, 0xab, 0x0d, 0xef,
      ]);
    });
  });

  describe("SHR ≥ wordBits — all-zero output", () => {
    // Distinct from ROR (which canonicalizes via modulo). SHR by ≥
    // wordBits wipes the word. Critical that the executor's short-circuit
    // ON THIS BRANCH avoids JS `>>>`'s mod-32 shift-amount truncation —
    // raw `x >>> 32` returns `x`, not `0`.
    it("wordBits=32, bits=32 → all zeros", () => {
      expect(callShr([0x12, 0x34, 0x56, 0x78], 32, 32)).toEqual([0x00, 0x00, 0x00, 0x00]);
    });

    it("wordBits=32, bits=64 → all zeros (well past the boundary)", () => {
      expect(callShr([0xff, 0xff, 0xff, 0xff], 64, 32)).toEqual([0x00, 0x00, 0x00, 0x00]);
    });

    it("wordBits=8, bits=8 → zero byte", () => {
      expect(callShr([0xa5], 8, 8)).toEqual([0x00]);
    });

    it("wordBits=16, bits=16 → zero word", () => {
      expect(callShr([0xa5, 0x5a], 16, 16)).toEqual([0x00, 0x00]);
    });

    it("wordBits=64, bits=64 → all zeros (BigInt boundary)", () => {
      expect(callShr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 64, 64)).toEqual([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]);
    });
  });

  describe("information-loss property — SHR is not invertible", () => {
    // Unlike ROR (which has an inverse: ROL by the same amount = ROR by
    // wordBits - n), SHR drops bits. SHR by n followed by SHL by n
    // CANNOT recover the original low n bits — they're gone. We don't
    // have a SHL primitive yet (ChaCha20 might bring one), but pin the
    // forward direction's information loss as a regression boundary.
    it("0xFF SHR 4 (= 0x0F) loses the low 4 bits irreversibly", () => {
      expect(callShr([0xff], 4, 8)).toEqual([0x0f]);
      // The dropped low nibble "F" is GONE — no operation reconstructs it.
    });

    it("two different inputs with same high bits produce identical SHR output", () => {
      // Both 0xF0 and 0xFF have top nibble 0xF; their SHR 4 outputs are
      // both 0x0F. Demonstrates SHR's non-injectivity.
      expect(callShr([0xf0], 4, 8)).toEqual([0x0f]);
      expect(callShr([0xff], 4, 8)).toEqual([0x0f]);
    });
  });

  describe("param validation", () => {
    it("throws when input length is not a multiple of word size", () => {
      // 3-byte input with wordBits=32 (4 bytes/word) is malformed.
      expect(() => callShr([0x12, 0x34, 0x56], 2, 32)).toThrow(/multiple of word size/);
    });

    it("throws when wordBits is not 8/16/32/64", () => {
      const inputs = new Map([["input", new Uint8Array([0x12, 0x34, 0x56, 0x78])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => shiftBitsRight(inputs, { bits: 1, wordBits: 24 }, ctx)).toThrow(/wordBits/);
    });

    it("throws when bits is negative or non-integer", () => {
      const inputs = new Map([["input", new Uint8Array([0x12, 0x34, 0x56, 0x78])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => shiftBitsRight(inputs, { bits: -1, wordBits: 32 }, ctx)).toThrow(
        /non-negative integer/,
      );
      expect(() => shiftBitsRight(inputs, { bits: 1.5, wordBits: 32 }, ctx)).toThrow(
        /non-negative integer/,
      );
    });

    it("throws when input port is missing", () => {
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => shiftBitsRight(new Map(), { bits: 1, wordBits: 32 }, ctx)).toThrow(
        /missing required input port/,
      );
    });
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("shift-bits-right@1 — runtime dispatch guards", () => {
  // Single-leaf spec — same shape as rotate-bits-right's. Mirrors the
  // guard expectations exactly; if either dispatch path's error message
  // changes, both test files surface the breakage simultaneously.
  const buildSpec = (): CipherSpec => ({
    id: "test-shift-bits-right@1",
    name: "test shift-bits-right",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "shift",
        type: "shift-bits-right@1",
        params: { bits: 3, wordBits: 32 },
      },
    ],
  });

  it("dispatch with no portInputs throws 'input port input is not wired' (Slice 2.6a)", () => {
    // Post-Slice-2.6a: edge-wiring landed; unwired ports surface
    // per-port via the dispatch-path guard. End-to-end wired specs
    // live in `runtime-port-edge-wiring-toy.test.ts`.
    const spec = buildSpec();
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
