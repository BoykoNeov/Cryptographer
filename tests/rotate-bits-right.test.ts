/**
 * Tests for `rotate-bits-right@1` — the first port-native step type
 * (universal-port plan Phase 2 Slice 2.1a, 2026-05-24).
 *
 * Three concerns:
 *   1. Pure executor unit tests: hand-derived KATs across all four
 *      `wordBits ∈ {8, 16, 32, 64}` plus identity, multi-word, and
 *      modulo-canonicalization edge cases.
 *   2. Off-flag dispatch error: a single-leaf spec wiring this step type
 *      throws the exact "port-native; requires portedDispatchEnabled:
 *      true" message under `portedDispatchEnabled: false`. This pins the
 *      runtime guard Slice 2.1a added at `core/runtime.ts`.
 *   3. On-flag dispatch error: the same spec under
 *      `portedDispatchEnabled: true` throws the "requires spec edge-
 *      wiring (Slice 2.6+)" message. Until SHA-256 lands a real consumer,
 *      this is the contract: port-native steps are reachable today only
 *      via direct executor invocation.
 *
 * KAT derivation: hand-derived from the textbook formula `ROR(w, n, B) =
 * ((w >> n) | (w << (B - n))) & (2^B - 1)`. The original Slice 2.1a plan
 * pinned `0x12345678 ROR 2 = 0x80123456` which is incorrect — bottom 2
 * bits (`00`) wrap to top so the result is `0x048D159E`. Advisor caught
 * the bug pre-implementation; KATs below use the corrected math.
 *
 * Direct executor calls — no `runSpec` for the KAT suite — because
 * port-native steps are unreachable via the dispatch path today and
 * forcing them through runSpec would require building a temporary
 * registry with a legacy stub, which would defeat the whole point of
 * Slice 2.1a's contract widening.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, StepContext } from "@/core/types";
import { rotateBitsRight } from "@/steps/rotate-bits-right";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callRotate = (
  inputBytes: readonly number[],
  bits: number,
  wordBits: 8 | 16 | 32 | 64,
): number[] => {
  const inputs = new Map([["input", new Uint8Array(inputBytes)]]);
  // Synthetic ctx — the executor doesn't read aux, stepId, or path,
  // but the type requires the field. An empty aux map and dummy ids
  // are honest stand-ins.
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = rotateBitsRight(inputs, { bits, wordBits }, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("rotate-bits-right: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("rotate-bits-right@1 — executor (direct invocation)", () => {
  describe("identity (rotate by 0)", () => {
    it("wordBits=32, single word", () => {
      expect(callRotate([0x12, 0x34, 0x56, 0x78], 0, 32)).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("wordBits=8, single byte", () => {
      expect(callRotate([0xa5], 0, 8)).toEqual([0xa5]);
    });

    it("wordBits=64, single word", () => {
      expect(callRotate([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0, 64)).toEqual([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      ]);
    });

    it("bits = wordBits acts as identity (canonicalized via modulo)", () => {
      expect(callRotate([0x12, 0x34, 0x56, 0x78], 32, 32)).toEqual([0x12, 0x34, 0x56, 0x78]);
      expect(callRotate([0x12], 8, 8)).toEqual([0x12]);
    });
  });

  describe("KAT — wordBits=32", () => {
    it("0x12345678 ROR 2 = 0x048D159E", () => {
      // 0x12345678 = 0001 0010 0011 0100 0101 0110 0111 1000
      // bottom 2 bits = 00, wrap to top → no change at the top
      // shift right by 2: 0000 0100 1000 1101 0001 0101 1001 1110
      //                 = 0x048D159E
      expect(callRotate([0x12, 0x34, 0x56, 0x78], 2, 32)).toEqual([0x04, 0x8d, 0x15, 0x9e]);
    });

    it("0x12345678 ROR 8 = 0x78123456 (byte rotation)", () => {
      // ROR by 8 = shift the low byte up to the top byte position.
      expect(callRotate([0x12, 0x34, 0x56, 0x78], 8, 32)).toEqual([0x78, 0x12, 0x34, 0x56]);
    });

    it("0x80000001 ROR 1 = 0xC0000000 (low bit wraps to top)", () => {
      expect(callRotate([0x80, 0x00, 0x00, 0x01], 1, 32)).toEqual([0xc0, 0x00, 0x00, 0x00]);
    });

    it("0x12345678 ROR 34 = 0x12345678 ROR 2 (bits % wordBits = 2)", () => {
      expect(callRotate([0x12, 0x34, 0x56, 0x78], 34, 32)).toEqual(
        callRotate([0x12, 0x34, 0x56, 0x78], 2, 32),
      );
    });
  });

  describe("KAT — wordBits=16", () => {
    it("0x1234 ROR 4 = 0x4123", () => {
      // bottom 4 bits = 0x4; shift right 4 → 0x0123; OR 0x4000 = 0x4123
      expect(callRotate([0x12, 0x34], 4, 16)).toEqual([0x41, 0x23]);
    });

    it("0x0001 ROR 1 = 0x8000 (low bit wraps to top of 16-bit word)", () => {
      expect(callRotate([0x00, 0x01], 1, 16)).toEqual([0x80, 0x00]);
    });
  });

  describe("KAT — wordBits=8", () => {
    it("0x12 ROR 4 = 0x21 (nibble swap)", () => {
      expect(callRotate([0x12], 4, 8)).toEqual([0x21]);
    });

    it("0x01 ROR 1 = 0x80 (low bit wraps to top of byte)", () => {
      expect(callRotate([0x01], 1, 8)).toEqual([0x80]);
    });
  });

  describe("KAT — wordBits=64", () => {
    it("0x123456789ABCDEF0 ROR 8 = 0xF0123456789ABCDE (byte wrap)", () => {
      // Low byte 0xF0 wraps to top byte position; everything else shifts
      // right by one byte. Validates the BigInt path.
      expect(callRotate([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 8, 64)).toEqual([
        0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
      ]);
    });

    it("0x8000000000000001 ROR 1 = 0xC000000000000000", () => {
      expect(callRotate([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], 1, 64)).toEqual([
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]);
    });
  });

  describe("multi-word — each word rotates independently", () => {
    it("two 32-bit words ROR 8: [0x12345678, 0x9ABCDEF0] → [0x78123456, 0xF09ABCDE]", () => {
      // Word boundaries matter — rotation does NOT cross words. The
      // low byte of word 0 wraps to the top of word 0, not into word 1.
      expect(callRotate([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 8, 32)).toEqual([
        0x78, 0x12, 0x34, 0x56, 0xf0, 0x9a, 0xbc, 0xde,
      ]);
    });

    it("four 16-bit words ROR 4, each rotated independently", () => {
      // 0x1234 → 0x4123, 0x5678 → 0x8567, 0x9ABC → 0xC9AB, 0xDEF0 → 0x0DEF.
      expect(callRotate([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], 4, 16)).toEqual([
        0x41, 0x23, 0x85, 0x67, 0xc9, 0xab, 0x0d, 0xef,
      ]);
    });
  });

  describe("round-trip property — ROR(B-n) ∘ ROR(n) = identity", () => {
    // ROR by N then ROR by (wordBits - N) is two rotations summing to a
    // full word width — back to the original. Pins the algebra over
    // several wordBits + random-ish payloads.
    const cases: ReadonlyArray<{ bytes: number[]; bits: number; wordBits: 8 | 16 | 32 | 64 }> = [
      { bytes: [0xa5], bits: 3, wordBits: 8 },
      { bytes: [0xa5, 0x5a], bits: 7, wordBits: 16 },
      { bytes: [0x12, 0x34, 0x56, 0x78], bits: 13, wordBits: 32 },
      { bytes: [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], bits: 25, wordBits: 64 },
    ];
    for (const { bytes, bits, wordBits } of cases) {
      it(`wordBits=${wordBits}, bits=${bits}`, () => {
        const onceForward = callRotate(bytes, bits, wordBits);
        const onceBack = callRotate(onceForward, wordBits - bits, wordBits);
        expect(onceBack).toEqual(bytes);
      });
    }
  });

  describe("param validation", () => {
    it("throws when input length is not a multiple of word size", () => {
      // 3-byte input with wordBits=32 (4 bytes/word) is malformed.
      expect(() => callRotate([0x12, 0x34, 0x56], 2, 32)).toThrow(/multiple of word size/);
    });

    it("throws when wordBits is not 8/16/32/64", () => {
      const inputs = new Map([["input", new Uint8Array([0x12, 0x34, 0x56, 0x78])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => rotateBitsRight(inputs, { bits: 1, wordBits: 24 }, ctx)).toThrow(/wordBits/);
    });

    it("throws when bits is negative or non-integer", () => {
      const inputs = new Map([["input", new Uint8Array([0x12, 0x34, 0x56, 0x78])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => rotateBitsRight(inputs, { bits: -1, wordBits: 32 }, ctx)).toThrow(
        /non-negative integer/,
      );
      expect(() => rotateBitsRight(inputs, { bits: 1.5, wordBits: 32 }, ctx)).toThrow(
        /non-negative integer/,
      );
    });

    it("throws when input port is missing", () => {
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => rotateBitsRight(new Map(), { bits: 1, wordBits: 32 }, ctx)).toThrow(
        /missing required input port/,
      );
    });
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("rotate-bits-right@1 — runtime dispatch guards", () => {
  // Single-leaf spec that wires the port-native step. Reachable today
  // only via either dispatch path's explicit error message — Slice 2.6+
  // is when a wired-via-edges path becomes available.
  const buildSpec = (): CipherSpec => ({
    id: "test-rotate-bits-right@1",
    name: "test rotate-bits-right",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "rotate",
        type: "rotate-bits-right@1",
        params: { bits: 2, wordBits: 32 },
      },
    ],
  });

  it("dispatch with no portInputs throws 'input port not wired'", () => {
    // Slice 2.6a (2026-05-25) landed spec edge-wiring via
    // `StepLeaf.portInputs`. A port-native leaf without `portInputs`
    // declarations triggers the dispatch-path guard for the first
    // unwired input port. The PRIOR throw ("requires spec edge-
    // wiring (Slice 2.6+)") was the placeholder for this exact slice;
    // it no longer fires because the mechanism is in place — the
    // guard now points at the missing wire concretely. End-to-end
    // wiring is exercised by `runtime-port-edge-wiring-toy.test.ts`.
    const spec = buildSpec();
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
