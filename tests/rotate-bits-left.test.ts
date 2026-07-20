/**
 * Tests for `rotate-bits-left@1` — the mirror of `rotate-bits-right@1`, added
 * for ChaCha20 (RFC 8439, 2026-07-20).
 *
 * This step type buys no new *behaviour* — `ROL(w, n, B) === ROR(w, B - n, B)`
 * — so the interesting question is not "does it rotate" but "does it rotate in
 * the direction it claims, at the amount it claims". Three concerns, ordered
 * by how much each actually discriminates:
 *
 *   1. **Hand-derived KATs**, verified independently of this codebase before
 *      being written down (a throwaway Node reference implementation, not
 *      recalled values), across all four `wordBits ∈ {8, 16, 32, 64}`. These
 *      are the tests that fail if the direction is backwards.
 *   2. **The complement identity against the shipped right-rotation.** ROL n
 *      must equal ROR (B - n) for every n, and — the assertion that catches a
 *      copy-paste registration of the wrong executor — must NOT equal ROR n
 *      except where the two coincide (n = 0, and n = B/2 for the 8-bit case
 *      where 4 is its own complement... in general n where n ≡ B - n).
 *   3. **Param validation and the word-multiple invariant**, mirroring the
 *      sibling's guards so a malformed spec fails loudly rather than rotating
 *      a truncated word.
 *
 * The ChaCha20 rotation amounts (16, 12, 8, 7 on 32-bit words) appear
 * explicitly among the KATs. Two of them — 12 and 7 — are not multiples of 8,
 * which is precisely the case where a byte-level implementation would silently
 * produce a byte-permutation instead of a bit-rotation.
 *
 * Direct executor calls rather than `runSpec`: these are unit tests of the bit
 * math. The step's behaviour inside a real spec is covered end-to-end by
 * `tests/chacha20-kat.test.ts` against RFC 8439's published vectors.
 */

import { rotateBitsLeft } from "@/steps/rotate-bits-left";
import { rotateBitsRight } from "@/steps/rotate-bits-right";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const call = (
  executor: typeof rotateBitsLeft,
  inputBytes: readonly number[],
  bits: number,
  wordBits: 8 | 16 | 32 | 64,
): number[] => {
  const inputs = new Map([["input", new Uint8Array(inputBytes)]]);
  const out = executor(inputs, { bits, wordBits }, undefined as never);
  const bytes = out.get("output");
  if (bytes === undefined) throw new Error("no output port");
  return Array.from(bytes);
};

const rol = (inputBytes: readonly number[], bits: number, wordBits: 8 | 16 | 32 | 64): number[] =>
  call(rotateBitsLeft, inputBytes, bits, wordBits);

const ror = (inputBytes: readonly number[], bits: number, wordBits: 8 | 16 | 32 | 64): number[] =>
  call(rotateBitsRight, inputBytes, bits, wordBits);

/** 0x12345678 as big-endian bytes — the shared 32-bit KAT input. */
const W32 = [0x12, 0x34, 0x56, 0x78];

const hex = (bytes: readonly number[]): string =>
  bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

// ─── 1. Known-answer tests ────────────────────────────────────────────────

describe("rotate-bits-left@1 rotates LEFT by the stated amount", () => {
  // Every expected value below was computed by an independent reference
  // implementation before being written here, not derived by reading the
  // executor. See the plan's "external oracle before tests" rule.
  it.each([
    // [bits, expected] — 0x12345678 rotated left, 32-bit word.
    [7, "1a2b3c09"],
    [8, "34567812"],
    [12, "45678123"],
    [16, "56781234"],
  ])("0x12345678 ROL %i = 0x%s (32-bit)", (bits, expected) => {
    expect(hex(rol(W32, bits, 32))).toBe(expected);
  });

  it("wraps the high bit around to the bottom, which is what makes it a rotation", () => {
    // 0x80000001 ROL 1: the top bit wraps to bit 0, the bottom bit moves to
    // bit 1. A logical SHIFT would have produced 0x00000002 and lost a bit.
    expect(hex(rol([0x80, 0x00, 0x00, 0x01], 1, 32))).toBe("00000003");
  });

  it("rotates 8-bit words", () => {
    expect(hex(rol([0x81], 1, 8))).toBe("03");
  });

  it("rotates 16-bit words", () => {
    expect(hex(rol([0x80, 0x01], 1, 16))).toBe("0003");
  });

  it("rotates 64-bit words (the BigInt path)", () => {
    expect(hex(rol([0x80, 0, 0, 0, 0, 0, 0, 0x01], 1, 64))).toBe("0000000000000003");
  });

  it("rotates each word of a multi-word input independently", () => {
    // Two 32-bit words; a rotation must not carry bits across the word
    // boundary. If it did, word 1's high bits would leak into word 0.
    const two = [...W32, 0x80, 0x00, 0x00, 0x01];
    expect(hex(rol(two, 8, 32))).toBe("34567812" + "00000180");
  });
});

// ─── 2. The complement identity — the load-bearing invariant ──────────────

describe("rotate-bits-left@1 is exactly its right-handed sibling at the complement", () => {
  const WORD_WIDTHS = [8, 16, 32, 64] as const;

  it.each(WORD_WIDTHS)("ROL n === ROR (%i - n) for every n in range", (wordBits) => {
    // A byte pattern wide enough to be a whole word at every width, with an
    // asymmetric bit pattern so a wrong-direction rotation cannot coincide.
    const input = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1].slice(0, wordBits / 8);
    for (let n = 0; n <= wordBits; n++) {
      expect(hex(rol(input, n, wordBits))).toBe(
        hex(ror(input, (wordBits - n) % wordBits, wordBits)),
      );
    }
  });

  it("is NOT the same as rotating right by the same amount", () => {
    // The assertion that catches registering the wrong executor, or "fixing"
    // ChaCha's rotations by pointing them at rotate-bits-right@1 unchanged.
    // Skips n where left and right coincide (n ≡ B - n, i.e. n = 0 and 16).
    for (const n of [1, 7, 8, 12, 15, 31]) {
      expect(hex(rol(W32, n, 32))).not.toBe(hex(ror(W32, n, 32)));
    }
  });

  it("rotating by 0 and by a whole word are both the identity", () => {
    expect(hex(rol(W32, 0, 32))).toBe(hex(W32));
    expect(hex(rol(W32, 32, 32))).toBe(hex(W32));
    // ...and the reduction is modular, so 33 is a rotation by 1.
    expect(hex(rol(W32, 33, 32))).toBe(hex(rol(W32, 1, 32)));
  });

  it("composes: ROL a then ROL b === ROL (a+b)", () => {
    const once = rol(W32, 12, 32);
    expect(hex(rol(once, 7, 32))).toBe(hex(rol(W32, 19, 32)));
  });

  it("round-trips against its own inverse rotation", () => {
    expect(hex(rol(rol(W32, 12, 32), 20, 32))).toBe(hex(W32));
  });
});

// ─── 3. Validation ────────────────────────────────────────────────────────

describe("rotate-bits-left@1 rejects malformed input loudly", () => {
  it("throws when the input length is not a whole number of words", () => {
    // 6 bytes is not a multiple of 4. Rotating it as "one and a half words"
    // would produce plausible-looking bytes; the throw is the point.
    expect(() => rol([1, 2, 3, 4, 5, 6], 8, 32)).toThrow(/not a multiple of word size 4/);
  });

  it("throws on a missing input port", () => {
    expect(() => rotateBitsLeft(new Map(), { bits: 8, wordBits: 32 }, undefined as never)).toThrow(
      /missing required input port 'input'/,
    );
  });

  it("throws on a negative or non-integer bits param", () => {
    expect(() => rol(W32, -1, 32)).toThrow(/params\.bits must be a non-negative integer/);
    expect(() => rol(W32, 1.5, 32)).toThrow(/params\.bits must be a non-negative integer/);
  });

  it("throws on an unsupported word width", () => {
    expect(() => rol(W32, 8, 24 as never)).toThrow(/params\.wordBits must be 8, 16, 32, or 64/);
  });

  it("throws when params are not an object", () => {
    expect(() =>
      rotateBitsLeft(new Map([["input", new Uint8Array(W32)]]), 42 as never, undefined as never),
    ).toThrow(/params must be an object/);
  });
});
