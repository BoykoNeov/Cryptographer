/**
 * Tests for `src/core/word-codec.ts` — the shared big-endian word codec
 * + ROR helpers consolidated in universal-port plan Phase 2 Slice 2.2
 * (2026-05-24).
 *
 * Two concerns:
 *   1. Direct unit coverage of every exported helper at every width.
 *      Round-trip, edge cases (top-bit-set / mod-2^N wrap), and
 *      independent KATs hand-derived from textbook BE encoding.
 *   2. **Regression gate for the consumers.** The existing 26-test
 *      `tests/rotate-bits-right.test.ts` and 28-test
 *      `tests/add-mod-32.test.ts` continue to pass against the
 *      refactored consumers — that IS the Q-gate-9 framing for this
 *      slice ("shared codec proves byte-equal to removed inline
 *      helpers"). No separate parity test is needed; the existing
 *      suites are the oracle.
 */

import {
  decodeBE8,
  decodeBE16,
  decodeBE32,
  decodeBE64,
  encodeBE8,
  encodeBE16,
  encodeBE32,
  encodeBE64,
  ror8,
  ror16,
  ror32,
  ror64,
} from "@/core/word-codec";
import { describe, expect, it } from "vitest";

// ─── Decode helpers ───────────────────────────────────────────────────────

describe("word-codec — decodeBE*", () => {
  describe("decodeBE8", () => {
    it("reads a single byte at offset 0", () => {
      expect(decodeBE8(new Uint8Array([0xa5]), 0)).toBe(0xa5);
    });

    it("reads at a non-zero offset", () => {
      expect(decodeBE8(new Uint8Array([0x12, 0x34, 0x56]), 2)).toBe(0x56);
    });

    it("returns 0 for a zero byte (and not undefined)", () => {
      // Defensive: bytes[i] is number | undefined under
      // noUncheckedIndexedAccess; the helper's cast must yield 0, not NaN.
      expect(decodeBE8(new Uint8Array([0x00]), 0)).toBe(0);
    });
  });

  describe("decodeBE16", () => {
    it("0x1234 from [0x12, 0x34]", () => {
      expect(decodeBE16(new Uint8Array([0x12, 0x34]), 0)).toBe(0x1234);
    });

    it("0xFFFF from [0xFF, 0xFF] stays unsigned (load-bearing for top bit)", () => {
      // Without the trailing `>>> 0` the high-bit-set case would return
      // a negative number under JS signed-int semantics for `|`.
      expect(decodeBE16(new Uint8Array([0xff, 0xff]), 0)).toBe(0xffff);
    });

    it("non-zero offset", () => {
      expect(decodeBE16(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), 2)).toBe(0xbeef);
    });
  });

  describe("decodeBE32", () => {
    it("0x12345678 from BE bytes", () => {
      expect(decodeBE32(new Uint8Array([0x12, 0x34, 0x56, 0x78]), 0)).toBe(0x12345678);
    });

    it("0xFFFFFFFF stays unsigned (high-bit set — load-bearing)", () => {
      // The defining 32-bit unsignedness check: without `>>> 0`, the
      // expression returns -1 in JS signed-int view, then `+ 1` returns
      // 0 by coincidence but breaks every other arithmetic operation.
      expect(decodeBE32(new Uint8Array([0xff, 0xff, 0xff, 0xff]), 0)).toBe(0xffffffff);
    });

    it("0x80000000 stays positive (just-above-signed-max)", () => {
      expect(decodeBE32(new Uint8Array([0x80, 0x00, 0x00, 0x00]), 0)).toBe(0x80000000);
    });

    it("non-zero offset (second word in an 8-byte buffer)", () => {
      const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
      expect(decodeBE32(bytes, 4)).toBe(0xcafebabe);
    });
  });

  describe("decodeBE64", () => {
    it("0x123456789ABCDEF0 from BE bytes", () => {
      expect(decodeBE64(new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]), 0)).toBe(
        0x123456789abcdef0n,
      );
    });

    it("0xFFFFFFFFFFFFFFFF stays in BigInt unsigned domain", () => {
      // No signedness collapse possible with BigInt — but pin it as a
      // sanity check on the all-ones edge.
      expect(decodeBE64(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), 0)).toBe(
        0xffffffffffffffffn,
      );
    });

    it("non-zero offset", () => {
      const bytes = new Uint8Array([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba,
        0xbe,
      ]);
      expect(decodeBE64(bytes, 8)).toBe(0xdeadbeefcafebaben);
    });
  });
});

// ─── Encode helpers ───────────────────────────────────────────────────────

describe("word-codec — encodeBE*", () => {
  describe("encodeBE8", () => {
    it("writes one byte at offset 0", () => {
      const out = new Uint8Array(1);
      encodeBE8(out, 0, 0xa5);
      expect(Array.from(out)).toEqual([0xa5]);
    });

    it("masks the low 8 bits (truncates 0x1FF → 0xFF)", () => {
      // Defensive masking documented behaviour; callers passing
      // out-of-range words get mod-2^8 truncation rather than throws.
      const out = new Uint8Array(1);
      encodeBE8(out, 0, 0x1ff);
      expect(out[0]).toBe(0xff);
    });
  });

  describe("encodeBE16", () => {
    it("writes 0x1234 as [0x12, 0x34]", () => {
      const out = new Uint8Array(2);
      encodeBE16(out, 0, 0x1234);
      expect(Array.from(out)).toEqual([0x12, 0x34]);
    });

    it("writes at non-zero offset, leaves surrounding bytes alone", () => {
      const out = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
      encodeBE16(out, 1, 0xdead);
      expect(Array.from(out)).toEqual([0x00, 0xde, 0xad, 0x00]);
    });
  });

  describe("encodeBE32", () => {
    it("writes 0x12345678 as [0x12, 0x34, 0x56, 0x78]", () => {
      const out = new Uint8Array(4);
      encodeBE32(out, 0, 0x12345678);
      expect(Array.from(out)).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("writes 0xFFFFFFFF correctly (unsigned top byte)", () => {
      // Without `>>> 24`, JS would arithmetic-shift the top byte and
      // produce -1 → 0xff under coercion. The `& 0xff` mask catches it
      // regardless; pinning here so a refactor can't silently regress.
      const out = new Uint8Array(4);
      encodeBE32(out, 0, 0xffffffff);
      expect(Array.from(out)).toEqual([0xff, 0xff, 0xff, 0xff]);
    });
  });

  describe("encodeBE64", () => {
    it("writes 0x123456789ABCDEF0n correctly", () => {
      const out = new Uint8Array(8);
      encodeBE64(out, 0, 0x123456789abcdef0n);
      expect(Array.from(out)).toEqual([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
    });

    it("writes 0xFFFFFFFFFFFFFFFFn correctly (all bits set)", () => {
      const out = new Uint8Array(8);
      encodeBE64(out, 0, 0xffffffffffffffffn);
      expect(Array.from(out)).toEqual([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    });
  });
});

// ─── Round-trip property ─────────────────────────────────────────────────

describe("word-codec — decode/encode round-trip", () => {
  it("8-bit: encode(x) followed by decode returns x", () => {
    for (const x of [0x00, 0x01, 0x7f, 0x80, 0xff]) {
      const out = new Uint8Array(1);
      encodeBE8(out, 0, x);
      expect(decodeBE8(out, 0)).toBe(x);
    }
  });

  it("16-bit: encode(x) followed by decode returns x", () => {
    for (const x of [0x0000, 0x0001, 0x7fff, 0x8000, 0xffff, 0x1234]) {
      const out = new Uint8Array(2);
      encodeBE16(out, 0, x);
      expect(decodeBE16(out, 0)).toBe(x);
    }
  });

  it("32-bit: encode(x) followed by decode returns x", () => {
    for (const x of [0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x12345678, 0xdeadbeef]) {
      const out = new Uint8Array(4);
      encodeBE32(out, 0, x);
      expect(decodeBE32(out, 0)).toBe(x);
    }
  });

  it("64-bit: encode(x) followed by decode returns x", () => {
    for (const x of [
      0n,
      1n,
      0x7fffffffffffffffn,
      0x8000000000000000n,
      0xffffffffffffffffn,
      0x123456789abcdef0n,
    ]) {
      const out = new Uint8Array(8);
      encodeBE64(out, 0, x);
      expect(decodeBE64(out, 0)).toBe(x);
    }
  });
});

// ─── Right-rotation helpers ──────────────────────────────────────────────

describe("word-codec — ror*", () => {
  describe("identity (n=0)", () => {
    it("ror8(x, 0) = x", () => {
      expect(ror8(0xa5, 0)).toBe(0xa5);
    });
    it("ror16(x, 0) = x", () => {
      expect(ror16(0x1234, 0)).toBe(0x1234);
    });
    it("ror32(x, 0) = x", () => {
      expect(ror32(0x12345678, 0)).toBe(0x12345678);
    });
    it("ror32(0xFFFFFFFF, 0) stays 0xFFFFFFFF (unsigned)", () => {
      // Critical: the `>>> 0` coercion at entry must keep the top bit
      // unsigned. A naive `((x >>> 0) | (x << 32))` would re-introduce a
      // signed view without the trailing `>>> 0`.
      expect(ror32(0xffffffff, 0)).toBe(0xffffffff);
    });
    it("ror64(x, 0n) = x", () => {
      expect(ror64(0x123456789abcdef0n, 0n)).toBe(0x123456789abcdef0n);
    });
  });

  describe("KATs — small rotations, hand-derived", () => {
    it("ror8(0x12, 4) = 0x21 (nibble swap)", () => {
      // Bottom nibble 0x2 wraps to the top; top nibble 0x1 shifts down.
      expect(ror8(0x12, 4)).toBe(0x21);
    });

    it("ror8(0x01, 1) = 0x80 (low bit wraps to top)", () => {
      expect(ror8(0x01, 1)).toBe(0x80);
    });

    it("ror16(0x1234, 4) = 0x4123", () => {
      // Bottom 4 bits = 0x4 wrap to the top; rest shifts right by 4.
      expect(ror16(0x1234, 4)).toBe(0x4123);
    });

    it("ror16(0x0001, 1) = 0x8000 (low bit wraps to top of 16-bit word)", () => {
      expect(ror16(0x0001, 1)).toBe(0x8000);
    });

    it("ror32(0x12345678, 2) = 0x048D159E", () => {
      // The KAT the Slice 2.1a plan got wrong (it claimed 0x80123456).
      // Bottom 2 bits = 00, so they wrap as zeros at the top — answer
      // is just shift-right-by-2: 0x12345678 >> 2 = 0x048D159E.
      expect(ror32(0x12345678, 2)).toBe(0x048d159e);
    });

    it("ror32(0x12345678, 8) = 0x78123456 (one full byte rotation)", () => {
      expect(ror32(0x12345678, 8)).toBe(0x78123456);
    });

    it("ror32(0x80000001, 1) = 0xC0000000 (low bit wraps onto sign bit)", () => {
      // The unsigned-coercion test under rotation: top bit must end up
      // ON after the rotation (forming 0xC0... not 0x40...).
      expect(ror32(0x80000001, 1)).toBe(0xc0000000);
    });

    it("ror64(0x123456789ABCDEF0n, 8n) = 0xF0123456789ABCDEn (byte wrap)", () => {
      expect(ror64(0x123456789abcdef0n, 8n)).toBe(0xf0123456789abcden);
    });

    it("ror64(0x8000000000000001n, 1n) = 0xC000000000000000n", () => {
      expect(ror64(0x8000000000000001n, 1n)).toBe(0xc000000000000000n);
    });
  });

  describe("round-trip — ror(N) then ror(B-N) is identity", () => {
    // Two rotations summing to a full word width compose to the
    // identity. Pins the algebra across all four widths.
    it("8-bit, n=3 then 5", () => {
      expect(ror8(ror8(0xa5, 3), 5)).toBe(0xa5);
    });
    it("16-bit, n=7 then 9", () => {
      expect(ror16(ror16(0xa55a, 7), 9)).toBe(0xa55a);
    });
    it("32-bit, n=13 then 19", () => {
      expect(ror32(ror32(0x12345678, 13), 19)).toBe(0x12345678);
    });
    it("32-bit, n=1 then 31 with 0xFFFFFFFF (high-bit edge)", () => {
      expect(ror32(ror32(0xffffffff, 1), 31)).toBe(0xffffffff);
    });
    it("64-bit, n=25n then 39n", () => {
      expect(ror64(ror64(0xdeadbeefcafebaben, 25n), 39n)).toBe(0xdeadbeefcafebaben);
    });
  });
});
