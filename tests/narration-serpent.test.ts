/**
 * Per-step narration tests for the Phase-2 Serpent narrators.
 *
 *   - serpentSubBytesNarration   → 16 byte units, per-nibble S-box lookups
 *   - serpentAddRoundKeyNarration → 16 cell units, XOR with aux
 *   - serpentBitPermutationNarration → 1 overview + 16 byte drills = 17 units
 *
 * Frames are fabricated with stable Uint8Array `before`/`after` and an
 * aux entry where needed. Prose is rendered via `@solidjs/testing-library`
 * and the text content is asserted against known sentences/values —
 * a unit-array shape assertion wouldn't catch a typo in the prose.
 */

// @vitest-environment jsdom

import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
import { applyBitPermutation } from "@/steps/serpent-bit-ops";
import {
  serpentAddRoundKeyNarration,
  serpentBitPermutationNarration,
  serpentSubBytesNarration,
} from "@/ui/narration/serpent";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const bytesState = (bytes: Uint8Array): BytesState => ({ shape: "bytes", bytes });

const makeFrame = (overrides: Partial<TraceFrame>): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: {},
  stateBefore: bytesState(new Uint8Array(16)),
  stateAfter: bytesState(new Uint8Array(16)),
  auxRead: new Map<string, AuxValue>(),
  auxWritten: new Map(),
  ...overrides,
});

const proseText = (Prose: (props: { fmt: "hex" }) => unknown): string => {
  const result = render(() => Prose({ fmt: "hex" }) as never);
  const text = result.container.textContent ?? "";
  result.unmount();
  return text;
};

// ─── Serpent SubBytes ────────────────────────────────────────────────

describe("serpentSubBytesNarration", () => {
  it("emits 16 byte units and names the round-specific S-box index in labels", () => {
    // Use an identity S-box for cell math simplicity. The narrator reads
    // params.sbox indirectly (via the after value), so the test exercises
    // the byte→nibble split independent of any specific S-box.
    const sbox = Array.from({ length: 16 }, (_, i) => i); // S[n] = n
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i * 17; // [0x00, 0x11, 0x22, ...]
    const after = new Uint8Array(before); // identity S-box → after == before
    const frame = makeFrame({
      stepType: "serpent.sub-bytes@1",
      params: { sbox, sboxIndex: 3 },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
    });
    const units = serpentSubBytesNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(16);
    expect(units[0]?.label).toBe("byte 0 (uses S_3)");
    expect(units[5]?.label).toBe("byte 5 (uses S_3)");

    // Byte 5 = 0x55 → low nibble 0x5, high nibble 0x5.
    // Identity S-box → low out 0x5, high out 0x5, reassembled 0x55.
    const t5 = proseText(units[5]?.Prose ?? (() => null));
    expect(t5).toContain("0x5"); // both nibbles
    expect(t5).toContain("55"); // before/after byte hex

    // Byte 6 = 0x66 → low nibble 0x6, high nibble 0x6.
    const t6 = proseText(units[6]?.Prose ?? (() => null));
    expect(t6).toContain("0x6");
  });

  it("falls back to a generic 'S-box' label when sboxIndex is missing", () => {
    const sbox = Array.from({ length: 16 }, (_, i) => i);
    const before = new Uint8Array(16);
    const after = new Uint8Array(16);
    const frame = makeFrame({
      stepType: "serpent.sub-bytes@1",
      params: { sbox },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
    });
    const units = serpentSubBytesNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units[0]?.label).toBe("byte 0");
    expect(proseText(units[0]?.Prose ?? (() => null))).toContain("S-box");
  });

  it("returns null on wrong-length bytes state", () => {
    const frame = makeFrame({
      stepType: "serpent.sub-bytes@1",
      stateBefore: bytesState(new Uint8Array(4)),
      stateAfter: bytesState(new Uint8Array(4)),
    });
    expect(serpentSubBytesNarration(frame)).toBeNull();
  });
});

// ─── Serpent AddRoundKey ─────────────────────────────────────────────

describe("serpentAddRoundKeyNarration", () => {
  it("emits 16 cell units and names the consumed aux in prose", () => {
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i;
    const rk = new Uint8Array(16);
    for (let i = 0; i < 16; i++) rk[i] = 0xff - i;
    const after = new Uint8Array(16);
    for (let i = 0; i < 16; i++) after[i] = (before[i] ?? 0) ^ (rk[i] ?? 0);
    const auxRead = new Map<string, AuxValue>([["roundKey.7", rk]]);
    const frame = makeFrame({
      stepType: "serpent.add-round-key@1",
      params: { roundKeyAux: "roundKey.7" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead,
    });
    const units = serpentAddRoundKeyNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(16);
    expect(units[0]?.label).toBe("cell 0");
    expect(units[15]?.label).toBe("cell 15");
    const text0 = proseText(units[0]?.Prose ?? (() => null));
    expect(text0).toContain("roundKey.7");
    expect(text0).toContain("00"); // before[0]
    expect(text0).toContain("ff"); // K[0] = 0xff
  });

  it("returns null when no aux was consumed", () => {
    const frame = makeFrame({
      stepType: "serpent.add-round-key@1",
      params: { roundKeyAux: "roundKey.0" },
      stateBefore: bytesState(new Uint8Array(16)),
      stateAfter: bytesState(new Uint8Array(16)),
    });
    expect(serpentAddRoundKeyNarration(frame)).toBeNull();
  });
});

// ─── Serpent bit permutation ─────────────────────────────────────────

describe("serpentBitPermutationNarration", () => {
  /**
   * Construct an arbitrary 128-entry permutation table that's easy to
   * reason about: `table[i] = (i + 32) mod 128`. So output bit i comes
   * from input bit (i+32). That means output byte 0 (state bits 0..7)
   * pulls from input bits 32..39, which are byte 4 entirely. The drill
   * for byte 0 should reference byte 4 in every line.
   */
  const buildShiftTable = (): number[] => {
    const t = new Array<number>(128);
    for (let i = 0; i < 128; i++) t[i] = (i + 32) % 128;
    return t;
  };

  it("emits 1 overview + 16 drill = 17 units", () => {
    const table = buildShiftTable();
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i * 17;
    const after = applyBitPermutation(before, table);
    const frame = makeFrame({
      stepType: "serpent.bit-permutation@1",
      params: { table, label: "IP" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
    });
    const units = serpentBitPermutationNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(17);
    expect(units[0]?.key).toBe("overview");
    expect(units[0]?.label).toContain("IP");
    expect(units[1]?.label).toBe("byte 0 of output");
    expect(units[16]?.label).toBe("byte 15 of output");
  });

  it("overview prose names the bit-numbering convention", () => {
    const table = buildShiftTable();
    const before = new Uint8Array(16);
    const after = applyBitPermutation(before, table);
    const frame = makeFrame({
      stepType: "serpent.bit-permutation@1",
      params: { table },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
    });
    const units = serpentBitPermutationNarration(frame);
    if (!units) {
      expect.fail("expected units");
      return;
    }
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toMatch(/LSB-first/);
    expect(text).toMatch(/MSB on the left/);
  });

  it("per-output-byte drill references the correct source byte", () => {
    const table = buildShiftTable();
    // After the +32-bit shift: output bits 0..7 = input bits 32..39 = byte 4.
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i * 17;
    const after = applyBitPermutation(before, table);
    const frame = makeFrame({
      stepType: "serpent.bit-permutation@1",
      params: { table },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
    });
    const units = serpentBitPermutationNarration(frame);
    if (!units) {
      expect.fail("expected units");
      return;
    }
    const drill0 = proseText(units[1]?.Prose ?? (() => null));
    // 8 lookups for output byte 0 — each should reference byte 4.
    expect(drill0).toMatch(/byte 4\[bit 0\]/);
    expect(drill0).toMatch(/byte 4\[bit 7\]/);
    expect(drill0).toMatch(/state bits 0\.\.7/);
    // The assembled output byte for byte 0 = before[4] = 4*17 = 0x44.
    expect(drill0).toContain("44");
  });

  it("returns null on a malformed table", () => {
    const frame = makeFrame({
      stepType: "serpent.bit-permutation@1",
      params: { table: [0, 1, 2] }, // wrong length
      stateBefore: bytesState(new Uint8Array(16)),
      stateAfter: bytesState(new Uint8Array(16)),
    });
    expect(serpentBitPermutationNarration(frame)).toBeNull();
  });
});
