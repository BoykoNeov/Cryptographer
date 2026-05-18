/**
 * Per-step narration unit tests for the 4 AES round-body narrators.
 * Verifies unit counts, labels, and Prose render output against
 * frames with known before/after bytes (FIPS-197 Appendix B values
 * for the round-1 traces).
 *
 * Each narrator's `Prose` is a Solid Component; we render it into a
 * test container via `@solidjs/testing-library`, then read its text
 * content. That confirms the prose actually inlines the right bytes —
 * a unit-array assertion wouldn't catch a typo in the prose template.
 *
 * `// @vitest-environment jsdom` directive: Prose components mount
 * into a DOM. Node env can't render Solid components.
 */

// @vitest-environment jsdom

import { AES_INV_MIX_MATRIX, AES_MIX_MATRIX, AES_SBOX } from "@/ciphers/aes-constants";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, TraceFrame } from "@/core/types";
import {
  aesAddRoundKeyNarration,
  aesMixColumnsNarration,
  aesShiftRowsNarration,
  aesSubBytesNarration,
} from "@/ui/narration/aes";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const makeFrame = (overrides: Partial<TraceFrame> = {}): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: {},
  stateBefore: matrixFromBytes(new Uint8Array(16)),
  stateAfter: matrixFromBytes(new Uint8Array(16)),
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

// ─── SubBytes ────────────────────────────────────────────────────────

describe("aesSubBytesNarration", () => {
  it("emits 16 units, one per cell, with row/col labels", () => {
    // Construct an arbitrary before; the executor would have written
    // the matching S-box outputs; we just stub `after` consistently.
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i * 17;
    const after = new Uint8Array(16);
    for (let i = 0; i < 16; i++) after[i] = AES_SBOX[before[i] ?? 0] ?? 0;
    const frame = makeFrame({
      stepType: "generic.byte-substitution@1",
      params: { sbox: [...AES_SBOX] },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
    });
    const units = aesSubBytesNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(16);
    // Spot-check labels for byte 0, byte 5, byte 15.
    expect(units[0]?.label).toBe("byte 0 (row 0, col 0)");
    expect(units[5]?.label).toBe("byte 5 (row 1, col 1)");
    expect(units[15]?.label).toBe("byte 15 (row 3, col 3)");
    // Spot-check prose for byte 0: should mention before, after.
    const text0 = proseText(units[0]?.Prose ?? (() => null));
    // formatByte renders hex without an "0x" prefix (just "00", "ff", …).
    expect(text0).toContain("00"); // before[0] = 0
    expect(text0).toContain((AES_SBOX[0] ?? 0).toString(16).padStart(2, "0")); // S[0x00] = 0x63
  });

  it("returns null when state isn't matrix4x4-bytes", () => {
    const frame = makeFrame({
      stepType: "generic.byte-substitution@1",
      stateBefore: { shape: "bytes", bytes: new Uint8Array(4) },
      stateAfter: { shape: "bytes", bytes: new Uint8Array(4) },
    } as never);
    expect(aesSubBytesNarration(frame)).toBeNull();
  });
});

// ─── ShiftRows ───────────────────────────────────────────────────────

describe("aesShiftRowsNarration", () => {
  it("emits 4 row units with shift labels for forward [0,1,2,3]", () => {
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i;
    // Forward shift: row r shifted left by r. Compute after explicitly.
    const after = new Uint8Array(16);
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        const srcCol = (c + r) % 4;
        after[r + 4 * c] = before[r + 4 * srcCol] ?? 0;
      }
    }
    const frame = makeFrame({
      stepType: "generic.shift-rows@1",
      params: { shifts: [0, 1, 2, 3] },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
    });
    const units = aesShiftRowsNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(4);
    expect(units[0]?.label).toBe("row 0 (shift = 0)");
    expect(units[1]?.label).toBe("row 1 (shift = 1)");
    expect(units[3]?.label).toBe("row 3 (shift = 3)");
    // Row 0 prose should note "unchanged."
    expect(proseText(units[0]?.Prose ?? (() => null))).toMatch(/unchanged/);
    // Row 1 prose should mention "rotated left by 1".
    expect(proseText(units[1]?.Prose ?? (() => null))).toMatch(/rotated left by 1/);
  });

  it("emits inverse [0,3,2,1] shift labels", () => {
    const before = new Uint8Array(16);
    const after = new Uint8Array(16);
    const frame = makeFrame({
      stepType: "generic.shift-rows@1",
      params: { shifts: [0, 3, 2, 1] },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
    });
    const units = aesShiftRowsNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units[1]?.label).toBe("row 1 (shift = 3)");
    expect(units[3]?.label).toBe("row 3 (shift = 1)");
  });
});

// ─── MixColumns ──────────────────────────────────────────────────────

describe("aesMixColumnsNarration", () => {
  it("emits 4 column units with GF(2^8) dot products in prose", () => {
    // Use an all-zero state so the dot products are trivially zero —
    // we're testing prose shape, not arithmetic. The arithmetic is
    // pinned by the executor's KAT tests.
    const before = new Uint8Array(16);
    const after = new Uint8Array(16);
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix: AES_MIX_MATRIX.map((row) => [...row]) },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
    });
    const units = aesMixColumnsNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(4);
    expect(units[0]?.label).toBe("column 0");
    expect(units[3]?.label).toBe("column 3");
    // Forward MixColumns matrix is [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]];
    // the prose for column 0 should mention coefficient 0x02 (the only
    // non-1 coefficient label rendered as "0x02·...").
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("0x02");
    expect(text).toContain("0x03");
  });

  it("emits inverse matrix coefficients (0x09, 0x0b, 0x0d, 0x0e)", () => {
    const before = new Uint8Array(16);
    const after = new Uint8Array(16);
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix: AES_INV_MIX_MATRIX.map((row) => [...row]) },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
    });
    const units = aesMixColumnsNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("0x09");
    expect(text).toContain("0x0e");
  });
});

// ─── AddRoundKey ─────────────────────────────────────────────────────

describe("aesAddRoundKeyNarration", () => {
  it("emits 16 cell units and references the consumed aux name in prose", () => {
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i;
    const roundKey = new Uint8Array(16);
    for (let i = 0; i < 16; i++) roundKey[i] = 0xff - i;
    const after = new Uint8Array(16);
    for (let i = 0; i < 16; i++) after[i] = (before[i] ?? 0) ^ (roundKey[i] ?? 0);
    const auxRead = new Map<string, AuxValue>([["roundKey.3", roundKey]]);
    const frame = makeFrame({
      stepType: "generic.add-round-key@1",
      params: { auxName: "roundKey.3" },
      stateBefore: matrixFromBytes(before),
      stateAfter: matrixFromBytes(after),
      auxRead,
    });
    const units = aesAddRoundKeyNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(16);
    expect(units[0]?.label).toBe("cell 0 (row 0, col 0)");
    expect(units[15]?.label).toBe("cell 15 (row 3, col 3)");
    // Prose mentions the aux name and the XOR result for cell 0.
    const text0 = proseText(units[0]?.Prose ?? (() => null));
    expect(text0).toContain("roundKey.3");
    // formatByte renders hex without "0x" prefix.
    expect(text0).toContain("00"); // before[0] = 0
    expect(text0).toContain("ff"); // K[0] = 0xff
  });

  it("returns null when no aux was consumed", () => {
    const frame = makeFrame({
      stepType: "generic.add-round-key@1",
      params: { auxName: "missing" },
      stateBefore: matrixFromBytes(new Uint8Array(16)),
      stateAfter: matrixFromBytes(new Uint8Array(16)),
      // auxRead is empty
    });
    expect(aesAddRoundKeyNarration(frame)).toBeNull();
  });
});
