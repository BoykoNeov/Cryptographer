/**
 * Per-step provenance unit tests for AES. Pins the four forward AES
 * round operations' source-cell formulas:
 *
 *   - SubBytes: same position
 *   - ShiftRows: shifted position per params.shifts (covers forward
 *     [0,1,2,3] AND inverse [0,3,2,1] via param-driven design)
 *   - MixColumns: 4 sources in same column, with GF(2^8) coefficient
 *     labels per source (covers forward + inverse matrices)
 *   - AddRoundKey: same-position before-cell AND same-position aux-cell
 *
 * The pure-function tests live here; the hover-integration test
 * (`provenance-hover-integration.test.tsx`) covers the MatrixView →
 * RoundKeyPanel wiring end-to-end.
 */

import { AES_INV_MIX_MATRIX, AES_MIX_MATRIX, AES_SBOX } from "@/ciphers/aes-constants";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, TraceFrame } from "@/core/types";
import {
  aesAddRoundKeyProvenance,
  aesMixColumnsProvenance,
  aesShiftRowsProvenance,
  aesSubBytesProvenance,
} from "@/ui/provenance/aes";
import { describe, expect, it } from "vitest";

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

describe("aesSubBytesProvenance — same-position S-box lookup", () => {
  it("returns one before-cell source at the same index", () => {
    const frame = makeFrame({
      stepType: "generic.byte-substitution@1",
      params: { sbox: [...AES_SBOX] },
    });
    for (let i = 0; i < 16; i++) {
      const sources = aesSubBytesProvenance(frame, i);
      expect(sources.length).toBe(1);
      expect(sources[0]).toEqual({ kind: "before-cell", index: i });
    }
  });

  it("returns empty for out-of-range indices", () => {
    const frame = makeFrame({ stepType: "generic.byte-substitution@1" });
    expect(aesSubBytesProvenance(frame, -1)).toEqual([]);
    expect(aesSubBytesProvenance(frame, 16)).toEqual([]);
    expect(aesSubBytesProvenance(frame, 100)).toEqual([]);
  });
});

describe("aesShiftRowsProvenance — shifted-position byte from same row", () => {
  // The state is column-major: index = row + 4*col.
  it("returns the column-shifted source for forward shifts [0,1,2,3]", () => {
    const frame = makeFrame({
      stepType: "generic.shift-rows@1",
      params: { shifts: [0, 1, 2, 3] },
    });
    // Row 0 unchanged: after[0+4*c] = before[0+4*c] for all c.
    for (let c = 0; c < 4; c++) {
      const idx = 0 + 4 * c;
      expect(aesShiftRowsProvenance(frame, idx)).toEqual([{ kind: "before-cell", index: idx }]);
    }
    // Row 1 shifted left by 1: after[1+4*c] = before[1+4*((c+1) mod 4)].
    // E.g. after[1+0]=before[1+4], after[1+4]=before[1+8], …, after[1+12]=before[1+0].
    expect(aesShiftRowsProvenance(frame, 1 + 4 * 0)).toEqual([
      { kind: "before-cell", index: 1 + 4 * 1 },
    ]);
    expect(aesShiftRowsProvenance(frame, 1 + 4 * 3)).toEqual([
      { kind: "before-cell", index: 1 + 4 * 0 },
    ]);
    // Row 3 shifted left by 3: after[3+4*c] = before[3+4*((c+3) mod 4)].
    expect(aesShiftRowsProvenance(frame, 3 + 4 * 0)).toEqual([
      { kind: "before-cell", index: 3 + 4 * 3 },
    ]);
  });

  it("returns the inverse-shifted source for inverse shifts [0,3,2,1] (decrypt-mode)", () => {
    // Param-driven: same provenance fn, different shift table — the
    // forward/inverse direction is handled without a separate
    // registration. Critical for decrypt-mode hover.
    const frame = makeFrame({
      stepType: "generic.shift-rows@1",
      params: { shifts: [0, 3, 2, 1] },
    });
    // Row 1 shifted left by 3: after[1+4*c] = before[1+4*((c+3) mod 4)].
    expect(aesShiftRowsProvenance(frame, 1 + 4 * 0)).toEqual([
      { kind: "before-cell", index: 1 + 4 * 3 },
    ]);
  });

  it("returns empty when params.shifts is missing or malformed", () => {
    const frame = makeFrame({ stepType: "generic.shift-rows@1", params: {} });
    expect(aesShiftRowsProvenance(frame, 0)).toEqual([]);
  });
});

describe("aesMixColumnsProvenance — 4 sources in same column, with coefficient labels", () => {
  it("returns 4 same-column sources for forward AES_MIX_MATRIX", () => {
    // AES_MIX_MATRIX is mostly small constants {0x01, 0x02, 0x03}. The
    // 0x01 (identity) coefficient produces no label; 0x02 and 0x03 carry
    // labels "× 0x02" and "× 0x03".
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix: AES_MIX_MATRIX.map((r) => [...r]) },
    });
    // After cell (row 0, col 0) = matrix[0][0..3] * before[0..3 in col 0].
    // Row 0 of matrix = [0x02, 0x03, 0x01, 0x01].
    const sources = aesMixColumnsProvenance(frame, 0); // r=0, c=0
    expect(sources.length).toBe(4);
    expect(sources[0]).toEqual({ kind: "before-cell", index: 0, label: "× 0x02" });
    expect(sources[1]).toEqual({ kind: "before-cell", index: 1, label: "× 0x03" });
    // Coefficients 0x01 = identity → no label
    expect(sources[2]).toEqual({ kind: "before-cell", index: 2 });
    expect(sources[3]).toEqual({ kind: "before-cell", index: 3 });
  });

  it("returns the inverse coefficients for AES_INV_MIX_MATRIX (decrypt-mode)", () => {
    // AES_INV_MIX_MATRIX = [[0e,0b,0d,09], ...]. Every coefficient is
    // non-identity, so every source carries a label.
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix: AES_INV_MIX_MATRIX.map((r) => [...r]) },
    });
    const sources = aesMixColumnsProvenance(frame, 0);
    expect(sources.length).toBe(4);
    expect(sources[0]?.label).toBe("× 0x0e");
    expect(sources[1]?.label).toBe("× 0x0b");
    expect(sources[2]?.label).toBe("× 0x0d");
    expect(sources[3]?.label).toBe("× 0x09");
  });

  it("returns the right column for non-zero column indices", () => {
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix: AES_MIX_MATRIX.map((r) => [...r]) },
    });
    // After cell (r=0, c=2) = matrix[0][0..3] * before[0..3 in col 2].
    // Sources should be at indices 0+4*2=8, 1+4*2=9, 2+4*2=10, 3+4*2=11.
    const sources = aesMixColumnsProvenance(frame, 8);
    expect(sources.map((s) => s.index)).toEqual([8, 9, 10, 11]);
  });

  it("skips zero coefficients (no provenance from a coefficient that contributes nothing)", () => {
    // Synthetic matrix with one zero coefficient.
    const matrix = [
      [0x00, 0x01, 0x01, 0x01], // row 0 has a zero coefficient at column 0
      [0x01, 0x01, 0x01, 0x01],
      [0x01, 0x01, 0x01, 0x01],
      [0x01, 0x01, 0x01, 0x01],
    ];
    const frame = makeFrame({
      stepType: "generic.mix-columns@1",
      params: { matrix },
    });
    const sources = aesMixColumnsProvenance(frame, 0); // r=0, c=0
    // 3 sources, skipping the zero-coefficient one.
    expect(sources.length).toBe(3);
    expect(sources.map((s) => s.index)).toEqual([1, 2, 3]);
  });
});

describe("aesAddRoundKeyProvenance — same-position XOR with round key", () => {
  it("returns BOTH a before-cell AND an aux-cell source per output cell", () => {
    const roundKey = new Uint8Array(16);
    const frame = makeFrame({
      stepType: "generic.add-round-key@1",
      params: { auxName: "roundKey.3" },
      auxRead: new Map<string, AuxValue>([["roundKey.3", roundKey]]),
    });
    for (let i = 0; i < 16; i++) {
      const sources = aesAddRoundKeyProvenance(frame, i);
      expect(sources.length).toBe(2);
      expect(sources[0]).toEqual({ kind: "before-cell", index: i });
      expect(sources[1]).toEqual({ kind: "aux-cell", auxName: "roundKey.3", index: i });
    }
  });

  it("returns only the before-cell source when auxRead is empty", () => {
    // Defensive: an executor that forgot to declare auxReads, or a
    // future variant with multiple aux entries (the helper returns
    // null in that case), still gets a before-cell highlight.
    const frame = makeFrame({
      stepType: "generic.add-round-key@1",
      auxRead: new Map(),
    });
    const sources = aesAddRoundKeyProvenance(frame, 5);
    expect(sources.length).toBe(1);
    expect(sources[0]).toEqual({ kind: "before-cell", index: 5 });
  });

  it("returns only the before-cell when auxRead has multiple entries (multi-aux is ambiguous)", () => {
    const frame = makeFrame({
      stepType: "generic.add-round-key@1",
      auxRead: new Map<string, AuxValue>([
        ["roundKey.3", new Uint8Array(16)],
        ["extra-aux", new Uint8Array(16)],
      ]),
    });
    const sources = aesAddRoundKeyProvenance(frame, 5);
    // Single-aux helper returns null → only the before-cell source
    // makes it through. Future multi-aux step types would need a
    // bespoke provenance fn.
    expect(sources.length).toBe(1);
    expect(sources[0]?.kind).toBe("before-cell");
  });
});
