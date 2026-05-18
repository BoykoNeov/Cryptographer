/**
 * Per-step provenance unit tests for Serpent's byte-level steps. Bit-
 * level steps (linear-transform, inv-linear-transform, bit-permutation)
 * are on the no-provenance allowlist by design; this file only covers
 * AddRoundKey and SubBytes.
 */

import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, TraceFrame } from "@/core/types";
import { serpentAddRoundKeyProvenance, serpentSubBytesProvenance } from "@/ui/provenance/serpent";
import { describe, expect, it } from "vitest";

const makeBytesFrame = (overrides: Partial<TraceFrame> = {}): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: {},
  stateBefore: makeBytesState(new Uint8Array(16)),
  stateAfter: makeBytesState(new Uint8Array(16)),
  auxRead: new Map<string, AuxValue>(),
  auxWritten: new Map(),
  ...overrides,
});

describe("serpentAddRoundKeyProvenance — same-position XOR", () => {
  it("returns BOTH a before-cell AND an aux-cell source per byte", () => {
    const frame = makeBytesFrame({
      stepType: "serpent.add-round-key@1",
      auxRead: new Map<string, AuxValue>([["roundKey.12", new Uint8Array(16)]]),
    });
    const sources = serpentAddRoundKeyProvenance(frame, 7);
    expect(sources.length).toBe(2);
    expect(sources[0]).toEqual({ kind: "before-cell", index: 7 });
    expect(sources[1]).toEqual({ kind: "aux-cell", auxName: "roundKey.12", index: 7 });
  });

  it("returns empty for out-of-range indices (bytes state)", () => {
    const frame = makeBytesFrame({
      stepType: "serpent.add-round-key@1",
      auxRead: new Map<string, AuxValue>([["roundKey.0", new Uint8Array(16)]]),
    });
    expect(serpentAddRoundKeyProvenance(frame, -1)).toEqual([]);
    expect(serpentAddRoundKeyProvenance(frame, 16)).toEqual([]);
  });
});

describe("serpentSubBytesProvenance — same-position 4-bit S-box", () => {
  it("returns one before-cell source per byte (both nibbles come from the same byte)", () => {
    const frame = makeBytesFrame({ stepType: "serpent.sub-bytes@1" });
    for (let i = 0; i < 16; i++) {
      const sources = serpentSubBytesProvenance(frame, i);
      expect(sources.length).toBe(1);
      expect(sources[0]).toEqual({ kind: "before-cell", index: i });
    }
  });

  it("returns empty for out-of-range indices", () => {
    const frame = makeBytesFrame({ stepType: "serpent.sub-bytes@1" });
    expect(serpentSubBytesProvenance(frame, -1)).toEqual([]);
    expect(serpentSubBytesProvenance(frame, 16)).toEqual([]);
  });
});
