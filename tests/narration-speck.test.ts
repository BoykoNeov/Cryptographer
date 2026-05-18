/**
 * Per-step narration tests for the Phase-2 Speck narrators.
 *
 *   - speckRoundNarration         → 3 ARX sub-op units
 *   - speckRoundInverseNarration  → 3 inverse sub-op units
 *
 * Speck32/64 reference test vector (Beaulieu et al. 2013, §3):
 *   plaintext  = 0x6574694c   (BE-paper: bytes 65 74 69 4c)
 *   round 0 key (k_0)         = 0x0100   (BE-paper: bytes 01 00)
 *
 * After ONE forward round with α=7, β=2:
 *   x0 = 0x6574, y0 = 0x694c, k = 0x0100
 *   ROR(0x6574, 7) = 0xe8ca
 *   (0xe8ca + 0x694c) mod 2^16 = 0x5216
 *   0x5216 XOR 0x0100 = 0x5316
 *   ROL(0x694c, 2) = 0xa531
 *   0xa531 XOR 0x5316 = 0xf627
 *   → block after round 0 (BE-paper) = bytes 53 16 f6 27
 *
 * The narrator decodes via `speck-word-codec.ts`, so it MUST exercise
 * both `byteOrder` values. The same words flow through both layouts.
 */

// @vitest-environment jsdom

import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
import { encodeBlock, encodeWord } from "@/steps/speck-word-codec";
import { speckRoundInverseNarration, speckRoundNarration } from "@/ui/narration/speck";
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
  stateBefore: bytesState(new Uint8Array(4)),
  stateAfter: bytesState(new Uint8Array(4)),
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

// Speck32/64 reference values used by both BE and LE forward-round tests.
const X0 = 0x6574;
const Y0 = 0x694c;
const K = 0x0100;
const X_AFTER = 0x5316;
const Y_AFTER = 0xf627;

// ─── Speck forward round ─────────────────────────────────────────────

describe("speckRoundNarration", () => {
  const baseParams = {
    roundKeyAux: "roundKey.0",
    alpha: 7,
    beta: 2,
    wordBits: 16,
  };

  it("emits 3 ARX sub-op units with the expected labels", () => {
    const before = encodeBlock(16, "be-paper", X0, Y0);
    const after = encodeBlock(16, "be-paper", X_AFTER, Y_AFTER);
    const rk = new Uint8Array(2);
    encodeWord(rk, 0, 16, "be-paper", K);
    const frame = makeFrame({
      stepType: "speck.round@1",
      params: { ...baseParams, byteOrder: "be-paper" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead: new Map<string, AuxValue>([["roundKey.0", rk]]),
    });
    const units = speckRoundNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(3);
    expect(units[0]?.label).toMatch(/ROR/);
    expect(units[1]?.label).toMatch(/k_i/);
    expect(units[2]?.label).toMatch(/ROL/);
  });

  it("BE-paper: prose carries the right intermediate values (ROR, sum, XOR)", () => {
    const before = encodeBlock(16, "be-paper", X0, Y0);
    const after = encodeBlock(16, "be-paper", X_AFTER, Y_AFTER);
    const rk = new Uint8Array(2);
    encodeWord(rk, 0, 16, "be-paper", K);
    const frame = makeFrame({
      stepType: "speck.round@1",
      params: { ...baseParams, byteOrder: "be-paper" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead: new Map<string, AuxValue>([["roundKey.0", rk]]),
    });
    const units = speckRoundNarration(frame);
    if (!units) {
      expect.fail("expected units");
      return;
    }
    // Sub-op 1 prose: ROR(0x6574, 7) = 0xe8ca; (0xe8ca + 0x694c) mod 2^16 = 0x5216.
    const t0 = proseText(units[0]?.Prose ?? (() => null));
    expect(t0).toContain("0x6574");
    expect(t0).toContain("0x694c");
    expect(t0).toContain("0xe8ca");
    expect(t0).toContain("0x5216");
    // Sub-op 2 prose: 0x5216 XOR 0x0100 = 0x5316.
    const t1 = proseText(units[1]?.Prose ?? (() => null));
    expect(t1).toContain("0x5216");
    expect(t1).toContain("0x0100");
    expect(t1).toContain("0x5316");
    // Sub-op 3 prose: ROL(0x694c, 2) = 0xa531; 0xa531 XOR 0x5316 = 0xf627.
    const t2 = proseText(units[2]?.Prose ?? (() => null));
    expect(t2).toContain("0xa531");
    expect(t2).toContain("0x5316");
    expect(t2).toContain("0xf627");
  });

  it("LE-NSA: same words produce the same intermediate values via the codec", () => {
    // The codec absorbs byte order — LE-NSA's in-memory layout for the
    // block is (y, x) low-byte first, but decodeBlock returns [x, y]
    // regardless. The narrator should produce identical prose values.
    const before = encodeBlock(16, "le-nsa", X0, Y0);
    const after = encodeBlock(16, "le-nsa", X_AFTER, Y_AFTER);
    const rk = new Uint8Array(2);
    encodeWord(rk, 0, 16, "le-nsa", K);
    const frame = makeFrame({
      stepType: "speck.round@1",
      params: { ...baseParams, byteOrder: "le-nsa" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead: new Map<string, AuxValue>([["roundKey.0", rk]]),
    });
    const units = speckRoundNarration(frame);
    if (!units) {
      expect.fail("expected units");
      return;
    }
    const t0 = proseText(units[0]?.Prose ?? (() => null));
    expect(t0).toContain("0x6574");
    expect(t0).toContain("0x694c");
    expect(t0).toContain("0x5216");
    const t2 = proseText(units[2]?.Prose ?? (() => null));
    expect(t2).toContain("0xf627");
  });

  it("returns null when block size doesn't match wordBits", () => {
    const frame = makeFrame({
      stepType: "speck.round@1",
      params: { ...baseParams, byteOrder: "be-paper" },
      stateBefore: bytesState(new Uint8Array(8)), // wrong size for wordBits=16
      stateAfter: bytesState(new Uint8Array(8)),
    });
    expect(speckRoundNarration(frame)).toBeNull();
  });
});

// ─── Speck inverse round ─────────────────────────────────────────────

describe("speckRoundInverseNarration", () => {
  const baseParams = {
    roundKeyAux: "roundKey.0",
    alpha: 7,
    beta: 2,
    wordBits: 16,
  };

  it("emits 3 inverse-direction units that recover (x, y) from (x', y')", () => {
    // Start with the forward-round outputs and assert the narrator's
    // prose produces the original x and y. Inverse round consumes the
    // same k_0 = 0x0100.
    const before = encodeBlock(16, "be-paper", X_AFTER, Y_AFTER);
    const after = encodeBlock(16, "be-paper", X0, Y0);
    const rk = new Uint8Array(2);
    encodeWord(rk, 0, 16, "be-paper", K);
    const frame = makeFrame({
      stepType: "speck.round-inverse@1",
      params: { ...baseParams, byteOrder: "be-paper" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead: new Map<string, AuxValue>([["roundKey.0", rk]]),
    });
    const units = speckRoundInverseNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(3);

    // Inverse sub-op 1: y = ROR(0xf627 XOR 0x5316, 2)
    // 0xf627 XOR 0x5316 = 0xa531; ROR(0xa531, 2) = 0x694c.
    const t0 = proseText(units[0]?.Prose ?? (() => null));
    expect(t0).toContain("0xf627");
    expect(t0).toContain("0x5316");
    expect(t0).toContain("0xa531");
    expect(t0).toContain("0x694c");

    // Inverse sub-op 2: 0x5316 XOR 0x0100 = 0x5216; (0x5216 - 0x694c) mod 2^16 = 0xe8ca.
    const t1 = proseText(units[1]?.Prose ?? (() => null));
    expect(t1).toContain("0x5316");
    expect(t1).toContain("0x0100");
    expect(t1).toContain("0x5216");
    expect(t1).toContain("0xe8ca");

    // Inverse sub-op 3: ROL(0xe8ca, 7) = 0x6574 (recovered x).
    const t2 = proseText(units[2]?.Prose ?? (() => null));
    expect(t2).toContain("0xe8ca");
    expect(t2).toContain("0x6574");
  });

  it("LE-NSA inverse: codec absorbs byte order; same intermediate words appear", () => {
    const before = encodeBlock(16, "le-nsa", X_AFTER, Y_AFTER);
    const after = encodeBlock(16, "le-nsa", X0, Y0);
    const rk = new Uint8Array(2);
    encodeWord(rk, 0, 16, "le-nsa", K);
    const frame = makeFrame({
      stepType: "speck.round-inverse@1",
      params: { ...baseParams, byteOrder: "le-nsa" },
      stateBefore: bytesState(before),
      stateAfter: bytesState(after),
      auxRead: new Map<string, AuxValue>([["roundKey.0", rk]]),
    });
    const units = speckRoundInverseNarration(frame);
    if (!units) {
      expect.fail("expected units");
      return;
    }
    const t2 = proseText(units[2]?.Prose ?? (() => null));
    expect(t2).toContain("0x6574"); // recovered x
  });
});
