/**
 * Slice 1.3 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the SIX padding step types lifted
 * in Slice 1.3:
 *
 *   - `generic.pkcs7-pad@1`     - RFC 5652 §6.3 PKCS#7 padding
 *   - `generic.pkcs7-unpad@1`   - inverse; throws on malformed input
 *   - `generic.zero-pad@1`      - ISO/IEC 9797-1 method 1 (lossy)
 *   - `generic.zero-unpad@1`    - inverse; lossy, never throws on shape
 *   - `generic.iso7816-4-pad@1` - sentinel-marked padding (0x80 + zeros)
 *   - `generic.iso7816-4-unpad@1` - inverse; throws on missing sentinel
 *
 * All six are pure bytes->bytes state transforms with no aux. The Slice
 * 1.3 test surface is correspondingly leaner than Slice 1.2: no aux
 * iteration-order hazards, no PortShape layout-decode paths to validate
 * (every port is `"raw"`), no MatrixState reconstruction. The
 * load-bearing checks are (a) shape-preserving lift on variable-length
 * outputs (`byteLength` ABSENT on the contract), (b) the runtime
 * preserves the executor's intentional throws on malformed input across
 * both dispatch paths, and (c) round-trip equivalence — pad then unpad
 * recovers the original bytes byte-identically.
 *
 * Three test surfaces:
 *
 *   (a) **Per-step-type frame-by-frame parity** — one synthetic spec per
 *       step type, run twice. Asserts frame-by-frame deep equality so a
 *       drift in state encoding (variable-length output, in particular)
 *       surfaces as a single failing it block.
 *
 *   (b) **Pad+unpad round-trip equivalence** — pad then immediately
 *       unpad, assert the result equals the original input. Runs only
 *       under the ported path (legacy round-trip is exercised by the
 *       existing padding-specific tests). KAT-sanity-floor character.
 *
 *   (c) **Throw parity on malformed input** — pkcs7-unpad on a corrupt
 *       padded block, iso7816-4-unpad on an all-zeros block. Both paths
 *       must throw with the same message. The lift adapter intentionally
 *       passes throws through unchanged so the educational "intentionally
 *       throws on bad input" behavior survives.
 *
 * This file is the Slice-1.3 sibling of the Slice-1.2 file
 * `tests/runtime-ported-dispatch-aux-only.test.ts`. The frame-equality
 * helpers are duplicated rather than extracted: small enough that the
 * test-local copy keeps a failing assertion's stack frame readable, and
 * any future refactor of `TraceFrame` will want a per-slice update audit.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── State / aux equality helpers (mirror Slice 1.2's structure) ────────

const expectStatesEqual = (a: State, b: State, label: string): void => {
  expect(a.shape, `${label}: shape`).toBe(b.shape);
  switch (a.shape) {
    case "bytes":
    case "matrix4x4-bytes": {
      if (b.shape !== a.shape) return;
      expect(Array.from(a.bytes), `${label}: bytes`).toEqual(Array.from(b.bytes));
      return;
    }
    case "bitvec":
      throw new Error(`${label}: bitvec not exercised by Slice 1.3 fixtures`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.3 fixtures`);
  }
};

const expectAuxMapsEqual = (
  a: ReadonlyMap<string, AuxValue>,
  b: ReadonlyMap<string, AuxValue>,
  label: string,
): void => {
  expect([...a.keys()].sort(), `${label}: keys`).toEqual([...b.keys()].sort());
  expect(a, `${label}: aux value`).toEqual(b);
};

const expectFramesEqual = (a: TraceFrame, b: TraceFrame, index: number): void => {
  const label = `frame ${index} (${a.stepType} @ ${a.stepId})`;
  expect(a.index, `${label}: index`).toBe(b.index);
  expect(a.path, `${label}: path`).toEqual(b.path);
  expect(a.stepId, `${label}: stepId`).toBe(b.stepId);
  expect(a.stepType, `${label}: stepType`).toBe(b.stepType);
  expect(a.params, `${label}: params`).toEqual(b.params);
  expect(a.blockIndex, `${label}: blockIndex`).toBe(b.blockIndex);
  expect(a.branchPath, `${label}: branchPath`).toEqual(b.branchPath);
  expect(a.auxReadMissing, `${label}: auxReadMissing`).toEqual(b.auxReadMissing);
  expectStatesEqual(a.stateBefore, b.stateBefore, `${label}: stateBefore`);
  expectStatesEqual(a.stateAfter, b.stateAfter, `${label}: stateAfter`);
  expectAuxMapsEqual(a.auxRead, b.auxRead, `${label}: auxRead`);
  expectAuxMapsEqual(a.auxWritten, b.auxWritten, `${label}: auxWritten`);
};

const expectFrameStreamsEqual = (
  a: readonly TraceFrame[],
  b: readonly TraceFrame[],
  label: string,
): void => {
  expect(a.length, `${label}: frame count`).toBe(b.length);
  for (let i = 0; i < a.length; i++) {
    const af = a[i];
    const bf = b[i];
    if (!af || !bf) throw new Error(`${label}: fixture missing frame at index ${i}`);
    expectFramesEqual(af, bf, i);
  }
};

// ─── Spec builders ──────────────────────────────────────────────────────

/**
 * Single-step spec scaffolded for a padding leaf. Each Slice 1.3 step
 * is exercised in isolation so any frame drift surfaces in the
 * smallest-possible failing assertion (vs. a multi-step chain where a
 * drift in step #2 would also propagate forward).
 */
const singleStepSpec = (id: string, stepType: string, blockSize: number): CipherSpec => ({
  id,
  name: `Slice 1.3 ${stepType} smoke`,
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "the-step",
      type: stepType,
      params: { blockSize },
    },
  ],
});

const runBoth = (
  spec: CipherSpec,
  initial: Uint8Array,
): { legacy: ReturnType<typeof runSpec>; ported: ReturnType<typeof runSpec> } => {
  const legacy = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(initial),
  });
  const ported = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(initial),
    portedDispatchEnabled: true,
  });
  return { legacy, ported };
};

// 5-byte plaintext "apple" — short enough to fit in one 16-byte block
// with room to spare. Each pad scheme appends a different sentinel
// pattern, so the resulting frames differ across step types in their
// `stateAfter.bytes` (correctly exercising the executor logic) while
// the cross-path comparison stays a within-step deep equality.
const APPLE_5 = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);

// 16-byte aligned input — exercises the "already a clean block multiple"
// edge case that splits the three pad schemes most sharply:
//   - PKCS#7  : appends a full extra block of 0x10 (16 bytes of 0x10)
//   - zero    : passthrough, padLen = 0
//   - ISO 7816: appends 0x80 followed by 15 zeros (full extra block)
const ALIGNED_16 = new Uint8Array(16).fill(0x42);

// ─── (a) Per-step-type frame-by-frame parity ────────────────────────────

describe("runtime — ported dispatch, Slice 1.3 padding primitives", () => {
  describe("(a) per-step-type frame-by-frame parity", () => {
    it("generic.pkcs7-pad@1 emits byte-equal frames across both dispatch paths", () => {
      const spec = singleStepSpec("pkcs7-pad-smoke@1", "generic.pkcs7-pad@1", 16);
      const { legacy, ported } = runBoth(spec, APPLE_5);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "pkcs7-pad");
      // KAT sanity floor: padded length is 16 (5 input + 11 padding).
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[15]).toBe(0x0b); // 11 = 0x0b pad length
    });

    it("generic.pkcs7-unpad@1 emits byte-equal frames across both dispatch paths", () => {
      // Pre-padded 16-byte input: "apple" + 11 copies of 0x0b.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);
      padded.fill(0x0b, 5);

      const spec = singleStepSpec("pkcs7-unpad-smoke@1", "generic.pkcs7-unpad@1", 16);
      const { legacy, ported } = runBoth(spec, padded);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "pkcs7-unpad");
      // KAT sanity floor: unpadded length recovers to 5.
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("generic.zero-pad@1 emits byte-equal frames across both dispatch paths", () => {
      const spec = singleStepSpec("zero-pad-smoke@1", "generic.zero-pad@1", 16);
      const { legacy, ported } = runBoth(spec, APPLE_5);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "zero-pad");
      // KAT sanity floor: padded length is 16 with 11 trailing zeros.
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[15]).toBe(0x00);
    });

    it("generic.zero-unpad@1 emits byte-equal frames across both dispatch paths", () => {
      // Pre-zero-padded 16-byte input: "apple" + 11 zero bytes.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);
      // remaining bytes already zero-initialized by Uint8Array

      const spec = singleStepSpec("zero-unpad-smoke@1", "generic.zero-unpad@1", 16);
      const { legacy, ported } = runBoth(spec, padded);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "zero-unpad");
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("generic.iso7816-4-pad@1 emits byte-equal frames across both dispatch paths", () => {
      const spec = singleStepSpec("iso7816-4-pad-smoke@1", "generic.iso7816-4-pad@1", 16);
      const { legacy, ported } = runBoth(spec, APPLE_5);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "iso7816-4-pad");
      // KAT sanity floor: padded length is 16, sentinel 0x80 at offset 5.
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[5]).toBe(0x80);
    });

    it("generic.iso7816-4-unpad@1 emits byte-equal frames across both dispatch paths", () => {
      // Pre-padded: "apple" + 0x80 + 10 zero bytes = 16 total.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);
      padded[5] = 0x80;

      const spec = singleStepSpec("iso7816-4-unpad-smoke@1", "generic.iso7816-4-unpad@1", 16);
      const { legacy, ported } = runBoth(spec, padded);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "iso7816-4-unpad");
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });
  });

  // ─── (b) Pad+unpad round-trip equivalence ────────────────────────────

  describe("(b) pad+unpad round-trip preserves original bytes under ported path", () => {
    const padUnpadSpec = (padType: string, unpadType: string, blockSize: number): CipherSpec => ({
      id: `roundtrip-${padType}@1`,
      name: `Slice 1.3 ${padType} + ${unpadType} round-trip`,
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "pad", type: padType, params: { blockSize } },
        { kind: "step", id: "unpad", type: unpadType, params: { blockSize } },
      ],
    });

    it("PKCS#7 round-trip recovers the original under ported dispatch", () => {
      const spec = padUnpadSpec("generic.pkcs7-pad@1", "generic.pkcs7-unpad@1", 16);
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(APPLE_5),
        portedDispatchEnabled: true,
      });
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("zero-pad round-trip recovers the original (non-zero-terminating input) under ported dispatch", () => {
      const spec = padUnpadSpec("generic.zero-pad@1", "generic.zero-unpad@1", 16);
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(APPLE_5),
        portedDispatchEnabled: true,
      });
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("ISO 7816-4 round-trip recovers the original under ported dispatch", () => {
      const spec = padUnpadSpec("generic.iso7816-4-pad@1", "generic.iso7816-4-unpad@1", 16);
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(APPLE_5),
        portedDispatchEnabled: true,
      });
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });
  });

  // ─── (c) Already-aligned input edge cases (the three schemes diverge) ──

  describe("(c) already-aligned input — three pad schemes diverge as documented", () => {
    it("PKCS#7 appends a full extra block of 0x10 when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("pkcs7-pad-aligned@1", "generic.pkcs7-pad@1", 16);
      const { legacy, ported } = runBoth(spec, ALIGNED_16);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "pkcs7-pad-aligned");
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(32);
      // Trailing 16 bytes are all 0x10 (= blockSize), per PKCS#7's "add full
      // extra block on alignment" rule. RFC 5652 §6.3.
      for (let i = 16; i < 32; i++) {
        expect(ported.finalState.bytes[i]).toBe(0x10);
      }
    });

    it("zero-pad is a no-op passthrough when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("zero-pad-aligned@1", "generic.zero-pad@1", 16);
      const { legacy, ported } = runBoth(spec, ALIGNED_16);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "zero-pad-aligned");
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(ALIGNED_16));
    });

    it("ISO 7816-4 appends 0x80 + 15 zeros when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("iso7816-4-pad-aligned@1", "generic.iso7816-4-pad@1", 16);
      const { legacy, ported } = runBoth(spec, ALIGNED_16);
      expectFrameStreamsEqual(ported.frames, legacy.frames, "iso7816-4-pad-aligned");
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(32);
      expect(ported.finalState.bytes[16]).toBe(0x80);
      for (let i = 17; i < 32; i++) {
        expect(ported.finalState.bytes[i]).toBe(0x00);
      }
    });
  });

  // ─── (d) Throw parity on malformed input ─────────────────────────────

  describe("(d) malformed-input throws survive the lift adapter — both paths throw the same", () => {
    it("pkcs7-unpad throws on a block with mismatched trailing bytes — same message on both paths", () => {
      // 16-byte block claiming pad length 5 (last byte = 0x05) but with
      // a mismatched byte in the trailing pad region. Triggers the
      // "padding byte at offset N is X, expected 5" throw.
      const malformed = new Uint8Array(16);
      malformed.fill(0xab, 0, 11); // 11 data bytes
      malformed.fill(0x05, 11); // 5 supposed pad bytes
      malformed[12] = 0x99; // corrupt one of them

      const spec = singleStepSpec("pkcs7-unpad-malformed@1", "generic.pkcs7-unpad@1", 16);

      const expectedMessage = /pkcs7-unpad: padding byte at offset 12 is 153, expected 5/;
      expect(() =>
        runSpec(spec, buildDefaultRegistry(), { initialState: makeBytesState(malformed) }),
      ).toThrow(expectedMessage);
      expect(() =>
        runSpec(spec, buildDefaultRegistry(), {
          initialState: makeBytesState(malformed),
          portedDispatchEnabled: true,
        }),
      ).toThrow(expectedMessage);
    });

    it("iso7816-4-unpad throws on an all-zeros block (no sentinel) — same message on both paths", () => {
      const allZeros = new Uint8Array(16); // already zero-initialized

      const spec = singleStepSpec("iso7816-4-unpad-no-sentinel@1", "generic.iso7816-4-unpad@1", 16);
      const expectedMessage = /no 0x80 sentinel found/;
      expect(() =>
        runSpec(spec, buildDefaultRegistry(), { initialState: makeBytesState(allZeros) }),
      ).toThrow(expectedMessage);
      expect(() =>
        runSpec(spec, buildDefaultRegistry(), {
          initialState: makeBytesState(allZeros),
          portedDispatchEnabled: true,
        }),
      ).toThrow(expectedMessage);
    });
  });
});
