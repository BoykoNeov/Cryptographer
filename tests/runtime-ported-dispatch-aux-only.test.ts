/**
 * Slice 1.2 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the THREE byte-typed aux-only step
 * types lifted in Slice 1.2 (the fourth, the matrix `generic.iv-load@1`,
 * retired in Phase 5 Slice 5.1 with the MatrixState shape):
 *
 *   - `generic.aux-load@1`  — pure source (no state, no aux read).
 *   - `generic.aux-copy@1`  — aux read + aux write, Uint8Array shape.
 *   - `generic.aux-xor@1`   — two aux reads + one aux write; the
 *                              load-bearing case for the Map-iteration-
 *                              order invariant called out in
 *                              `ProjectionMetadata`'s contract comment.
 *
 * Two test surfaces (was three — (b) removed in Slice B1.4b):
 *
 *   (a) **Synthetic 3-step spec** — exercises each lifted step type in
 *       turn under both flag values. Frame-by-frame deep-equality.
 *
 *   (b) **REMOVED in Slice B1.4b.** Was the AES-128 CBC KAT + frame-parity
 *       smoke — the only shipped spec that exercised the matrix `iv-load`.
 *       CBC is now byte-native (no legacy frame stream; the IV rides a
 *       port-native `aux-load-bytes@1` "fetch-iv" leaf), so there's nothing
 *       to compare against. The CBC KAT lives in aes-128-cbc-kat; `iv-load`'s
 *       ported-vs-legacy parity is still pinned by the synthetic (a) spec.
 *
 *   (c) **Targeted invariant pins** for the two hazards the advisor
 *       flagged before Slice 1.2 work began:
 *         - Map iteration order: `auxXor`'s metadata returns the binding
 *           in `[from, into]` order, so the runtime's auxReadMissing
 *           array matches the legacy executor's `auxReads: [from, into]`
 *           order. Drift here would break frame-parity in subtle ways
 *           (Vitest's `.toEqual` is order-insensitive on Maps, but the
 *           auxReadMissing field is an ARRAY — order matters).
 *         - Empty-auxName sentinel: a fresh palette drop with unset
 *           params yields a legacy frame with no auxWrites; the ported
 *           path's metadata must return an EMPTY write binding rather
 *           than `[port → ""]` (which would corrupt `aux.set("", ...)`).
 *
 * The existing `tests/runtime-ported-dispatch.test.ts` covers the
 * Phase-0 byte-substitution + add-round-key entries; this file is its
 * Slice-1.2 sibling.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── State / aux equality helpers (mirror the Phase-0 dispatch tests) ───

const expectStatesEqual = (a: State, b: State, label: string): void => {
  expect(a.shape, `${label}: shape`).toBe(b.shape);
  switch (a.shape) {
    case "bytes": {
      if (b.shape !== a.shape) return;
      expect(Array.from(a.bytes), `${label}: bytes`).toEqual(Array.from(b.bytes));
      return;
    }
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

// ─── (a) Synthetic 4-step spec ──────────────────────────────────────────

/**
 * Hand-built spec exercising all four Slice 1.2 step types. The data
 * flow is the head of a CBC composition: load an IV literal, copy it
 * into the chain accumulator, XOR a per-block value into it, then run
 * iv-load to obtain the matrix-shaped chain value the downstream cipher
 * would consume. State is passthrough throughout (each step's
 * shapeContract is `{ input: "any", output: "preserveInput" }`).
 *
 * The four leaves are NOT wrapped in any container — Slice 1.2 doesn't
 * touch iterate/feistel-round handling. The flat trace is what matters
 * for frame-parity.
 */
const auxOnlySpec: CipherSpec = {
  id: "test-aux-only@1",
  name: "Slice 1.2 aux-only smoke",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "load-iv",
      type: "generic.aux-load@1",
      params: {
        auxName: "iv-literal",
        // 16 bytes — matches AES block size so iv-load can run after.
        value: [
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
          0x0f,
        ],
      },
    },
    {
      kind: "step",
      id: "copy-iv-to-chain",
      type: "generic.aux-copy@1",
      params: { from: "iv-literal", to: "chain-bytes" },
    },
    {
      kind: "step",
      id: "xor-plaintext-into-chain",
      type: "generic.aux-xor@1",
      params: { from: "plaintext-block", into: "chain-bytes" },
    },
    // The matrix `generic.iv-load@1` step (chain-bytes → MatrixState
    // chain-matrix) retired in Phase 5 Slice 5.1 (2026-05-30) with the
    // MatrixState shape; the three surviving byte-typed aux primitives keep
    // the frame-parity coverage.
  ],
};

const auxOnlyInitialState = () => makeBytesState(new Uint8Array(0));
const auxOnlyInitialAux = (): Map<string, AuxValue> =>
  new Map<string, AuxValue>([
    [
      // A 16-byte "plaintext block" that the aux-xor mixes into the chain.
      "plaintext-block",
      new Uint8Array([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
      ]),
    ],
  ]);

describe("runtime — ported dispatch, Slice 1.2 aux-only primitives", () => {
  describe("(a) synthetic 3-step spec — frame-by-frame parity", () => {
    it("emits byte-equal frames across the three lifted aux step types", () => {
      const legacy = runSpec(auxOnlySpec, buildDefaultRegistry(), {
        initialState: auxOnlyInitialState(),
        initialAux: auxOnlyInitialAux(),
      });
      const ported = runSpec(auxOnlySpec, buildDefaultRegistry(), {
        initialState: auxOnlyInitialState(),
        initialAux: auxOnlyInitialAux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "aux-only synthetic");
    });

    it("end-to-end aux state matches: chain-bytes is iv XOR plaintext", () => {
      const ported = runSpec(auxOnlySpec, buildDefaultRegistry(), {
        initialState: auxOnlyInitialState(),
        initialAux: auxOnlyInitialAux(),
        portedDispatchEnabled: true,
      });

      // Expected XOR: IV (00..0f) ⊕ plaintext (6b..2a)
      const expectedChain = new Uint8Array([
        0x6b ^ 0x00,
        0xc1 ^ 0x01,
        0xbe ^ 0x02,
        0xe2 ^ 0x03,
        0x2e ^ 0x04,
        0x40 ^ 0x05,
        0x9f ^ 0x06,
        0x96 ^ 0x07,
        0xe9 ^ 0x08,
        0x3d ^ 0x09,
        0x7e ^ 0x0a,
        0x11 ^ 0x0b,
        0x73 ^ 0x0c,
        0x93 ^ 0x0d,
        0x17 ^ 0x0e,
        0x2a ^ 0x0f,
      ]);
      const chainBytes = ported.finalAux.get("chain-bytes");
      expect(chainBytes).toBeInstanceOf(Uint8Array);
      expect(Array.from(chainBytes as Uint8Array)).toEqual(Array.from(expectedChain));
    });
  });

  // ─── (b) AES-128 CBC — REMOVED in Slice B1.4b ───────────────────────────
  // Was the real-spec legacy-vs-ported frame-parity smoke (iv-load + the AES
  // core + chaining on the matrix CBC spec). CBC is now byte-native (no legacy
  // frame stream); its KAT lives in aes-128-cbc-kat. The iv-load primitive
  // stays parity-pinned by the synthetic (a) spec above.

  // ─── (c) Targeted invariants for the two pre-Slice-1.2 hazards ──────────

  describe("(c) hazard pins (advisor flags before Slice 1.2 work began)", () => {
    it("auxReadMissing iteration order on aux-xor matches the legacy executor's auxReads: [from, into]", () => {
      // Fresh-palette-drop variant: params has neither `from` nor `into`,
      // so the legacy executor declares `auxReads: ["", ""]`. Both
      // executions must produce `auxReadMissing: ["", ""]` in the same
      // order — a Map-iteration drift in `auxXorMeta.auxReadPorts` would
      // surface here even with vitest's order-insensitive Map .toEqual.
      const spec: CipherSpec = {
        id: "test-aux-xor-unset@1",
        name: "Aux-xor unset params",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "xor-unwired",
            type: "generic.aux-xor@1",
            params: {}, // no from, no into — fresh palette drop
          },
        ],
      };

      const legacy = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
      });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      expect(legacy.frames.length).toBe(1);
      expect(ported.frames.length).toBe(1);
      const legacyFrame = legacy.frames[0];
      const portedFrame = ported.frames[0];
      if (!legacyFrame || !portedFrame) throw new Error("frame missing");

      // The substantive assertion: auxReadMissing is an ARRAY, so order
      // matters. Both paths must produce ["", ""].
      expect(legacyFrame.auxReadMissing).toEqual(["", ""]);
      expect(portedFrame.auxReadMissing).toEqual(["", ""]);
    });

    it("aux-load with empty auxName produces NO auxWrites on either path (empty-sentinel)", () => {
      // Fresh palette drop: `auxName === ""`. Legacy returns `{ state }`
      // with no auxWrites. Ported must match: meta.auxWritePorts({auxName:""})
      // returns empty map; runtime auxWritten stays empty. If the meta
      // bound an empty-string aux key, the runtime would aux.set("", ...)
      // and the frame's auxWritten would diverge.
      const spec: CipherSpec = {
        id: "test-aux-load-unset@1",
        name: "Aux-load unset params",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "load-unwired",
            type: "generic.aux-load@1",
            params: {}, // no auxName
          },
        ],
      };

      const legacy = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
      });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      const legacyFrame = legacy.frames[0];
      const portedFrame = ported.frames[0];
      if (!legacyFrame || !portedFrame) throw new Error("frame missing");

      // No auxWrites under either path.
      expect(legacyFrame.auxWritten.size).toBe(0);
      expect(portedFrame.auxWritten.size).toBe(0);

      // Critical follow-on: the live aux map (carried through finalAux)
      // must not contain a "" key from a stray empty-string binding.
      expect(legacy.finalAux.has("")).toBe(false);
      expect(ported.finalAux.has("")).toBe(false);
    });

    it("aux-copy with empty target produces NO auxWrites and doesn't pollute aux", () => {
      // Sentinel test for the writer: aux-xor's write never fires (missing
      // reads → no write); aux-copy could plausibly mis-bind its `to`
      // empty-string case if its auxWritePorts didn't gate. (The matrix
      // `iv-load` empty-target case retired in Phase 5 Slice 5.1.)
      const spec: CipherSpec = {
        id: "test-copy-unset@1",
        name: "Aux-copy unset writer",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          // Seed a value the copy will read, so the read side succeeds
          // and the only divergence vector is the unset-write target.
          {
            kind: "step",
            id: "seed",
            type: "generic.aux-load@1",
            params: { auxName: "seed", value: [0xaa, 0xbb, 0xcc, 0xdd] },
          },
          {
            kind: "step",
            id: "copy-unset-target",
            type: "generic.aux-copy@1",
            params: { from: "seed", to: "" }, // empty target
          },
        ],
      };

      const legacy = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
      });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      // Full frame parity covers everything; this is a focused floor for
      // the empty-target case specifically.
      expectFrameStreamsEqual(ported.frames, legacy.frames, "unset-target-writers");

      // Empty-string key pollution check — both paths must agree.
      expect(ported.finalAux.has("")).toBe(false);
      expect(legacy.finalAux.has("")).toBe(false);
    });
  });
});
