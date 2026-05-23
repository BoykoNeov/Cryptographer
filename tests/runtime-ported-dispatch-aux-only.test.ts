/**
 * Slice 1.2 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the FOUR aux-only step types lifted
 * in Slice 1.2:
 *
 *   - `generic.aux-load@1`  — pure source (no state, no aux read).
 *   - `generic.aux-copy@1`  — aux read + aux write, Uint8Array shape.
 *   - `generic.aux-xor@1`   — two aux reads + one aux write; the
 *                              load-bearing case for the Map-iteration-
 *                              order invariant called out in
 *                              `ProjectionMetadata`'s contract comment.
 *   - `generic.iv-load@1`   — aux read (Uint8Array) → aux write
 *                              (MatrixState). Exercises the PortContract
 *                              `layout: "matrix-cm-4x4"` decode path so
 *                              `xor-aux-into-state` downstream finds a
 *                              MatrixState rather than a Uint8Array.
 *
 * Three test surfaces:
 *
 *   (a) **Synthetic 4-step spec** — exercises each lifted step type in
 *       turn under both flag values. Frame-by-frame deep-equality.
 *
 *   (b) **AES-128 CBC KAT under `portedDispatchEnabled: true`** — the
 *       only place a shipped spec exercises `iv-load`. Validates that
 *       the cipher's algebra survives the ported path (KAT sanity floor
 *       per the slice plan's "KAT first, deep equality next" guidance)
 *       AND that frame-parity holds across all 1300+ frames of a real
 *       multi-block cipher run.
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

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── State / aux equality helpers (mirror the Phase-0 dispatch tests) ───

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.2 fixtures`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.2 fixtures`);
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
    {
      kind: "step",
      id: "iv-load-to-matrix",
      type: "generic.iv-load@1",
      params: { ivAuxName: "chain-bytes", outAuxName: "chain-matrix" },
    },
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
  describe("(a) synthetic 4-step spec — frame-by-frame parity", () => {
    it("emits byte-equal frames across all four lifted step types", () => {
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

    it("end-to-end aux state matches: chain-bytes is iv XOR plaintext, chain-matrix is the matrix form", () => {
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

      // iv-load wraps the same bytes into a MatrixState — the
      // PortContract's `layout: "matrix-cm-4x4"` ensures the runtime
      // reconstructs the variant, not a raw Uint8Array.
      const chainMatrix = ported.finalAux.get("chain-matrix");
      expect(typeof chainMatrix).toBe("object");
      if (typeof chainMatrix !== "object" || chainMatrix === null || !("shape" in chainMatrix)) {
        throw new Error("chain-matrix not a State");
      }
      expect((chainMatrix as { shape: string }).shape).toBe("matrix4x4-bytes");
      const matrixBytes = (chainMatrix as { bytes: Uint8Array }).bytes;
      expect(Array.from(matrixBytes)).toEqual(Array.from(expectedChain));
    });
  });

  // ─── (b) AES-128 CBC — real-spec smoke under portedDispatchEnabled: true ─

  describe("(b) AES-128 CBC (NIST SP 800-38A §F.2.1) — full frame parity", () => {
    const KEY = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV = "000102030405060708090a0b0c0d0e0f";
    const PLAINTEXT_4_BLOCKS =
      "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411e5fbc1191a0a52ef" +
      "f69f2445df4f9b17ad2b417be66c3710";
    const CBC_CIPHERTEXT_4_BLOCKS =
      "7649abac8119b246cee98e9b12e9197d" +
      "5086cb9b507219ee95db113a917678b2" +
      "73bed6b8e3c1743b7116e69e22229516" +
      "3ff1caa1681fac09120eca307586e1a7";

    const initial = () => makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS));
    const buildAux = (): Map<string, AuxValue> =>
      new Map<string, AuxValue>([
        ["key", bytesFromHex(KEY)],
        ["iv", bytesFromHex(IV)],
      ]);

    it("produces the published ciphertext under portedDispatchEnabled: true (KAT sanity floor)", () => {
      const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CBC_CIPHERTEXT_4_BLOCKS);
    });

    it("emits frame-by-frame byte-equal traces vs legacy dispatch (iv-load + Phase-0 entries combined)", () => {
      const legacy = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
      });
      const ported = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "aes-128 cbc");
    });
  });

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

    it("aux-copy / iv-load with empty target produce NO auxWrites and don't pollute aux", () => {
      // Same sentinel test for the other two writers. aux-xor's write
      // never fires (missing reads → no write); aux-copy and iv-load
      // could plausibly mis-bind their `to`/`outAuxName` empty-string
      // case if their auxWritePorts didn't gate.
      const spec: CipherSpec = {
        id: "test-copy-iv-unset@1",
        name: "Aux-copy/iv-load unset writers",
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
          // 16-byte seed for iv-load's structural validation.
          {
            kind: "step",
            id: "seed-16",
            type: "generic.aux-load@1",
            params: {
              auxName: "seed16",
              value: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            },
          },
          {
            kind: "step",
            id: "iv-load-unset-target",
            type: "generic.iv-load@1",
            params: { ivAuxName: "seed16", outAuxName: "" },
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
