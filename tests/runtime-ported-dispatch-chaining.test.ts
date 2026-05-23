/**
 * Slice 1.5 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the TWO chaining primitives lifted
 * in Slice 1.5:
 *
 *   - `generic.xor-aux-into-state@1` — reads a MatrixState chain from
 *     `aux[auxName]` and XORs it into matrix-shaped state. The
 *     load-bearing case for Slice 1.5's INPUT-SIDE aux-value widening at
 *     `runtime.ts:243-261` — the previous hard throw on non-Uint8Array
 *     aux was a Slice-1.2 deferral; the chaining XOR is the first ported
 *     step type that actually reads a MatrixState through an input port.
 *   - `generic.state-to-aux@1` — snapshots current state into
 *     `aux[auxName]` as a MatrixState (decoded via output port's
 *     `layout: "matrix-cm-4x4"` — same path Slice-1.2's `iv-load`
 *     already exercises on the output side).
 *
 * Four test surfaces:
 *
 *   (a) **Per-primitive synthetic spec** — minimal flow exercising each
 *       lifted step under both flag values. Frame-by-frame deep
 *       equality. Pins isolated unit semantics without the algebra of a
 *       full cipher on top.
 *
 *   (b) **AES-128 CBC encrypt (NIST SP 800-38A §F.2.1)** — the load-
 *       bearing cipher gate per the Slice 1.5 plan. After this slice,
 *       every step type the CBC encrypt body uses is ported (iv-load
 *       Slice 1.2, key-expansion + AES core Slice 1.4, padding Slice
 *       1.3, plus today's xor-aux-into-state + state-to-aux). Iterate,
 *       split-blocks, concat-blocks, compute-block-count remain legacy
 *       per Slice 1.3's deferral — they're outside the per-leaf
 *       dispatch.
 *
 *   (c-pre) **Per-primitive aux-copy variant preservation** — minimal
 *       3-step spec (aux-load → iv-load → aux-copy) pinning that aux-copy
 *       under the `"preserve-input-variant"` layout sentinel (Slice 1.5b)
 *       round-trips a MatrixState aux without flattening it to Uint8Array.
 *       Failing this BEFORE (c) below is the cleaner debug signal — the
 *       full multi-block CBC pipeline can fail for reasons other than the
 *       variant gap.
 *
 *   (c) **AES-128 CBC decrypt (NIST SP 800-38A §F.2.2)** — exercises a
 *       previously-untested ported codepath: `aux-copy` (ported in
 *       Slice 1.2) reading a MatrixState chain that `state-to-aux`
 *       wrote. UNSKIPPED 2026-05-23 once Slice 1.5b shipped the
 *       `"preserve-input-variant"` layout sentinel — the runtime now
 *       captures the source variant from `portedAuxRead` and clones it
 *       with fresh output bytes, so the next iteration's
 *       `xor-aux-into-state` finds a MatrixState exactly where the legacy
 *       path puts one.
 *
 *   (d) **Empty-auxName parity** — fresh-palette-drop case where
 *       `auxName === ""`. xor-aux-into-state legacy declares
 *       `auxReads: [""]`; the metadata emits the binding regardless so
 *       `auxReadMissing: [""]` matches under both paths. state-to-aux
 *       legacy early-returns with no auxWrites; the metadata's
 *       `auxWritePorts` returns an empty Map so the runtime doesn't
 *       try to `aux.set("", ...)`.
 *
 * The existing Slice-1.2 test (b) already exercises AES-128 CBC encrypt
 * under flag-on — but `xor-aux-into-state` + `state-to-aux` were both
 * still legacy then, so the per-leaf dispatch took the legacy branch for
 * those steps. After Slice 1.5 they take the ported branch; the gate
 * re-runs the same KAT to confirm the cipher's algebra still holds.
 */

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── State / aux equality helpers (mirror the Slice 1.2 / 1.4 dispatch tests) ─

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.5 fixtures`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.5 fixtures`);
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

// ─── (a) Per-primitive synthetic specs ──────────────────────────────────

describe("runtime — ported dispatch, Slice 1.5 chaining primitives", () => {
  describe("(a) per-primitive synthetic specs — frame-by-frame parity", () => {
    /**
     * Two-step spec exercising `xor-aux-into-state` on its own. iv-load
     * (ported, Slice 1.2) writes MatrixState to aux["chain"]; the second
     * step XORs that MatrixState into the matrix-shaped state. This is
     * the smallest fixture that drives a MatrixState through an input
     * port — pinning Slice 1.5's runtime widening in isolation, before
     * the AES-CBC algebra layers on top.
     */
    const xorSpec: CipherSpec = {
      id: "test-xor-aux-into-state@1",
      name: "Slice 1.5 — xor-aux-into-state synthetic",
      stateShape: "matrix4x4-bytes",
      inputs: { plaintext: { shape: "matrix4x4-bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "iv-load",
          type: "generic.iv-load@1",
          params: { ivAuxName: "iv", outAuxName: "chain" },
        },
        {
          kind: "step",
          id: "cbc-xor",
          type: "generic.xor-aux-into-state@1",
          params: { auxName: "chain" },
        },
      ],
    };

    const xorInitialState = () =>
      matrixFromBytes(
        new Uint8Array([
          0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
          0x2a,
        ]),
      );
    const xorInitialAux = (): Map<string, AuxValue> =>
      new Map<string, AuxValue>([
        [
          "iv",
          new Uint8Array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
          ]),
        ],
      ]);

    it("xor-aux-into-state — MatrixState aux read survives the port projection", () => {
      const legacy = runSpec(xorSpec, buildDefaultRegistry(), {
        initialState: xorInitialState(),
        initialAux: xorInitialAux(),
      });
      const ported = runSpec(xorSpec, buildDefaultRegistry(), {
        initialState: xorInitialState(),
        initialAux: xorInitialAux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "xor-aux-into-state synthetic");

      // Sanity floor: post-XOR state is plaintext ⊕ IV. If the input-side
      // widening corrupted the operand, the bytes would be wrong even
      // before frame-parity caught it.
      expect(ported.finalState.shape).toBe("matrix4x4-bytes");
      if (ported.finalState.shape !== "matrix4x4-bytes") return;
      const expected = new Uint8Array([
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
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(expected));
    });

    /**
     * Single-step spec exercising `state-to-aux` on its own. Snapshots
     * the initial state into aux["snap"] as a MatrixState. Pins that the
     * output port's `layout: "matrix-cm-4x4"` decode produces a
     * MatrixState (matching legacy's `cloneState(state)` shape).
     */
    const snapshotSpec: CipherSpec = {
      id: "test-state-to-aux@1",
      name: "Slice 1.5 — state-to-aux synthetic",
      stateShape: "matrix4x4-bytes",
      inputs: { plaintext: { shape: "matrix4x4-bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "snap-it",
          type: "generic.state-to-aux@1",
          params: { auxName: "snap" },
        },
      ],
    };

    const snapshotInitialState = () =>
      matrixFromBytes(
        new Uint8Array([
          0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
          0xef,
        ]),
      );

    it("state-to-aux — snapshot lands as MatrixState (layout matrix-cm-4x4 decode)", () => {
      const legacy = runSpec(snapshotSpec, buildDefaultRegistry(), {
        initialState: snapshotInitialState(),
      });
      const ported = runSpec(snapshotSpec, buildDefaultRegistry(), {
        initialState: snapshotInitialState(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "state-to-aux synthetic");

      // The decoded aux value must be a MatrixState — a raw Uint8Array
      // would break downstream consumers (xor-aux-into-state validates
      // operand.shape === "matrix4x4-bytes").
      const snap = ported.finalAux.get("snap");
      expect(typeof snap).toBe("object");
      if (typeof snap !== "object" || snap === null || !("shape" in snap)) {
        throw new Error("snap not a State");
      }
      expect((snap as { shape: string }).shape).toBe("matrix4x4-bytes");
      const snapBytes = (snap as { bytes: Uint8Array }).bytes;
      expect(Array.from(snapBytes)).toEqual([
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
      ]);
    });
  });

  // ─── (b) AES-128 CBC encrypt — full frame parity ────────────────────────

  describe("(b) AES-128 CBC encrypt (NIST SP 800-38A §F.2.1)", () => {
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

    it("emits frame-by-frame byte-equal traces vs legacy dispatch (all chaining primitives ported)", () => {
      // After Slice 1.5, every leaf the CBC encrypt body touches is on
      // the ported path: key-expansion + AES core (Slice 1.4), padding
      // (Slice 1.3), iv-load (Slice 1.2), and now xor-aux-into-state +
      // state-to-aux (Slice 1.5). split/concat/count and the iterate
      // runtime stay legacy per Slice 1.3 deferral, but they sit
      // OUTSIDE the per-leaf dispatch so they're invariant to the flag.
      const legacy = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
      });
      const ported = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "aes-128 cbc encrypt");
    });
  });

  // ─── (c-pre) Per-primitive: aux-copy preserves MatrixState variant ─────
  //
  // Slice 1.5b pin. Fixture: aux-load (Uint8Array IV) → iv-load (Uint8Array
  // → MatrixState into aux[chain-matrix]) → aux-copy (chain-matrix →
  // chain-matrix-copy). Under flag-on, aux-copy MUST emit a MatrixState
  // into the destination key — not a flattened Uint8Array. This is the
  // pin that fails first if a future refactor breaks the
  // `"preserve-input-variant"` layout sentinel; failure surfaces here
  // BEFORE block (c) below buries it inside a 1200+-frame CBC decrypt
  // diff.

  describe("(c-pre) aux-copy MatrixState round-trip (variant-preserving layout)", () => {
    // Build the smallest spec that proves the variant survives aux-copy
    // under flag-on. iv-load is the simplest way to get a MatrixState
    // into aux from a byte source — it reads aux[ivAuxName] as bytes
    // and writes aux[outAuxName] as a MatrixState (output port's layout
    // tag = "matrix-cm-4x4").
    const variantSpec: CipherSpec = {
      id: "test-aux-copy-variant@1",
      name: "Slice 1.5b aux-copy MatrixState pin",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "load-iv-bytes",
          type: "generic.aux-load@1",
          params: {
            auxName: "iv-bytes",
            // Same 16-byte IV used in the §F.2 KATs above — convenient
            // pattern, no algorithmic significance.
            value: [
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
              0x0e, 0x0f,
            ],
          },
        },
        {
          kind: "step",
          id: "iv-to-matrix",
          type: "generic.iv-load@1",
          params: { ivAuxName: "iv-bytes", outAuxName: "chain-matrix" },
        },
        {
          kind: "step",
          id: "copy-matrix-to-destination",
          type: "generic.aux-copy@1",
          params: { from: "chain-matrix", to: "chain-matrix-copy" },
        },
      ],
    };

    const initial = () => makeBytesState(new Uint8Array(0));
    const expectedMatrix = matrixFromBytes(
      new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
      ]),
    );

    it("aux-copy emits a MatrixState (not Uint8Array) when source aux is a MatrixState", () => {
      const ported = runSpec(variantSpec, buildDefaultRegistry(), {
        initialState: initial(),
        portedDispatchEnabled: true,
      });

      const copied = ported.finalAux.get("chain-matrix-copy");
      // The pin: variant SHAPE must be preserved across aux-copy.
      // Without the "preserve-input-variant" layout sentinel, this is a
      // Uint8Array and the test fails — exactly the regression Slice
      // 1.5b ships to prevent.
      expect(copied).toBeDefined();
      expect(typeof copied).toBe("object");
      if (typeof copied !== "object" || copied === null || !("shape" in copied)) {
        throw new Error("aux-copy variant-preservation: chain-matrix-copy not a State");
      }
      expect((copied as { shape: string }).shape).toBe("matrix4x4-bytes");
      // Bytes must also be byte-equal — variant preservation without
      // byte preservation is a different bug.
      expect(Array.from((copied as { bytes: Uint8Array }).bytes)).toEqual(
        Array.from(expectedMatrix.bytes),
      );
    });

    it("emits frame-by-frame byte-equal traces vs legacy dispatch (variant + bytes)", () => {
      const legacy = runSpec(variantSpec, buildDefaultRegistry(), {
        initialState: initial(),
      });
      const ported = runSpec(variantSpec, buildDefaultRegistry(), {
        initialState: initial(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "aux-copy variant-preservation");
    });

    it("aux-copy of a Uint8Array source still emits a Uint8Array (no false-positive variant promotion)", () => {
      // Negative pin: the "preserve-input-variant" sentinel must NOT
      // accidentally promote a Uint8Array source into a State variant.
      // The Uint8Array branch in auxPortBytesToValue is meant to be a
      // pass-through; a regression that wraps it in a State would be
      // a different kind of variant gap.
      const rawSpec: CipherSpec = {
        id: "test-aux-copy-raw@1",
        name: "Slice 1.5b aux-copy Uint8Array pin",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "load-raw",
            type: "generic.aux-load@1",
            params: {
              auxName: "raw-bytes",
              value: [0xaa, 0xbb, 0xcc, 0xdd],
            },
          },
          {
            kind: "step",
            id: "copy-raw",
            type: "generic.aux-copy@1",
            params: { from: "raw-bytes", to: "raw-bytes-copy" },
          },
        ],
      };
      const ported = runSpec(rawSpec, buildDefaultRegistry(), {
        initialState: initial(),
        portedDispatchEnabled: true,
      });
      const copied = ported.finalAux.get("raw-bytes-copy");
      expect(copied).toBeInstanceOf(Uint8Array);
      expect(Array.from(copied as Uint8Array)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
    });
  });

  // ─── (c) AES-128 CBC decrypt — UNSKIPPED 2026-05-23 (Slice 1.5b GREEN) ─
  //
  // Originally `describe.skip`d at Slice 1.5 because the decrypt CBC body
  // advances the chain via `aux-copy(next-chain → chain)` where
  // `aux[next-chain]` is a MatrixState (written by `state-to-aux`, ported
  // in 1.5). `aux-copy` was ported in Slice 1.2 with a STATIC
  // `PortContract.outputs["result"].layout: "raw"`, which dropped the
  // MatrixState variant on decode and corrupted the next iteration's
  // `xor-aux-into-state` aux read.
  //
  // Slice 1.5b (Open #2 fix, candidate (a)) added a
  // `"preserve-input-variant"` layout sentinel: the runtime captures the
  // source AuxValue from `portedAuxRead.get(<first auxReadPorts binding>)`
  // and `auxPortBytesToValue` clones the source variant shape with a
  // fresh-bytes copy of the output bytes. aux-copy's output port now
  // declares the sentinel; one input → one output makes the
  // single-source convention unambiguous.
  //
  // This block becomes the gate: KAT sanity (decrypt produces the original
  // plaintext under flag-on) + frame-by-frame parity with legacy across
  // the full multi-block chain-advance path.

  describe("(c) AES-128 CBC decrypt (NIST SP 800-38A §F.2.2) — variant-preserving aux passthrough", () => {
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

    const initial = () => makeBytesState(bytesFromHex(CBC_CIPHERTEXT_4_BLOCKS));
    const buildAux = (): Map<string, AuxValue> =>
      new Map<string, AuxValue>([
        ["key", bytesFromHex(KEY)],
        ["iv", bytesFromHex(IV)],
      ]);

    it("produces the original plaintext under portedDispatchEnabled: true (KAT sanity floor)", () => {
      const trace = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_4_BLOCKS);
    });

    it("emits frame-by-frame byte-equal traces vs legacy dispatch (chain-advance path covered)", () => {
      const legacy = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
      });
      const ported = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "aes-128 cbc decrypt");
    });
  });

  // ─── (d) Empty-auxName parity (fresh-palette-drop sentinel) ─────────────

  describe("(d) empty-auxName sentinel parity", () => {
    it('xor-aux-into-state with empty auxName: auxReadMissing matches legacy\'s [""]', () => {
      // Fresh palette drop: params = {} → auxName === "". Legacy
      // declares `auxReads: [""]` so auxReadMissing materializes as
      // [""]. Metadata must emit the binding even for empty auxName so
      // both paths land in the runtime's missing-read bookkeeping
      // identically. (Same hazard pinned for aux-xor in Slice 1.2's
      // test (c).)
      const spec: CipherSpec = {
        id: "test-xor-unset@1",
        name: "xor-aux-into-state unset",
        stateShape: "matrix4x4-bytes",
        inputs: { plaintext: { shape: "matrix4x4-bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "xor-unwired",
            type: "generic.xor-aux-into-state@1",
            params: {},
          },
        ],
      };

      const initial = () => matrixFromBytes(new Uint8Array(16));
      const legacy = runSpec(spec, buildDefaultRegistry(), { initialState: initial() });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: initial(),
        portedDispatchEnabled: true,
      });

      expect(legacy.frames.length).toBe(1);
      expect(ported.frames.length).toBe(1);
      const lf = legacy.frames[0];
      const pf = ported.frames[0];
      if (!lf || !pf) throw new Error("frame missing");
      expect(lf.auxReadMissing).toEqual([""]);
      expect(pf.auxReadMissing).toEqual([""]);
    });

    it("state-to-aux with empty auxName: no auxWrites and no empty-string aux pollution", () => {
      // Fresh palette drop: params = {} → auxName === "". Legacy
      // early-returns with no auxWrites. Metadata must return empty Map
      // from auxWritePorts so the runtime doesn't try to aux.set("",
      // ...). (Same hazard pattern as iv-load's outAuxName="" in Slice
      // 1.2.)
      const spec: CipherSpec = {
        id: "test-state-to-aux-unset@1",
        name: "state-to-aux unset",
        stateShape: "matrix4x4-bytes",
        inputs: { plaintext: { shape: "matrix4x4-bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "snap-unwired",
            type: "generic.state-to-aux@1",
            params: {},
          },
        ],
      };

      const initial = () => matrixFromBytes(new Uint8Array(16));
      const legacy = runSpec(spec, buildDefaultRegistry(), { initialState: initial() });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: initial(),
        portedDispatchEnabled: true,
      });

      const lf = legacy.frames[0];
      const pf = ported.frames[0];
      if (!lf || !pf) throw new Error("frame missing");

      expect(lf.auxWritten.size).toBe(0);
      expect(pf.auxWritten.size).toBe(0);
      expect(legacy.finalAux.has("")).toBe(false);
      expect(ported.finalAux.has("")).toBe(false);
    });
  });
});
