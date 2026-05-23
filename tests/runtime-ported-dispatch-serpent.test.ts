/**
 * Slice 1.7 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the SIX Serpent step types lifted
 * in Slice 1.7:
 *
 *   - `serpent.key-expansion@1` — the THIRD one-to-many writer in the
 *     universal-port migration (after `aes.key-expansion@1` in Slice 1.4
 *     and `speck.key-schedule@1` in Slice 1.6). **33 output ports**
 *     (`key0` … `key32`), fixed across all three Serpent key sizes
 *     unlike AES (Nr+1, scales with `params.rounds`) and Speck (rounds,
 *     also scales). Function-form contract for uniformity with the
 *     precedents. Aux-only — no state ports; lift adapter creates a
 *     sentinel state and the runtime preserves the caller's
 *     `bytes`-shape across the call.
 *   - `serpent.add-round-key@1` — state-bearing single-aux-read step.
 *     Direct analog of `generic.add-round-key@1` (AES, Slice 1.4) but
 *     with `stateLayout: "bytes"` instead of `"matrix4x4-bytes"`.
 *     `byteLength: 16` on both state and aux-read ports (Serpent has
 *     no variant — 128-bit state and 128-bit round keys across all
 *     three key sizes).
 *   - `serpent.bit-permutation@1` / `serpent.sub-bytes@1` /
 *     `serpent.linear-transform@1` / `serpent.inv-linear-transform@1`
 *     — four pure bytes→bytes 16-byte fixed transforms, no aux. The
 *     cleanest possible lift batch (strictly simpler than Slice 1.3's
 *     padding primitives, which had variable output lengths).
 *
 * Four test surfaces (mirror the Slice 1.6 Speck test structure):
 *
 *   (a) **Reference KATs under flag-on** for all three Serpent variants
 *       (encrypt + decrypt). The "single-bit key, all-zero plaintext"
 *       vectors come from the Python reference (CryptoPlus pyserpent.py,
 *       a direct transcription of the Anderson/Biham/Knudsen reference
 *       code). KAT sanity floor — a failure here is a louder signal
 *       than a deep-equality miss across the dozens of frames per
 *       cipher.
 *
 *   (b) **Frame-by-frame byte parity** vs legacy dispatch for all 6
 *       specs (3 variants × {encrypt, decrypt}). Each Serpent variant's
 *       trace exercises key expansion + IP + 32 rounds (31 of them
 *       with full S-box + LT + AddRoundKey, the last with an extra
 *       AddRoundKey instead of LT) + FP, so the frame stream is dozens
 *       of frames each.
 *
 *   (c) **Round-key port ordering** — verifies that Map insertion order
 *       on the 33 emitted round keys matches the legacy `auxWrites`
 *       insertion order (`roundKey.0`, `roundKey.1`, …, `roundKey.32`).
 *       Mirrors the Slice 1.4/1.6 pins on AES/Speck key-expansion
 *       insertion order. Load-bearing for visualizations that iterate
 *       `frame.auxWritten.entries()` in spec order.
 *
 *   (d) **Per-primitive synthetic spec** — minimal spec exercising
 *       just `serpent.key-expansion@1` + one `serpent.add-round-key@1`
 *       leaf, to pin the isolated lift semantics without the algebra
 *       of all 32 rounds on top. Mirrors the Slice 1.5/1.6 per-primitive
 *       synthetic structure.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the Slice 1.4 / 1.5 / 1.6 dispatch tests) ─

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.7 Serpent fixtures`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.7 Serpent fixtures`);
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

// ─── Serpent reference KATs (pyserpent.py / Anderson-Biham-Knudsen reference) ─

const KEY_128 = "80000000000000000000000000000000";
const KEY_192 = "800000000000000000000000000000000000000000000000";
const KEY_256 = "8000000000000000000000000000000000000000000000000000000000000000";
const PLAINTEXT_ZERO = "00000000000000000000000000000000";
const CIPHERTEXT_128 = "264e5481eff42a4606abda06c0bfda3d";
const CIPHERTEXT_192 = "9e274ead9b737bb21efcfca548602689";
const CIPHERTEXT_256 = "a223aa1288463c0e2be38ebd825616c0";

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, Slice 1.7 Serpent step types", () => {
  // ─── (a) KAT sanity floor under flag-on ──────────────────────────────

  describe("(a) Reference KATs under portedDispatchEnabled: true", () => {
    it("Serpent-128 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_128);
    });

    it("Serpent-192 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent192Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_192)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_192);
    });

    it("Serpent-256 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent256Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_256)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_256);
    });

    it("Serpent-128 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent128DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_128)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });

    it("Serpent-192 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent192DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_192)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_192)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });

    it("Serpent-256 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent256DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_256)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_256)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });
  });

  // ─── (b) Frame-by-frame byte parity vs legacy ─────────────────────────

  describe("(b) Frame parity vs legacy dispatch — all 6 specs", () => {
    const runs: ReadonlyArray<{
      label: string;
      spec: CipherSpec;
      stateHex: string;
      keyHex: string;
    }> = [
      {
        label: "Serpent-128 encrypt",
        spec: serpent128Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_128,
      },
      {
        label: "Serpent-192 encrypt",
        spec: serpent192Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_192,
      },
      {
        label: "Serpent-256 encrypt",
        spec: serpent256Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_256,
      },
      {
        label: "Serpent-128 decrypt",
        spec: serpent128DecryptSpec,
        stateHex: CIPHERTEXT_128,
        keyHex: KEY_128,
      },
      {
        label: "Serpent-192 decrypt",
        spec: serpent192DecryptSpec,
        stateHex: CIPHERTEXT_192,
        keyHex: KEY_192,
      },
      {
        label: "Serpent-256 decrypt",
        spec: serpent256DecryptSpec,
        stateHex: CIPHERTEXT_256,
        keyHex: KEY_256,
      },
    ];

    for (const run of runs) {
      it(`${run.label} — frame-by-frame byte equality`, () => {
        const legacy = runSpec(run.spec, buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(run.stateHex)),
          initialAux: new Map<string, AuxValue>([["key", bytesFromHex(run.keyHex)]]),
        });
        const ported = runSpec(run.spec, buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(run.stateHex)),
          initialAux: new Map<string, AuxValue>([["key", bytesFromHex(run.keyHex)]]),
          portedDispatchEnabled: true,
        });

        expectFrameStreamsEqual(ported.frames, legacy.frames, run.label);
      });
    }
  });

  // ─── (c) Round-key port insertion order ──────────────────────────────

  describe("(c) serpent.key-expansion@1 emits 33 round keys in insertion order", () => {
    it("aux Map iteration preserves roundKey.0 → roundKey.32 ordering under ported", () => {
      const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });

      // Find the key-expansion frame (typically frame 0 — the schedule
      // runs once at the start of every Serpent spec). Locating by
      // stepType keeps the test robust to any future leading aux-load
      // additions to the builder.
      const ksFrame = trace.frames.find((f) => f.stepType === "serpent.key-expansion@1");
      if (!ksFrame) throw new Error("expected one serpent.key-expansion@1 frame");

      const keys = [...ksFrame.auxWritten.keys()];
      expect(keys.length).toBe(33);
      const expected: string[] = [];
      for (let i = 0; i < 33; i++) expected.push(`roundKey.${i}`);
      expect(keys).toEqual(expected);

      // Cross-check: each round-key value is a 16-byte Uint8Array
      // (Serpent round keys are always 128 bits). Pins that the ported
      // path didn't accidentally widen a single round key into a
      // MatrixState or other variant — layout "raw" on the output
      // ports must decode back to Uint8Array.
      for (const k of keys) {
        const v = ksFrame.auxWritten.get(k);
        expect(v).toBeInstanceOf(Uint8Array);
        expect((v as Uint8Array).length).toBe(16);
      }
    });
  });

  // ─── (d) Per-primitive synthetic spec ────────────────────────────────

  describe("(d) per-primitive synthetic — key-expansion + one add-round-key", () => {
    // Two-step spec: schedule expands the master key, then a single
    // AddRoundKey consumes roundKey.0 against the plaintext. Pins the
    // lift in isolation — the cipher-level KAT (a) and full frame
    // parity (b) above layer 31 more rounds + IP/FP/LT/SubBytes on top;
    // this fixture is the smallest fixture that exercises both ported
    // leaves end-to-end. Matches Slice 1.6 (d) synthetic shape.
    const spec: CipherSpec = {
      id: "test-serpent-add-round-key@1",
      name: "Slice 1.7 — serpent schedule + one AddRoundKey synthetic",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        {
          kind: "step",
          id: "schedule",
          type: "serpent.key-expansion@1",
          params: {
            keyAuxName: "key",
            outputPrefix: "roundKey",
            keyByteLength: 16,
          },
        },
        {
          kind: "step",
          id: "round.0.add-round-key",
          type: "serpent.add-round-key@1",
          params: { roundKeyAux: "roundKey.0" },
        },
      ],
    };

    it("frame-by-frame byte equality across both dispatch paths", () => {
      const legacy = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
      });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "serpent schedule + one AddRoundKey");
    });
  });
});
