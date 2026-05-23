/**
 * Slice 1.6 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the THREE Speck step types lifted
 * in Slice 1.6:
 *
 *   - `speck.key-schedule@1` — the SECOND one-to-many writer in the
 *     universal-port migration (after `aes.key-expansion@1` in Slice
 *     1.4). 22 output ports for Speck32/64 (`key0` … `key21`), exactly
 *     `params.rounds` ports vs AES's `params.rounds + 1`. Aux-only —
 *     no state ports, lift adapter creates a sentinel state and the
 *     runtime preserves the caller's `bytes`-shape across the call.
 *   - `speck.round@1` — state-bearing ARX round. `stateLayout: "bytes"`
 *     with polymorphic byteLength (Speck variants vary the block size).
 *     Single aux read `roundKey` bound to `params.roundKeyAux`.
 *   - `speck.round-inverse@1` — same port shape as the forward round;
 *     decrypt specs wire the round-key aux names in reverse order.
 *
 * Four test surfaces:
 *
 *   (a) **Beaulieu et al. 2013 Table 4.1 KAT under flag-on** for both
 *       byte conventions (BE-paper + LE-NSA). KAT sanity floor — a
 *       failure here is a louder signal than a deep-equality miss
 *       across 23 frames.
 *
 *   (b) **Frame-by-frame byte parity** vs legacy dispatch for the same
 *       two encrypt specs + the matching decrypt specs. Two encrypt + two
 *       decrypt = four 23-frame traces total, exercising both directions
 *       of the ARX round (round + round-inverse) under both byte
 *       conventions.
 *
 *   (c) **Round-key port ordering** — verifies that Map insertion order
 *       on the 22 emitted round keys matches the legacy `auxWrites`
 *       insertion order (`roundKey.0`, `roundKey.1`, …, `roundKey.21`).
 *       Mirrors the Slice 1.4 pin on AES key-expansion's 11-key insertion
 *       order; load-bearing for visualizations that iterate
 *       `frame.auxWritten.entries()` in spec order.
 *
 *   (d) **Per-primitive synthetic spec** — minimal spec exercising just
 *       `speck.key-schedule@1` + one `speck.round@1` leaf, to pin the
 *       isolated lift semantics without the algebra of all 22 rounds on
 *       top. Mirrors the Slice 1.5 per-primitive synthetic structure.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the Slice 1.4 / 1.5 dispatch tests) ─

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.6 Speck fixtures`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.6 Speck fixtures`);
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

// ─── Beaulieu et al. 2013, Table 4.1 — Speck32/64 KATs ─────────────────

const BE_KEY = "1918111009080100";
const BE_PLAINTEXT = "6574694c";
const BE_CIPHERTEXT = "a86842f2";

const LE_KEY = "0001080910111819";
const LE_PLAINTEXT = "4c697465";
const LE_CIPHERTEXT = "f24268a8";

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, Slice 1.6 Speck step types", () => {
  // ─── (a) KAT sanity floor under flag-on ──────────────────────────────

  describe("(a) Beaulieu et al. 2013 KATs under portedDispatchEnabled: true", () => {
    it("BE-paper encrypt — published ciphertext under ported", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(BE_CIPHERTEXT);
    });

    it("LE-NSA encrypt — published ciphertext under ported", () => {
      const trace = runSpec(speck32_64LeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(LE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(LE_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(LE_CIPHERTEXT);
    });

    it("BE-paper decrypt — recovers the plaintext under ported", () => {
      const trace = runSpec(speck32_64BeDecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_CIPHERTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(BE_PLAINTEXT);
    });

    it("LE-NSA decrypt — recovers the plaintext under ported", () => {
      const trace = runSpec(speck32_64LeDecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(LE_CIPHERTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(LE_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(LE_PLAINTEXT);
    });
  });

  // ─── (b) Frame-by-frame byte parity vs legacy ─────────────────────────

  describe("(b) Frame parity vs legacy dispatch — all 4 specs", () => {
    const runs: ReadonlyArray<{
      label: string;
      spec: CipherSpec;
      stateHex: string;
      keyHex: string;
    }> = [
      {
        label: "BE-paper encrypt",
        spec: speck32_64BeSpec,
        stateHex: BE_PLAINTEXT,
        keyHex: BE_KEY,
      },
      {
        label: "LE-NSA encrypt",
        spec: speck32_64LeSpec,
        stateHex: LE_PLAINTEXT,
        keyHex: LE_KEY,
      },
      {
        label: "BE-paper decrypt",
        spec: speck32_64BeDecryptSpec,
        stateHex: BE_CIPHERTEXT,
        keyHex: BE_KEY,
      },
      {
        label: "LE-NSA decrypt",
        spec: speck32_64LeDecryptSpec,
        stateHex: LE_CIPHERTEXT,
        keyHex: LE_KEY,
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

  describe("(c) speck.key-schedule@1 emits 22 round keys in insertion order", () => {
    it("aux Map iteration preserves roundKey.0 → roundKey.21 ordering under ported", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
        portedDispatchEnabled: true,
      });

      // The first frame is the key-schedule leaf — pre-rounds, the
      // entire 22-key emission happens in one frame. Pull it and inspect
      // auxWritten's key order.
      const f0 = trace.frames[0];
      if (!f0) throw new Error("expected key-schedule frame at index 0");
      expect(f0.stepType).toBe("speck.key-schedule@1");

      const keys = [...f0.auxWritten.keys()];
      expect(keys.length).toBe(22);
      const expected: string[] = [];
      for (let i = 0; i < 22; i++) expected.push(`roundKey.${i}`);
      expect(keys).toEqual(expected);

      // Cross-check: each round-key value is the expected 2-byte
      // Uint8Array (Speck32/64 wordBits=16). Ports under the legacy
      // contract layout "raw" decode back to Uint8Array — pinning that
      // the ported path didn't accidentally widen a single Speck round
      // key into a MatrixState or other variant.
      for (const k of keys) {
        const v = f0.auxWritten.get(k);
        expect(v).toBeInstanceOf(Uint8Array);
        expect((v as Uint8Array).length).toBe(2);
      }
    });
  });

  // ─── (d) Per-primitive synthetic spec ────────────────────────────────

  describe("(d) per-primitive synthetic — key-schedule + one round", () => {
    // Two-step spec: schedule expands the master key, then a single round
    // consumes roundKey.0. Pins the lift in isolation — the cipher-level
    // KAT (a) and full frame parity (b) above layer 21 more rounds on
    // top; this fixture is the smallest fixture that exercises both
    // ported leaves end-to-end.
    const spec: CipherSpec = {
      id: "test-speck-one-round@1",
      name: "Slice 1.6 — speck schedule + one round synthetic",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 8 } },
      steps: [
        {
          kind: "step",
          id: "schedule",
          type: "speck.key-schedule@1",
          params: {
            keyAuxName: "key",
            outputPrefix: "roundKey",
            rounds: 22,
            wordBits: 16,
            m: 4,
            alpha: 7,
            beta: 2,
            byteOrder: "be-paper",
          },
        },
        {
          kind: "step",
          id: "round.0",
          type: "speck.round@1",
          params: {
            roundKeyAux: "roundKey.0",
            alpha: 7,
            beta: 2,
            wordBits: 16,
            byteOrder: "be-paper",
          },
        },
      ],
    };

    it("frame-by-frame byte equality across both dispatch paths", () => {
      const legacy = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "speck schedule + one round");
    });
  });
});
