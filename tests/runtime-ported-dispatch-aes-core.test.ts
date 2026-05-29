/**
 * Slice 1.4 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the SIX AES core step types lifted
 * in Slice 1.4:
 *
 *   - `generic.byte-substitution@1` — pure state-only, originally lifted
 *     via the Phase-0 `PROJECTION_METADATA` side-map (deleted in Slice 1.9).
 *   - `generic.shift-rows@1` — pure state-only.
 *   - `generic.mix-columns@1` — pure state-only.
 *   - `generic.add-round-key@1` — aux read (one round key), originally
 *     lifted via the Phase-0 side-map (deleted in Slice 1.9).
 *   - `aes.key-expansion@1` — the FIRST one-to-many writer in the
 *     universal-port migration. Port-per-roundkey (Decision B): one
 *     output port per round key, dynamic-N sized by `params.rounds`.
 *     Exercises the PortContract.outputs FUNCTION form (Slice 1.4
 *     contract evolution, user pick over templated `keyN` lie).
 *   - `aes.key-expansion@2` — relaxed-rounds variant; shares meta +
 *     contract with @1 verbatim. Tested at the canonical AES-128 rounds
 *     count where @1 + @2 produce byte-identical traces.
 *
 * Three test surfaces:
 *
 *   (a) **FIPS-197 Appendix C KATs under `portedDispatchEnabled: true`**
 *       for all three key sizes (AES-128/192/256). KAT sanity floor — a
 *       failure here is a louder signal than a deep-equality miss across
 *       50+ frames.
 *
 *   (b) **Frame-by-frame byte parity** vs legacy dispatch. AES-192 has 13
 *       round keys (rounds=12), AES-256 has 15 (rounds=14) — two different
 *       dynamic-N port counts validated. (AES-128's parity row was removed
 *       in Slice B1 — it is byte-native with no legacy path to compare
 *       against; its frame stream is pinned in `aes-vectors.test.ts`.)
 *
 *   (c) **`aes.key-expansion@2` parity at canonical rounds** under the
 *       ported path. @2's relaxed assertion + Rcon extension produce
 *       byte-identical output to @1 when `rounds === Nk + 6`; the
 *       ported path must preserve that property.
 *
 * The Phase-0 test file (`tests/runtime-ported-dispatch.test.ts`) also
 * exercises byte-substitution + add-round-key at the AES-128 cipher
 * boundary; both pass through the same `kind: "ported"` registrations
 * the Slice 1.4 lift installed. (The original side-map fallback dispatch
 * branch was removed in Slice 1.9.)
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { AES_RCON, AES_SBOX } from "@/ciphers/aes-constants";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the Slice 1.2 dispatch tests) ───────

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.4 AES specs`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.4 AES specs`);
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

// ─── FIPS-197 / NIST AES Core fixtures ──────────────────────────────────

// FIPS-197 Appendix C.1
const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PLAINTEXT = "00112233445566778899aabbccddeeff";
const AES128_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a";

// FIPS-197 §A.2 key + NIST AES Core 192 vector
const AES192_KEY = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const AES192_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";
const AES192_CIPHERTEXT = "bd334f1d6e45f25ff712a214571fa5cc";

// FIPS-197 §A.3 key + NIST AES Core 256 vector
const AES256_KEY = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const AES256_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";
const AES256_CIPHERTEXT = "f3eed1bdb5d2a03c064b5a7e3db181f8";

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, Slice 1.4 AES core step types", () => {
  // ─── (a) FIPS-197 Appendix C KATs under flag-on ───────────────────────

  describe("(a) FIPS-197 KATs under portedDispatchEnabled: true (sanity floor)", () => {
    it("AES-128 (FIPS-197 §C.1) — published ciphertext under ported", () => {
      // Byte-native (Slice B1): bytes state in, bytes finalState out. Port-
      // native primitives, so `portedDispatchEnabled: true` is the only path.
      const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(AES128_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(AES128_CIPHERTEXT);
    });

    it("AES-192 (FIPS-197 §A.2 + NIST AES Core 192) — published ciphertext under ported", () => {
      const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
        initialState: matrixFromBytes(bytesFromHex(AES192_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES192_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("matrix4x4-bytes");
      if (trace.finalState.shape !== "matrix4x4-bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(AES192_CIPHERTEXT);
    });

    it("AES-256 (FIPS-197 §A.3 + NIST AES Core 256) — published ciphertext under ported", () => {
      // The AES-256 ported KAT also stresses the Nk>6 SubWord-only branch
      // (every word at `i % Nk === 4`) — that branch is INSIDE the legacy
      // executor, so the lift's adapter only sees its output, but a port
      // metadata bug that corrupted key-expansion's Map ordering would
      // surface as a wrong ciphertext here.
      const trace = runSpec(aes256Spec, buildDefaultRegistry(), {
        initialState: matrixFromBytes(bytesFromHex(AES256_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES256_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("matrix4x4-bytes");
      if (trace.finalState.shape !== "matrix4x4-bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(AES256_CIPHERTEXT);
    });
  });

  // ─── (b) Frame-by-frame byte parity ───────────────────────────────────

  describe("(b) frame-by-frame byte parity vs legacy dispatch", () => {
    // AES-128's legacy-vs-ported parity row was REMOVED in Slice B1: the
    // byte-native AES-128 spec has no legacy executor, so there is no legacy
    // dispatch run to compare against. The parity property only ever applied
    // to lifted-legacy steps; AES-192/256 below are still matrix/lifted-legacy
    // (they convert in Slice B1.3), so they keep exercising the dynamic-N
    // round-key port surface here. Byte-native AES-128's frame stream is
    // pinned in `aes-vectors.test.ts`.

    it("AES-192 — dynamic-N=13 round-key ports round-trip across all frames", () => {
      // AES-192's port surface has 13 round-key output ports (rounds=12,
      // 12+1 = 13). The PortContract.outputs FUNCTION form (Slice 1.4's
      // contract evolution) is exercised here at a different N than
      // AES-128's 11 — proves the function actually consults `params.
      // rounds` rather than hard-coding a constant.
      const initialState = matrixFromBytes(bytesFromHex(AES192_PLAINTEXT));
      const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(AES192_KEY)]]);
      const legacy = runSpec(aes192Spec, buildDefaultRegistry(), {
        initialState,
        initialAux,
      });
      const ported = runSpec(aes192Spec, buildDefaultRegistry(), {
        initialState,
        initialAux,
        portedDispatchEnabled: true,
      });
      expectFrameStreamsEqual(ported.frames, legacy.frames, "aes-192");
    });

    it("AES-256 — dynamic-N=15 round-key ports round-trip across all frames", () => {
      const initialState = matrixFromBytes(bytesFromHex(AES256_PLAINTEXT));
      const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(AES256_KEY)]]);
      const legacy = runSpec(aes256Spec, buildDefaultRegistry(), {
        initialState,
        initialAux,
      });
      const ported = runSpec(aes256Spec, buildDefaultRegistry(), {
        initialState,
        initialAux,
        portedDispatchEnabled: true,
      });
      expectFrameStreamsEqual(ported.frames, legacy.frames, "aes-256");
    });

    it("preserves auxWritten Map insertion order for the 11 AES-128 round keys", () => {
      // Map iteration is insertion-ordered in JS; downstream consumers
      // (round-key panel layout, narration ordering) depend on it. The
      // function-form `outputs(params)` insertion order MUST match the
      // legacy executor's `auxWrites.set(...)` insertion order (r =
      // 0..rounds). A drift here would break visual order silently.
      const initialState = matrixFromBytes(bytesFromHex(AES128_PLAINTEXT));
      const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]);
      const ported = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState,
        initialAux,
        portedDispatchEnabled: true,
      });
      const keyExpansionFrame = ported.frames.find((f) => f.stepType === "aes.key-expansion@1");
      if (!keyExpansionFrame) throw new Error("no key-expansion frame found");
      const writtenKeys = [...keyExpansionFrame.auxWritten.keys()];
      // Expected order: roundKey.0, roundKey.1, ..., roundKey.10.
      const expected: string[] = [];
      for (let r = 0; r <= 10; r++) expected.push(`roundKey.${r}`);
      expect(writtenKeys).toEqual(expected);
    });
  });

  // ─── (c) aes.key-expansion@2 parity at canonical rounds ───────────────

  describe("(c) aes.key-expansion@2 — frame parity at canonical AES-128 rounds", () => {
    // Build a one-leaf spec that exercises ONLY @2 with rounds=10 (the
    // canonical AES-128 count). At this round count @2 + @1 are byte-
    // identical (the relaxed assertion accepts but doesn't change
    // anything; the Rcon table covers all 11 indices the executor needs).
    // The ported path must preserve that property — a meta-shape drift
    // between @1 and @2 (e.g., wrong output port count) would diverge
    // here even at canonical rounds.
    const v2Spec: CipherSpec = {
      id: "aes-key-expansion-v2-canonical@1",
      name: "Slice 1.4 — key-expansion @2 at canonical AES-128 rounds",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        {
          kind: "step",
          id: "ke-v2",
          type: "aes.key-expansion@2",
          params: {
            keyAuxName: "key",
            outputPrefix: "roundKey",
            sbox: [...AES_SBOX],
            rcon: [...AES_RCON],
            rounds: 10,
          },
        },
      ],
    };

    it("emits frame-by-frame byte-equal traces vs legacy dispatch", () => {
      const initial = () => makeBytesState(new Uint8Array(0));
      const aux = (): Map<string, AuxValue> =>
        new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]);

      const legacy = runSpec(v2Spec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: aux(),
      });
      const ported = runSpec(v2Spec, buildDefaultRegistry(), {
        initialState: initial(),
        initialAux: aux(),
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "key-expansion-v2");
      // Sanity: 11 round keys present in finalAux (rounds=10 → 11 keys).
      for (let r = 0; r <= 10; r++) {
        expect(ported.finalAux.has(`roundKey.${r}`)).toBe(true);
      }
    });
  });
});
