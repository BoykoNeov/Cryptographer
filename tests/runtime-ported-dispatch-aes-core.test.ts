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
 *   (b) **Dynamic-N round-key port surface** under ported dispatch. Every
 *       single-block AES is byte-native (Slices B1.1–B1.3) with no legacy
 *       path, so the old frame-parity-vs-legacy rows are gone; what they
 *       uniquely validated — `aes.key-expansion@1`'s function-form output
 *       contract sizing its round-key ports to `params.rounds` — survives as
 *       a ported-only check of the emitted round keys at N=11/13/15
 *       (AES-128/192/256). Frame streams are pinned in the *-vectors files.
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
      // Byte-native (Slice B1.3): bytes state in, bytes finalState out.
      const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(AES192_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES192_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(AES192_CIPHERTEXT);
    });

    it("AES-256 (FIPS-197 §A.3 + NIST AES Core 256) — published ciphertext under ported", () => {
      // The AES-256 ported KAT also stresses the Nk>6 SubWord-only branch
      // (every word at `i % Nk === 4`) inside `aes.key-expansion@1`; a port
      // metadata bug that corrupted key-expansion's round-key Map ordering
      // would surface as a wrong ciphertext here. Byte-native (Slice B1.3):
      // bytes state in, bytes finalState out.
      const trace = runSpec(aes256Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(AES256_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES256_KEY)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(AES256_CIPHERTEXT);
    });
  });

  // ─── (b) Frame-by-frame byte parity ───────────────────────────────────

  describe("(b) dynamic-N round-key port surface under ported dispatch", () => {
    // The legacy-vs-ported frame-parity rows were REMOVED across Slices B1.1
    // (AES-128 encrypt), B1.2 (AES-128 decrypt), and B1.3 (AES-192/256): every
    // single-block AES spec is byte-native with no legacy executor, so there is
    // no legacy dispatch run to compare against. The parity property only ever
    // applied to lifted-legacy steps. What these rows uniquely validated — the
    // `aes.key-expansion@1` PortContract.outputs FUNCTION form sizing its
    // round-key output ports to `params.rounds` at N ≠ 11 — survives as a
    // ported-only check: the number + insertion order of the round keys the
    // function emits, at N=13 (AES-192) and N=15 (AES-256). The end-to-end KATs
    // in block (a) already prove those keys are wired correctly to AddRoundKey;
    // these pin the function actually consults `params.rounds` rather than
    // hard-coding AES-128's 11. (Byte-native frame streams are pinned in
    // `aes-vectors` / `aes-192-vectors` / `aes-256-vectors`.)

    // Map iteration is insertion-ordered in JS; downstream consumers (round-key
    // panel layout, narration ordering) depend on `roundKey.0..N` order. The
    // function-form `outputs(params)` insertion order MUST be ascending.
    const expectRoundKeyOrder = (spec: CipherSpec, key: string, rounds: number, label: string) => {
      // A full 16-byte block is required: byte-native AES reads its plaintext
      // from `$input`, and the initial AddRoundKey xor's the round key into it
      // (a 0-length state would length-mismatch the 16-byte key). The actual
      // plaintext value is irrelevant — we only inspect the key-expansion
      // frame's auxWritten, which doesn't depend on the plaintext.
      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(16)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(key)]]),
        portedDispatchEnabled: true,
      });
      const keyExpansionFrame = ported.frames.find((f) => f.stepType === "aes.key-expansion@1");
      if (!keyExpansionFrame) throw new Error(`${label}: no key-expansion frame found`);
      const writtenKeys = [...keyExpansionFrame.auxWritten.keys()];
      const expected: string[] = [];
      for (let r = 0; r <= rounds; r++) expected.push(`roundKey.${r}`);
      expect(writtenKeys, label).toEqual(expected);
    };

    it("AES-192 emits 13 round keys (rounds=12) in ascending order under ported", () => {
      expectRoundKeyOrder(aes192Spec, AES192_KEY, 12, "aes-192");
    });

    it("AES-256 emits 15 round keys (rounds=14) in ascending order under ported", () => {
      expectRoundKeyOrder(aes256Spec, AES256_KEY, 14, "aes-256");
    });

    it("AES-128 emits 11 round keys (rounds=10) in ascending order under ported", () => {
      expectRoundKeyOrder(aes128Spec, AES128_KEY, 10, "aes-128");
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
