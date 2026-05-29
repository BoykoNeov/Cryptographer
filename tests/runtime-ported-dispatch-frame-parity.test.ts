/**
 * Slice 1.11 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Single-file frame-parity gate across every shipped cipher spec. Each
 * `it()` row is a (spec, KAT, frames-byte-equal) triple — build the spec,
 * run twice (legacy + ported), assert the published reference under
 * `portedDispatchEnabled: true` (KAT sanity floor), then assert
 * frame-by-frame byte equality with the legacy run across the whole frame
 * stream (no filter — iterate-body and feistel-rejoin frames included).
 *
 * The per-cipher dispatch test files (-aes-core, -chaining, -speck,
 * -serpent, -des, -aux-only, -padding) keep their family-specific
 * surfaces (round-key port ordering, dynamic-N port counts, layout-driven
 * aux decode, empty-auxName sentinels, etc.). This file is the
 * consolidated single-file gate that exercises every shipped cipher
 * family end-to-end under both dispatch paths in one place — so a regression
 * in any cipher family surfaces here whether or not its family-specific
 * file also caught it.
 *
 * Coverage (16 rows — was 22; aes-128 encrypt dropped in Slice B1.1,
 * aes-128 decrypt in Slice B1.2, and all four aes-192/256 single-block rows
 * in Slice B1.3, see below):
 *
 *   AES single-block:  none. Every single-block AES (128/192/256, both
 *                      directions) is byte-native (no legacy path) →
 *                      removed; the encrypt KATs + frame streams live in
 *                      aes-vectors / aes-192-vectors / aes-256-vectors, the
 *                      AES-128 decrypt KAT in aes-decrypt.test.ts.   [0 rows]
 *   AES modes:         none. AES-128 ECB (Slice B1.4a) and CBC (B1.4b) are
 *                      byte-native (port-mode iterate, no legacy path) →
 *                      removed; their KATs live in aes-128-ecb-kat /
 *                      aes-128-cbc-kat.                              [0 rows]
 *   Speck:             speck-32-64-be + decrypt, -le + decrypt
 *                      (Beaulieu et al. 2013 Table 4.1)             [4 rows]
 *   Serpent:           serpent-128/-192/-256 + decrypt counterparts
 *                      (pyserpent / Anderson-Biham-Knudsen reference)
 *                                                                   [6 rows]
 *   DES:               des + des-decrypt (FIPS 46-3 Appendix B.1)  [2 rows]
 *
 * Every remaining row is also pinned in a per-cipher dispatch file; the
 * matrix file's value is the single-file gate + the explicit (spec, KAT,
 * frames-byte-equal) triple per row.
 *
 * Helper duplication intentional: per project convention every
 * `runtime-ported-dispatch-*.test.ts` file inlines its own
 * `expectStatesEqual` / `expectAuxMapsEqual` / `expectFramesEqual` /
 * `expectFrameStreamsEqual` quartet verbatim (CLAUDE.md "no abstractions
 * beyond what the task requires"). The helpers stay co-located with the
 * tests that use them.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the per-cipher dispatch tests) ──────

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
      throw new Error(`${label}: bitvec not exercised by Slice 1.11 matrix`);
    case "bigint":
      throw new Error(`${label}: bigint not exercised by Slice 1.11 matrix`);
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

// ─── Row encoding ────────────────────────────────────────────────────────
//
// Per-row data: the spec, how to build the initial state (matrix vs
// bytes), the input bytes, the expected output bytes (CT for encrypt rows,
// PT for decrypt rows), and the aux inputs needed to drive the run.
//
// `auxInputs` carries every aux entry the spec needs at run start — `key`
// for everything, plus `iv` for the CBC rows. The `initialAux` Map is
// rebuilt per call so legacy and ported runs each get a fresh Map (the
// runtime aliases entries into the trace's frames, so sharing the same
// Map across two runs would couple their auxRead bookkeeping).

type StateBuilder = (hex: string) => State;
const buildBytesState: StateBuilder = (hex) => makeBytesState(bytesFromHex(hex));

type Row = {
  readonly label: string;
  readonly spec: CipherSpec;
  readonly stateBuilder: StateBuilder;
  readonly inputHex: string;
  readonly expectedOutputHex: string;
  readonly auxInputs: readonly (readonly [string, string])[];
};

// ─── Reference KAT constants ─────────────────────────────────────────────

// AES single-block KATs moved out with the byte-native rows — every
// single-block AES (128 encrypt B1.1 / 128 decrypt B1.2 / 192+256 both
// directions B1.3) is now port-native with no legacy frame stream to compare
// against. Their KATs live in aes-vectors / aes-192-vectors / aes-256-vectors /
// aes-decrypt. Only the AES-128 ECB/CBC modes remain matrix here.

// AES-128 ECB + CBC KAT constants moved out with their rows — both modes
// are byte-native (Slice B1.4a/B1.4b), pinned in aes-128-ecb-kat /
// aes-128-cbc-kat.

// Speck32/64 — Beaulieu et al. 2013 Table 4.1 KAT under both byte
// conventions. BE-paper is the paper's MSB-first presentation; LE-NSA
// is the NSA reference implementation's LSB-first byte order.
const SPECK_BE_KEY = "1918111009080100";
const SPECK_BE_PT = "6574694c";
const SPECK_BE_CT = "a86842f2";
const SPECK_LE_KEY = "0001080910111819";
const SPECK_LE_PT = "4c697465";
const SPECK_LE_CT = "f24268a8";

// Serpent — pyserpent.py / Anderson-Biham-Knudsen reference. All-zero
// plaintext + one-bit key for each key size (the conventional Serpent
// reference fixture).
const SERPENT_PT = "00000000000000000000000000000000";
const SERPENT_KEY_128 = "80000000000000000000000000000000";
const SERPENT_KEY_192 = "800000000000000000000000000000000000000000000000";
const SERPENT_KEY_256 = "8000000000000000000000000000000000000000000000000000000000000000";
const SERPENT_CT_128 = "264e5481eff42a4606abda06c0bfda3d";
const SERPENT_CT_192 = "9e274ead9b737bb21efcfca548602689";
const SERPENT_CT_256 = "a223aa1288463c0e2be38ebd825616c0";

// DES — FIPS 46-3 Appendix B.1 worked example, cross-checked with
// `node:crypto` des-ecb (--openssl-legacy-provider). One vector here;
// the per-cipher DES dispatch file exercises all 3 fixture vectors.
const DES_PT = "0123456789abcdef";
const DES_KEY = "133457799bbcdff1";
const DES_CT = "85e813540f0ab405";

// ─── The 12-row matrix (Speck 4 + Serpent 6 + DES 2; all AES rows are now
//     byte-native and live in their own KAT files) ──────────────────────

const ROWS: readonly Row[] = [
  // AES single-block: 0 rows. The aes-128 ENCRYPT row was removed in Slice
  // B1.1, the aes-128 DECRYPT row in Slice B1.2, and all four aes-192/256
  // single-block rows in Slice B1.3 — every single-block AES is now byte-native
  // (port-native primitives, no legacy executor), so it cannot run under
  // `portedDispatchEnabled: false` and has no legacy frame stream to compare
  // against. This matrix's contract is "legacy == ported", which is vacuous for
  // a genuinely port-native spec. The byte-native KATs + frame streams live in
  // `aes-vectors.test.ts` (128 encrypt), `aes-decrypt.test.ts` (128 decrypt),
  // and `aes-192-vectors` / `aes-256-vectors`. The AES-128 ECB rows were
  // removed in Slice B1.4a and the CBC rows in B1.4b — both modes are now
  // byte-native (port-mode iterate + port-native body, no legacy path),
  // KAT-pinned in `aes-128-ecb-kat` / `aes-128-cbc-kat`. No AES rows remain.
  // Speck32/64 × 2 conventions × 2 directions = 4 rows
  {
    label: "speck-32-64 BE-paper encrypt (Beaulieu et al. 2013 Table 4.1)",
    spec: speck32_64BeSpec,
    stateBuilder: buildBytesState,
    inputHex: SPECK_BE_PT,
    expectedOutputHex: SPECK_BE_CT,
    auxInputs: [["key", SPECK_BE_KEY]],
  },
  {
    label: "speck-32-64 BE-paper decrypt (Beaulieu et al. 2013 Table 4.1)",
    spec: speck32_64BeDecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SPECK_BE_CT,
    expectedOutputHex: SPECK_BE_PT,
    auxInputs: [["key", SPECK_BE_KEY]],
  },
  {
    label: "speck-32-64 LE-NSA encrypt (Beaulieu et al. 2013 Table 4.1)",
    spec: speck32_64LeSpec,
    stateBuilder: buildBytesState,
    inputHex: SPECK_LE_PT,
    expectedOutputHex: SPECK_LE_CT,
    auxInputs: [["key", SPECK_LE_KEY]],
  },
  {
    label: "speck-32-64 LE-NSA decrypt (Beaulieu et al. 2013 Table 4.1)",
    spec: speck32_64LeDecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SPECK_LE_CT,
    expectedOutputHex: SPECK_LE_PT,
    auxInputs: [["key", SPECK_LE_KEY]],
  },
  // Serpent × 3 key sizes × 2 directions = 6 rows
  {
    label: "serpent-128 encrypt (pyserpent reference)",
    spec: serpent128Spec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_PT,
    expectedOutputHex: SERPENT_CT_128,
    auxInputs: [["key", SERPENT_KEY_128]],
  },
  {
    label: "serpent-128 decrypt (pyserpent reference)",
    spec: serpent128DecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_CT_128,
    expectedOutputHex: SERPENT_PT,
    auxInputs: [["key", SERPENT_KEY_128]],
  },
  {
    label: "serpent-192 encrypt (pyserpent reference)",
    spec: serpent192Spec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_PT,
    expectedOutputHex: SERPENT_CT_192,
    auxInputs: [["key", SERPENT_KEY_192]],
  },
  {
    label: "serpent-192 decrypt (pyserpent reference)",
    spec: serpent192DecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_CT_192,
    expectedOutputHex: SERPENT_PT,
    auxInputs: [["key", SERPENT_KEY_192]],
  },
  {
    label: "serpent-256 encrypt (pyserpent reference)",
    spec: serpent256Spec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_PT,
    expectedOutputHex: SERPENT_CT_256,
    auxInputs: [["key", SERPENT_KEY_256]],
  },
  {
    label: "serpent-256 decrypt (pyserpent reference)",
    spec: serpent256DecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SERPENT_CT_256,
    expectedOutputHex: SERPENT_PT,
    auxInputs: [["key", SERPENT_KEY_256]],
  },
  // DES × 2 directions = 2 rows
  {
    label: "des encrypt (FIPS 46-3 Appendix B.1)",
    spec: desSpec,
    stateBuilder: buildBytesState,
    inputHex: DES_PT,
    expectedOutputHex: DES_CT,
    auxInputs: [["key", DES_KEY]],
  },
  {
    label: "des decrypt (FIPS 46-3 Appendix B.1)",
    spec: desDecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: DES_CT,
    expectedOutputHex: DES_PT,
    auxInputs: [["key", DES_KEY]],
  },
];

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — Slice 1.11 frame-parity matrix (all shipped specs)", () => {
  for (const row of ROWS) {
    it(`${row.label} — KAT under ported + full frame stream byte-equal vs legacy`, () => {
      const buildAux = (): Map<string, AuxValue> =>
        new Map<string, AuxValue>(row.auxInputs.map(([name, hex]) => [name, bytesFromHex(hex)]));

      // Run twice — fresh state + fresh aux Map per run so the two paths
      // don't share AuxValue references (the runtime aliases aux entries
      // into the trace's frames; sharing one Map across both runs would
      // couple their auxRead bookkeeping).
      const legacy = runSpec(row.spec, buildDefaultRegistry(), {
        initialState: row.stateBuilder(row.inputHex),
        initialAux: buildAux(),
      });
      const ported = runSpec(row.spec, buildDefaultRegistry(), {
        initialState: row.stateBuilder(row.inputHex),
        initialAux: buildAux(),
        portedDispatchEnabled: true,
      });

      // (1) KAT sanity floor under flag-on first — a single-byte miss
      // here is a louder, easier-to-diagnose signal than a deep-equality
      // miss buried inside hundreds of frames.
      expect(ported.finalState.shape, `${row.label}: ported finalState.shape`).toBe(
        legacy.finalState.shape,
      );
      // Bytes-only state shapes in this matrix (bytes / matrix4x4-bytes);
      // both expose `.bytes: Uint8Array`. Narrowing assertion is needed
      // to keep TS happy under `noUncheckedIndexedAccess` + discriminated
      // union.
      if (ported.finalState.shape !== "bytes" && ported.finalState.shape !== "matrix4x4-bytes") {
        throw new Error(
          `${row.label}: unexpected ported finalState shape ${ported.finalState.shape}`,
        );
      }
      expect(hexFromBytes(ported.finalState.bytes), `${row.label}: ported finalState bytes`).toBe(
        row.expectedOutputHex,
      );

      // (2) Full frame-stream byte equality vs legacy — no filter.
      // Iterate-body frames and feistel-rejoin frames included; both
      // classes are byte-identical between paths per invariants 1+2 of
      // the Phase 1 plan.
      expectFrameStreamsEqual(ported.frames, legacy.frames, row.label);
    });
  }
});
