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
 * Coverage (20 rows — was 22; aes-128 encrypt dropped in Slice B1.1,
 * aes-128 decrypt in Slice B1.2, see below):
 *
 *   AES single-block:  aes-192 / aes-256 + decrypt counterparts (§A.2 +
 *                      NIST AES Core 192, §A.3 + NIST AES Core 256). Both
 *                      aes-128 rows are byte-native (no legacy path) →
 *                      removed; the encrypt KAT + frame stream live in
 *                      aes-vectors.test.ts, the decrypt KAT in
 *                      aes-decrypt.test.ts.                         [4 rows]
 *   AES modes:         aes-128-ecb + decrypt (NIST SP 800-38A §F.1),
 *                      aes-128-cbc + decrypt (NIST SP 800-38A §F.2) [4 rows]
 *   Speck:             speck-32-64-be + decrypt, -le + decrypt
 *                      (Beaulieu et al. 2013 Table 4.1)             [4 rows]
 *   Serpent:           serpent-128/-192/-256 + decrypt counterparts
 *                      (pyserpent / Anderson-Biham-Knudsen reference)
 *                                                                   [6 rows]
 *   DES:               des + des-decrypt (FIPS 46-3 Appendix B.1)  [2 rows]
 *
 * Genuine new coverage relative to the per-cipher files: AES-128 ECB
 * encrypt + decrypt have no dedicated dispatch-parity pin today — the
 * closest existing pin (`runtime-ported-dispatch-aux-only.test.ts` block
 * (b)) covers CBC, not ECB. Every other row is also pinned in a
 * per-cipher file; the matrix file's value is the single-file gate + the
 * explicit (spec, KAT, frames-byte-equal) triple per row.
 *
 * Helper duplication intentional: per project convention every
 * `runtime-ported-dispatch-*.test.ts` file inlines its own
 * `expectStatesEqual` / `expectAuxMapsEqual` / `expectFramesEqual` /
 * `expectFrameStreamsEqual` quartet verbatim (CLAUDE.md "no abstractions
 * beyond what the task requires"). The helpers stay co-located with the
 * tests that use them.
 */

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
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
import { matrixFromBytes } from "@/core/state/matrix";
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
const buildMatrixState: StateBuilder = (hex) => matrixFromBytes(bytesFromHex(hex));
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

// AES single-block: §A.2 + NIST AES Core 192, §A.3 + NIST AES Core 256.
// The §A.* references are key schedules; the matching plaintext/ciphertext
// pairs come from the NIST CSRC "AES Core" example PDFs that replaced FIPS
// Appendix C.2 / C.3 (removed in the May 2023 upd1 of FIPS-197). The AES-128
// vectors moved out with the byte-native rows (encrypt B1.1 / decrypt B1.2).
const AES192_KEY = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const AES192_PT = "6bc1bee22e409f96e93d7e117393172a";
const AES192_CT = "bd334f1d6e45f25ff712a214571fa5cc";

const AES256_KEY = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const AES256_PT = "6bc1bee22e409f96e93d7e117393172a";
const AES256_CT = "f3eed1bdb5d2a03c064b5a7e3db181f8";

// NIST SP 800-38A §F.1 (ECB) + §F.2 (CBC) share a 4-block plaintext
// sample and a key. ECB §F.1.1 (encrypt) / §F.1.2 (decrypt); CBC §F.2.1
// (encrypt) / §F.2.2 (decrypt). The §F PT sample is concatenated 4 × 16 B
// = 64 B with no padding.
const SP38A_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const SP38A_IV = "000102030405060708090a0b0c0d0e0f";
const SP38A_PT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";
const SP38A_ECB_CT_4_BLOCKS =
  "3ad77bb40d7a3660a89ecaf32466ef97" +
  "f5d3d58503b9699de785895a96fdbaaf" +
  "43b1cd7f598ece23881b00e3ed030688" +
  "7b0c785e27e8ad3f8223207104725dd4";
const SP38A_CBC_CT_4_BLOCKS =
  "7649abac8119b246cee98e9b12e9197d" +
  "5086cb9b507219ee95db113a917678b2" +
  "73bed6b8e3c1743b7116e69e22229516" +
  "3ff1caa1681fac09120eca307586e1a7";

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

// ─── The 20-row matrix ─────────────────────────────────────────────────

const ROWS: readonly Row[] = [
  // AES single-block: 4 rows (AES-192/256 × 2 directions). The aes-128
  // ENCRYPT row was removed in Slice B1.1 and the aes-128 DECRYPT row in
  // Slice B1.2 — both are now byte-native (port-native primitives, no legacy
  // executor), so they cannot run under `portedDispatchEnabled: false` and
  // have no legacy frame stream to compare against. This matrix's contract is
  // "legacy == ported", which is vacuous for a genuinely port-native spec.
  // The byte-native AES-128 encrypt frame stream + KAT are pinned in
  // `aes-vectors.test.ts`; the decrypt KAT (bytes + ported) in
  // `aes-decrypt.test.ts`. AES-192/256 stay matrix/lifted-legacy until Slice
  // B1.3, so they remain here.
  {
    label: "aes-192 encrypt (FIPS-197 §A.2 + NIST AES Core 192)",
    spec: aes192Spec,
    stateBuilder: buildMatrixState,
    inputHex: AES192_PT,
    expectedOutputHex: AES192_CT,
    auxInputs: [["key", AES192_KEY]],
  },
  {
    label: "aes-192 decrypt (FIPS-197 §A.2 + NIST AES Core 192)",
    spec: aes192DecryptSpec,
    stateBuilder: buildMatrixState,
    inputHex: AES192_CT,
    expectedOutputHex: AES192_PT,
    auxInputs: [["key", AES192_KEY]],
  },
  {
    label: "aes-256 encrypt (FIPS-197 §A.3 + NIST AES Core 256)",
    spec: aes256Spec,
    stateBuilder: buildMatrixState,
    inputHex: AES256_PT,
    expectedOutputHex: AES256_CT,
    auxInputs: [["key", AES256_KEY]],
  },
  {
    label: "aes-256 decrypt (FIPS-197 §A.3 + NIST AES Core 256)",
    spec: aes256DecryptSpec,
    stateBuilder: buildMatrixState,
    inputHex: AES256_CT,
    expectedOutputHex: AES256_PT,
    auxInputs: [["key", AES256_KEY]],
  },
  // AES-128 ECB × 2 directions = 2 rows (the genuinely-new coverage)
  {
    label: "aes-128 ECB encrypt (NIST SP 800-38A §F.1.1)",
    spec: aes128EcbSpec,
    stateBuilder: buildBytesState,
    inputHex: SP38A_PT_4_BLOCKS,
    expectedOutputHex: SP38A_ECB_CT_4_BLOCKS,
    auxInputs: [["key", SP38A_KEY]],
  },
  {
    label: "aes-128 ECB decrypt (NIST SP 800-38A §F.1.2)",
    spec: aes128EcbDecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SP38A_ECB_CT_4_BLOCKS,
    expectedOutputHex: SP38A_PT_4_BLOCKS,
    auxInputs: [["key", SP38A_KEY]],
  },
  // AES-128 CBC × 2 directions = 2 rows
  {
    label: "aes-128 CBC encrypt (NIST SP 800-38A §F.2.1)",
    spec: aes128CbcSpec,
    stateBuilder: buildBytesState,
    inputHex: SP38A_PT_4_BLOCKS,
    expectedOutputHex: SP38A_CBC_CT_4_BLOCKS,
    auxInputs: [
      ["key", SP38A_KEY],
      ["iv", SP38A_IV],
    ],
  },
  {
    label: "aes-128 CBC decrypt (NIST SP 800-38A §F.2.2)",
    spec: aes128CbcDecryptSpec,
    stateBuilder: buildBytesState,
    inputHex: SP38A_CBC_CT_4_BLOCKS,
    expectedOutputHex: SP38A_PT_4_BLOCKS,
    auxInputs: [
      ["key", SP38A_KEY],
      ["iv", SP38A_IV],
    ],
  },
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
