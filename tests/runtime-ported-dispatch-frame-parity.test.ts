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
 * Coverage (2 rows — was 22; aes-128 encrypt dropped in Slice B1.1,
 * aes-128 decrypt in Slice B1.2, all four aes-192/256 single-block rows
 * in Slice B1.3, AES ECB/CBC in B1.4, the four Speck rows in Slice B2, and
 * the six Serpent rows in Slice B3, see below):
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
 *   Speck:             none. The two ARX rounds are byte-native (Slice B2,
 *                      no legacy path) → removed; the KATs + frame streams
 *                      live in speck-32-64-vectors / -decrypt and
 *                      runtime-ported-dispatch-speck.                [0 rows]
 *   Serpent:           none. The five round-body executors are byte-native
 *                      (Slice B3, no legacy path) → removed; the KATs + a
 *                      golden frame-stream checksum live in serpent-vectors /
 *                      serpent-roundtrip and
 *                      runtime-ported-dispatch-serpent.              [0 rows]
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
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the per-cipher dispatch tests) ──────

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

// Speck32/64 rows were removed in Slice B2 — the two ARX rounds are now
// port-native (no legacy executor), so the spec can't run under
// `portedDispatchEnabled: false` and has no legacy frame stream to compare
// against. KATs + frame streams live in speck-32-64-vectors / -decrypt and
// runtime-ported-dispatch-speck.

// Serpent rows were removed in Slice B3 — the five round-body executors are
// now port-native (no legacy executor), so the specs can't run under
// `portedDispatchEnabled: false` and have no legacy frame stream to compare
// against. KATs + the golden frame-stream checksum live in
// serpent-vectors / serpent-roundtrip and runtime-ported-dispatch-serpent.

// Toy Feistel — the LAST lifted-legacy-AND-port-runnable construct after
// the cipher migration completed (B4 made DES port-native). `feistel.toy-
// add-k@1` keeps both a `legacy` executor (runs under flag-off) and the
// ported path (runs under flag-on), and `FEISTEL_TOY_SPEC` wraps it in a
// `feistel-round`, so this single row still exercises the matrix's reason
// for existing: invariant 2 of the Phase 1 plan — lift-adapter frames AND
// the runtime's feistel-round / rejoin synthesis are byte-identical across
// dispatch paths. KAT hand-derived in `feistel-toy.ts` (FEISTEL_TOY_KAT).
const TOY_PT = "01020304";
const TOY_CT = "343d1517";

// ─── The matrix (toy Feistel only) ──────────────────────────────────────
// All shipped cipher/hash specs are now byte-native port-native and have no
// legacy frame stream to compare against — their KATs + golden frame
// streams live in the per-cipher KAT files (aes-*-vectors, speck-*-vectors,
// serpent-vectors/roundtrip, des-vectors/des-decrypt + the per-leaf parity
// nets). AES rows were removed across B1.1–B1.4b, Speck in B2, Serpent in
// B3, and DES in B4. The toy Feistel fixture is the only surviving spec that
// runs under BOTH dispatch flags, so it carries the matrix's invariant-2
// check forward.

const ROWS: readonly Row[] = [
  {
    label: "toy feistel (lift-adapter + feistel-round synthesis frame parity)",
    spec: FEISTEL_TOY_SPEC,
    stateBuilder: buildBytesState,
    inputHex: TOY_PT,
    expectedOutputHex: TOY_CT,
    auxInputs: [],
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
      // Both surviving state shapes (bytes / matrix4x4-bytes) expose
      // `.bytes: Uint8Array`, so the union accessor below type-checks
      // without a narrowing guard.
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
