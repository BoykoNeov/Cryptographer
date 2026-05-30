/**
 * Slice 1.8 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Pins frame-byte equivalence between `portedDispatchEnabled: true` and
 * `portedDispatchEnabled: false` for the SEVEN DES step types lifted in
 * Slice 1.8, plus the `feistel.toy-add-k@1` test fixture lifted in the
 * same commit:
 *
 *   - `des.key-schedule@1` — the FOURTH one-to-many writer in the
 *     universal-port migration (after `aes.key-expansion@1` in Slice 1.4,
 *     `speck.key-schedule@1` in Slice 1.6, and `serpent.key-expansion@1`
 *     in Slice 1.7). **16 output ports** (`key0` … `key15`), fixed
 *     across DES (no variant — 64-bit master key always). Function-form
 *     contract for uniformity with the precedents. Aux-only — no state
 *     ports; lift adapter creates a sentinel state and the runtime
 *     preserves the caller's `bytes`-shape across the call.
 *   - `des.xor-with-K@1` — state-bearing single-aux-read step. Direct
 *     analog of `serpent.add-round-key@1` (Slice 1.7) but with 6-byte
 *     state + 6-byte aux read (R-side, 48 bits) instead of 16-byte.
 *   - `des.initial-permutation@1` / `des.final-permutation@1` /
 *     `des.p-permutation@1` — three pure bytes→bytes no-aux transforms
 *     at FIXED 8/8/4-byte sizes.
 *   - `des.expand-R@1` (4 → 6) / `des.s-boxes@1` (6 → 4) — the FIRST
 *     two lifted steps in any slice where `input.byteLength !==
 *     output.byteLength` on the state port. Both share `stateLayout:
 *     "bytes"` and the `bytes`-shape codec in `port-projection.ts`
 *     copies bytes without a length check, so the asymmetric declaration
 *     works without runtime contract changes. The executors' own length
 *     assertions remain the runtime gate on wiring errors.
 *
 * Plus `feistel.toy-add-k@1` — test-fixture step type, length-polymorphic
 * bytes→bytes (byteLength absent on both state ports). Exercised here
 * via the existing `FEISTEL_TOY_SPEC` (which is the test infrastructure
 * the parent plan's invariant 2 leans on: "body leaves of feistel-round
 * containers run ported, rejoin frame stays as runtime synthesis").
 *
 * Four test surfaces (mirror the Slice 1.6/1.7 dispatch test structure):
 *
 *   (a) **Reference KATs under flag-on** for DES encrypt + decrypt
 *       against all three fixture vectors in `tests/fixtures/des-kat.json`
 *       (FIPS Appendix B + all-zeros + all-ones — `node:crypto`
 *       cross-checked per [[feedback-crypto-verification]]). KAT sanity
 *       floor — a failure here is a louder signal than a deep-equality
 *       miss across the dozens of frames per cipher.
 *
 *   (b) **Frame-by-frame byte parity** vs legacy dispatch for all six
 *       (cipher × direction) combinations: DES encrypt + decrypt × 3
 *       vectors. **Critical for Slice 1.8** because DES is the first
 *       slice where body leaves live inside a `feistel-round` container.
 *       The same parity helper that pinned AES/Speck/Serpent here pins
 *       both classes of frame: the body-leaf ported-vs-legacy parity AND
 *       the rejoin frame's byte-identity (which is free per invariant 2
 *       — the runtime synthesizes it from Uint8Array track outputs
 *       independent of dispatch flag).
 *
 *   (c) **Round-key port ordering** — verifies that Map insertion order
 *       on the 16 emitted round keys matches the legacy `auxWrites`
 *       insertion order (`roundKey.0`, `roundKey.1`, …, `roundKey.15`).
 *       Mirrors the Slice 1.4/1.6/1.7 pins on AES/Speck/Serpent key-
 *       expansion insertion order. Load-bearing for visualizations that
 *       iterate `frame.auxWritten.entries()` in spec order.
 *
 *   (d) **Per-primitive synthetic spec** — minimal spec exercising just
 *       `des.key-schedule@1` + one `des.xor-with-K@1` leaf, to pin the
 *       isolated lift semantics without the 16 rounds + IP/FP/E/S/P
 *       layered on top. Mirrors the Slice 1.5/1.6/1.7 per-primitive
 *       synthetic structure.
 *
 *   (e) **Toy Feistel fixture lift** — runs `FEISTEL_TOY_SPEC` under
 *       both dispatch paths and pins frame-by-frame byte equality. This
 *       is the most isolated possible exercise of "body leaves inside a
 *       `feistel-round` run ported, rejoin frame stays byte-identical."
 *       If a future change to the runtime breaks Feistel body dispatch,
 *       this fixture catches it before any DES-side noise enters.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { FEISTEL_TOY_KAT, FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Frame-equality helpers (mirror the Slice 1.7 dispatch tests) ──────

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

// ─── DES KAT fixture (shared with tests/des-vectors.test.ts) ───────────

type FixtureVector = { readonly pt: string; readonly key: string; readonly ct: string };
type Fixture = { readonly vectors: readonly FixtureVector[] };

const FIXTURE_PATH = join(process.cwd(), "tests", "fixtures", "des-kat.json");
const RAW_FIXTURE = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Fixture;

// Pull just the (pt, key, ct) triples for the dispatch-parity tests; the
// per-round detail in the fixture is consumed by `tests/des-vectors.test.ts`
// and not needed here.
const DES_KATS: readonly FixtureVector[] = RAW_FIXTURE.vectors.map((v) => ({
  pt: v.pt,
  key: v.key,
  ct: v.ct,
}));

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, Slice 1.8 DES + feistel-toy step types", () => {
  // ─── (a) KAT sanity floor under flag-on ──────────────────────────────

  describe("(a) Reference KATs under portedDispatchEnabled: true", () => {
    for (const vec of DES_KATS) {
      it(`DES encrypt — PT=${vec.pt} K=${vec.key} → CT=${vec.ct}`, () => {
        const trace = runSpec(desSpec, buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(vec.pt)),
          initialAux: new Map<string, AuxValue>([["key", bytesFromHex(vec.key)]]),
          portedDispatchEnabled: true,
        });
        expect(trace.finalState.shape).toBe("bytes");
        if (trace.finalState.shape !== "bytes") return;
        expect(hexFromBytes(trace.finalState.bytes)).toBe(vec.ct);
      });
    }

    for (const vec of DES_KATS) {
      it(`DES decrypt — CT=${vec.ct} K=${vec.key} → PT=${vec.pt}`, () => {
        const trace = runSpec(desDecryptSpec, buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(vec.ct)),
          initialAux: new Map<string, AuxValue>([["key", bytesFromHex(vec.key)]]),
          portedDispatchEnabled: true,
        });
        expect(trace.finalState.shape).toBe("bytes");
        if (trace.finalState.shape !== "bytes") return;
        expect(hexFromBytes(trace.finalState.bytes)).toBe(vec.pt);
      });
    }
  });

  // ─── (b) Frame parity vs legacy — REMOVED in B4 ──────────────────────
  // DES is now port-native (universal-port Phase 4d): the F-function leaves
  // demand `portInputs` and have no legacy executor, so a flag-OFF run
  // throws — there is no legacy frame stream to compare against. The B2/B3
  // precedent (Speck/Serpent removed their parity rows for the same reason).
  // The per-leaf parity net against the FIPS oracle fixture lives in
  // `des-vectors.test.ts` (every IP/E/X/S/P/split/fxor/recombine output
  // asserted across all 16 rounds) — the real replacement for frame parity.

  // ─── (c) Round-key port insertion order ──────────────────────────────

  describe("(c) des.key-schedule@1 emits 16 round keys in insertion order", () => {
    it("aux Map iteration preserves roundKey.0 → roundKey.15 ordering under ported", () => {
      const vec = DES_KATS[0];
      if (!vec) throw new Error("expected at least one DES KAT vector");

      const trace = runSpec(desSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(vec.pt)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(vec.key)]]),
        portedDispatchEnabled: true,
      });

      // Find the key-schedule frame. Locating by stepType keeps the test
      // robust to any future spec-builder additions ahead of the schedule.
      const ksFrame = trace.frames.find((f) => f.stepType === "des.key-schedule@1");
      if (!ksFrame) throw new Error("expected one des.key-schedule@1 frame");

      const keys = [...ksFrame.auxWritten.keys()];
      expect(keys.length).toBe(16);
      const expected: string[] = [];
      for (let i = 0; i < 16; i++) expected.push(`roundKey.${i}`);
      expect(keys).toEqual(expected);

      // Cross-check: each round-key value is a 6-byte Uint8Array (DES
      // round keys are always 48 bits). Pins that the ported path didn't
      // accidentally widen a single round key into a MatrixState or other
      // variant — layout "raw" on the output ports must decode back to
      // Uint8Array.
      for (const k of keys) {
        const v = ksFrame.auxWritten.get(k);
        expect(v).toBeInstanceOf(Uint8Array);
        expect((v as Uint8Array).length).toBe(6);
      }
    });
  });

  // ─── (d) Per-primitive synthetic spec — REMOVED in B4 ────────────────
  // The old (d) wired a bare `des.xor-with-K@1` leaf on a state thread and
  // compared lift-vs-ported frames. Post-B4 that leaf is port-native (no
  // legacy path; reads `state` via portInputs), so the lift-comparison is
  // gone and a thread-fed leaf no longer runs. The isolated native behavior
  // of every DES leaf — including xor-K's 6-byte aux read recorded in
  // `frame.auxRead` — is pinned per-round against the FIPS oracle in
  // `des-vectors.test.ts`.

  // ─── (e) feistel.toy-add-k@1 lift via FEISTEL_TOY_SPEC ───────────────

  describe("(e) feistel.toy-add-k@1 inside a feistel-round container", () => {
    // Re-use the existing toy spec from `feistel-primitive.test.ts`'s
    // surface — a 2-round Feistel with one `feistel.toy-add-k@1` leaf in
    // each round's R track and an empty L track. This is the most
    // isolated possible exercise of "body leaves inside a `feistel-round`
    // run ported, rejoin frame stays byte-identical between paths" —
    // which is the parent plan's invariant 2 for Slice 1.8. A future
    // runtime change that broke Feistel body dispatch would catch here
    // before any DES-side noise enters.
    it("frame-by-frame byte equality across both dispatch paths", () => {
      const legacy = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
      });
      const ported = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
        portedDispatchEnabled: true,
      });

      expectFrameStreamsEqual(ported.frames, legacy.frames, "feistel-toy");
      // Cross-check: both paths produce the expected ciphertext from
      // the hand-computed KAT — guards against the "frames match each
      // other but both are wrong" failure mode.
      expect(legacy.finalState.shape).toBe("bytes");
      expect(ported.finalState.shape).toBe("bytes");
      if (legacy.finalState.shape !== "bytes" || ported.finalState.shape !== "bytes") return;
      expect(hexFromBytes(legacy.finalState.bytes)).toBe(hexFromBytes(FEISTEL_TOY_KAT.ciphertext));
      expect(hexFromBytes(ported.finalState.bytes)).toBe(hexFromBytes(FEISTEL_TOY_KAT.ciphertext));
    });
  });
});
