/**
 * Slice 2.0c — toy fixture for the
 * `for-each-subgraph-with-history` spec node kind.
 *
 * The slice introduces a per-iteration lookback primitive — body reads
 * named priors from a runtime-maintained history buffer via
 * `aux["prior-{N}"]`. The forcing function is SHA-256's message schedule
 * (W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}); this toy
 * validates the runtime contract on a synthetic XOR-shape body before
 * SHA-256 specifics land.
 *
 * Contract design picks baked into these tests
 * (per `docs/plans/universal-port-phase-2-slices.md` Slice 2.0c):
 *
 *  - **Q1 (lookback declaration) = Declarative offsets.** Body declares
 *    `lookbackOffsets: [N1, N2, ...]`; runtime exposes `aux["prior-{N}"]`
 *    per offset. Memory bounded by max offset; data dependency explicit
 *    in spec.
 *  - **Q2 (packaging) = Sibling node kind.** New `StepNode` discriminant
 *    `for-each-subgraph-with-history` rather than a third mode on
 *    `for-each-subgraph`. The 2-mode invariant block on FES stays
 *    untouched; this kind's invariants live local in its own walker.
 *  - **Q3 (reset scope) = Per-outer reset.** History buffer is a local
 *    variable in the runtime walker — each invocation freshly seeds
 *    from parent state. The aux snapshot+restore protocol preserves
 *    any pre-existing `prior-{N}` keys across the node's lifetime.
 *
 * Pass/fail gate:
 *  - 8-iter XOR-shape toy: 8 frames emit with `:r0`..`:r7` suffixes;
 *    aux["prior-1"] / aux["prior-2"] populated per iteration; body
 *    starts each iteration with zero state of entry length; body exit
 *    state appended to history; final exit state = full concatenated
 *    history (seeds + iteration outputs).
 *  - Composed suffix under `iterate`: 2-block × 3-iter case produces
 *    `:b{i}:r{j}` per the type-order rule (`:t < :b < :r`).
 *  - Throws cover every load-bearing contract invariant — empty
 *    lookbackOffsets, non-positive offset, non-integer offset, bad
 *    entry length, insufficient seeds, non-bytes parent state, length
 *    not divisible, body exit wrong length / wrong shape.
 *  - Aux snapshot+restore preserves prior aux state across the node
 *    (absent stays absent; present stays present-with-original-value).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { canonicalStepId } from "@/core/step-id";
import type { AuxValue, BytesState, CipherSpec, StepDefinition } from "@/core/types";
import { describe, expect, it } from "vitest";

// Test-local body leaf: reads aux["prior-1"] and aux["prior-2"], XORs them,
// writes the result as the iteration's bytes-state output. Built test-
// local because no shipped step type combines bytes-shape state with
// 1-byte arithmetic (the existing `xor-aux-into-state@1` is matrix4x4-
// bytes only). Keeps the toy hand-verifiable at 1-byte entries.
const xorPriorsIntoState: StepDefinition = {
  executor: (state, _params, ctx) => {
    if (state.shape !== "bytes") {
      throw new Error("xorPriorsIntoState expects bytes state");
    }
    const prior1 = ctx.aux.get("prior-1");
    const prior2 = ctx.aux.get("prior-2");
    if (!(prior1 instanceof Uint8Array) || !(prior2 instanceof Uint8Array)) {
      throw new Error("xorPriorsIntoState requires aux['prior-1'] + aux['prior-2'] as Uint8Array");
    }
    if (prior1.length !== state.bytes.length || prior2.length !== state.bytes.length) {
      throw new Error(
        `xorPriorsIntoState length mismatch: state=${state.bytes.length} prior-1=${prior1.length} prior-2=${prior2.length}`,
      );
    }
    const out = new Uint8Array(state.bytes.length);
    for (let i = 0; i < out.length; i++) {
      out[i] = (prior1[i] ?? 0) ^ (prior2[i] ?? 0);
    }
    const next: BytesState = { shape: "bytes", bytes: out };
    return { state: next, auxReads: ["prior-1", "prior-2"] };
  },
};

// (The "body exits with wrong shape" throw test was retired in Phase 5
// Slice 5.1 (2026-05-30) with the MatrixState shape — with `bytes` the only
// State shape there is no wrong-shape state to return. The wrong-byte-length
// invariant below still exercises the body-exit shape guard.)

// Test-local body leaf for the "body exits with wrong byte length" throw
// test. Returns a bytes state of length 2 regardless of input — under
// historyEntryByteLength=1 this trips the length invariant.
const returnTwoBytes: StepDefinition = {
  executor: () => {
    const next: BytesState = { shape: "bytes", bytes: new Uint8Array([0xff, 0xee]) };
    return { state: next };
  },
};

// Test-local body leaf that asserts a named aux key is absent. Used by
// the aux-cleanup test to verify snapshot+restore deleted runtime-set
// keys after the FES-with-history node exits.
const assertAuxAbsent: StepDefinition = {
  executor: (state, params, ctx) => {
    const key = (params as unknown as { readonly key: string }).key;
    if (ctx.aux.has(key)) {
      throw new Error(
        `assertAuxAbsent: aux["${key}"] is present but expected absent (FES-with-history cleanup failed)`,
      );
    }
    return { state };
  },
};

// Test-local body leaf that asserts a named aux key has a specific byte
// value. Used by the aux-restore test to verify pre-existing aux state
// was restored verbatim after the FES-with-history node exits.
const assertAuxEquals: StepDefinition = {
  executor: (state, params, ctx) => {
    const key = (params as unknown as { readonly key: string }).key;
    const expectedHex = (params as unknown as { readonly expectedHex: string }).expectedHex;
    const got = ctx.aux.get(key);
    if (!(got instanceof Uint8Array)) {
      throw new Error(`assertAuxEquals: aux["${key}"] is not a Uint8Array (got ${typeof got})`);
    }
    const gotHex = Array.from(got)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    if (gotHex !== expectedHex) {
      throw new Error(`assertAuxEquals: aux["${key}"]=${gotHex} expected ${expectedHex}`);
    }
    return { state, auxReads: [key] };
  },
};

const buildRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("test.xor-priors-into-state@1", xorPriorsIntoState);
  r.register("test.return-two-bytes@1", returnTwoBytes);
  r.register("test.assert-aux-absent@1", assertAuxAbsent);
  r.register("test.assert-aux-equals@1", assertAuxEquals);
  return r;
};

// ─── Happy path: 8-iter XOR-shape lookback ────────────────────────────────
//
// Seeds [0x05, 0x03] at historyEntryByteLength=1. Body XORs prior-1 +
// prior-2 per iteration. The sequence cycles with period 3 because XOR
// is involutive: `a, b, a^b, b^(a^b)=a, (a^b)^a=b, a^b, …`.
//
// Expected full history after 8 iterations (10 entries total):
//   t=0 (absIdx=2): prior-1=hist[1]=0x03, prior-2=hist[0]=0x05 → 0x06
//   t=1 (absIdx=3): prior-1=hist[2]=0x06, prior-2=hist[1]=0x03 → 0x05
//   t=2 (absIdx=4): prior-1=hist[3]=0x05, prior-2=hist[2]=0x06 → 0x03
//   t=3 (absIdx=5): prior-1=hist[4]=0x03, prior-2=hist[3]=0x05 → 0x06
//   t=4 (absIdx=6): prior-1=hist[5]=0x06, prior-2=hist[4]=0x03 → 0x05
//   t=5 (absIdx=7): prior-1=hist[6]=0x05, prior-2=hist[5]=0x06 → 0x03
//   t=6 (absIdx=8): prior-1=hist[7]=0x03, prior-2=hist[6]=0x05 → 0x06
//   t=7 (absIdx=9): prior-1=hist[8]=0x06, prior-2=hist[7]=0x03 → 0x05
// Final state.bytes = [0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05].

const xorShapeSpec: CipherSpec = {
  id: "test-fes-history-inner@1",
  name: "8-iter XOR-shape lookback",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "for-each-subgraph-with-history",
      id: "loop",
      label: "8x xor priors",
      iterationCount: 8,
      lookbackOffsets: [1, 2],
      historyEntryByteLength: 1,
      children: [
        {
          kind: "step",
          id: "xor-priors",
          type: "test.xor-priors-into-state@1",
          params: {},
        },
      ],
    },
  ],
};

describe("runtime — for-each-subgraph-with-history node (Slice 2.0c)", () => {
  it("8-iter XOR-shape lookback: emits :r{i}-suffixed frames + correct final history", () => {
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array([0x05, 0x03]) };
    const trace = runSpec(xorShapeSpec, buildRegistry(), { initialState: initial });

    // 8 iterations × 1 body leaf = 8 frames.
    expect(trace.frames).toHaveLength(8);

    // StepId suffixes pin Slice 2.0c's `:r{i}` convention (same as
    // for-each-subgraph state-thread mode).
    expect(trace.frames.map((f) => f.stepId)).toEqual([
      "xor-priors:r0",
      "xor-priors:r1",
      "xor-priors:r2",
      "xor-priors:r3",
      "xor-priors:r4",
      "xor-priors:r5",
      "xor-priors:r6",
      "xor-priors:r7",
    ]);

    // Canonical stepId strips back to the spec-leaf id — same as for
    // every other iteration kind, so `setTrace`'s frame-preservation
    // across re-runs continues to work.
    for (const f of trace.frames) {
      expect(canonicalStepId(f.stepId)).toBe("xor-priors");
    }

    // Body starts each iteration with zero state of entryLen (1 byte).
    // The aux reads + XOR are what produce the iteration's output.
    for (const f of trace.frames) {
      if (f.stateBefore.shape !== "bytes") throw new Error("expected bytes stateBefore");
      expect(Array.from(f.stateBefore.bytes)).toEqual([0x00]);
    }

    // Per-iteration auxRead binding contains "prior-1" + "prior-2" in
    // executor-declared order. (The runtime's frame-builder records the
    // executor's `auxReads` list verbatim.)
    for (const f of trace.frames) {
      expect(f.auxRead.has("prior-1")).toBe(true);
      expect(f.auxRead.has("prior-2")).toBe(true);
    }

    // Iteration outputs (XOR of declared priors per iteration) per the
    // hand-computed cycle above.
    const expectedOutputs = [0x06, 0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05];
    for (let i = 0; i < trace.frames.length; i++) {
      const f = trace.frames[i];
      if (!f || f.stateAfter.shape !== "bytes") throw new Error(`frame ${i}`);
      expect(Array.from(f.stateAfter.bytes)).toEqual([expectedOutputs[i]]);
    }

    // Final state = seeds concatenated with all iteration outputs.
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05,
    ]);
  });

  it("iterationCount=0 emits zero body frames; exit state = seeds verbatim", () => {
    const zeroSpec: CipherSpec = {
      ...xorShapeSpec,
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "loop",
          iterationCount: 0,
          lookbackOffsets: [1, 2],
          historyEntryByteLength: 1,
          children: [
            { kind: "step", id: "xor-priors", type: "test.xor-priors-into-state@1", params: {} },
          ],
        },
      ],
    };
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array([0x05, 0x03]) };
    const trace = runSpec(zeroSpec, buildRegistry(), { initialState: initial });
    expect(trace.frames).toHaveLength(0);
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0x05, 0x03]);
  });

  it("iterationCount.fromParam throws with a clear Slice-2.0c-deferred error", () => {
    const paramSpec: CipherSpec = {
      ...xorShapeSpec,
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "loop",
          iterationCount: { fromParam: "rounds" },
          lookbackOffsets: [1, 2],
          historyEntryByteLength: 1,
          children: [
            { kind: "step", id: "xor-priors", type: "test.xor-priors-into-state@1", params: {} },
          ],
        },
      ],
    };
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array([0x05, 0x03]) };
    expect(() => runSpec(paramSpec, buildRegistry(), { initialState: initial })).toThrow(
      /Slice 2\.0c/,
    );
  });

  // ─── Composed suffix under iterate: 2-block × 3-iter case ──────────────
  //
  // Pins the type-order rule `:t < :b < :r` when an outer `iterate`
  // wraps a for-each-subgraph-with-history. Outer iterate seeds each
  // block from an aux array per its existing contract; inner FES-with-
  // history runs 3 iterations per block. Composition rule: outer block
  // index appears as `:b{i}` and inner round index as `:r{j}`, in that
  // order regardless of nesting depth (because `:b` is type-order-before
  // `:r`). See `core/step-id.ts`.

  it("composed suffix under iterate: 2-block × 3-iter emits :b{i}:r{j}", () => {
    const nestedSpec: CipherSpec = {
      id: "test-fes-history-nested@1",
      name: "nested iterate × FES-with-history",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "iterate",
          id: "blocks",
          countFromAux: "count",
          blocksFromAux: "in-blocks",
          outBlocksAux: "out-blocks",
          children: [
            // Outer iterate hands each iteration a MatrixState from
            // `in-blocks` aux, but FES-with-history requires bytes-shape
            // parent state. The `to-bytes` leaf below is a test-local
            // matrix→bytes adapter (takes the matrix's first 2 bytes as
            // its bytes-state output) that bridges the two contracts so
            // the suffix-composition assertion can run.
            {
              kind: "step",
              id: "to-bytes",
              type: "test.matrix-to-first-2-bytes@1",
              params: {},
            },
            {
              kind: "for-each-subgraph-with-history",
              id: "rounds",
              iterationCount: 3,
              lookbackOffsets: [1, 2],
              historyEntryByteLength: 1,
              children: [
                {
                  kind: "step",
                  id: "xor-priors",
                  type: "test.xor-priors-into-state@1",
                  params: {},
                },
              ],
            },
          ],
        },
      ],
    };

    // Test-local head-slice step for the nested case. Takes the first
    // 2 bytes of the 16-byte block and emits them as bytes state — small
    // enough to feed FES-with-history as 2 seeds at entry=1.
    const firstTwoBytes: StepDefinition = {
      executor: (state) => {
        if (state.shape !== "bytes") throw new Error("expects bytes");
        const head = state.bytes.subarray(0, 2);
        const next: BytesState = { shape: "bytes", bytes: new Uint8Array(head) };
        return { state: next };
      },
    };
    const registry = buildRegistry();
    registry.register("test.matrix-to-first-2-bytes@1", firstTwoBytes);

    const block16WithFirstTwo = (a: number, b: number): BytesState => {
      const bytes = new Uint8Array(16);
      bytes[0] = a;
      bytes[1] = b;
      return { shape: "bytes", bytes };
    };
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array(0) };
    const blocks: readonly BytesState[] = [
      block16WithFirstTwo(0x05, 0x03),
      block16WithFirstTwo(0x0a, 0x05),
    ];
    const trace = runSpec(nestedSpec, registry, {
      initialState: initial,
      initialAux: new Map<string, AuxValue>([
        ["count", 2],
        ["in-blocks", blocks],
      ]),
    });

    // Two blocks × (1 to-bytes + 3 inner rounds) = 8 frames total.
    expect(trace.frames).toHaveLength(8);

    // Suffix composition: outer iterate is `:b{i}` (type-order before
    // `:r`), inner FES-with-history is `:r{j}`. Block 0's frames come
    // first (iterate fully expands each block before moving to the next).
    const expectedStepIds = [
      "to-bytes:b0",
      "xor-priors:b0:r0",
      "xor-priors:b0:r1",
      "xor-priors:b0:r2",
      "to-bytes:b1",
      "xor-priors:b1:r0",
      "xor-priors:b1:r1",
      "xor-priors:b1:r2",
    ];
    expect(trace.frames.map((f) => f.stepId)).toEqual(expectedStepIds);

    // blockIndex stamped per outer iteration.
    expect(trace.frames.map((f) => f.blockIndex)).toEqual([0, 0, 0, 0, 1, 1, 1, 1]);
  });

  // ─── Contract-invariant throws ───────────────────────────────────────────
  //
  // Each invariant gets its own test for attribution clarity — when a
  // future contract change breaks one, the failing test name names the
  // exact constraint that broke.

  const seedsTwo: BytesState = { shape: "bytes", bytes: new Uint8Array([0x05, 0x03]) };
  const makeSpec = (overrides: {
    readonly lookbackOffsets?: readonly number[];
    readonly historyEntryByteLength?: number;
    readonly iterationCount?: number | { readonly fromParam: string };
    readonly bodyType?: string;
  }): CipherSpec => ({
    id: "test-fes-history-throw@1",
    name: "throw-case",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "for-each-subgraph-with-history",
        id: "loop",
        iterationCount: overrides.iterationCount ?? 2,
        lookbackOffsets: overrides.lookbackOffsets ?? [1, 2],
        historyEntryByteLength: overrides.historyEntryByteLength ?? 1,
        children: [
          {
            kind: "step",
            id: "body",
            type: overrides.bodyType ?? "test.xor-priors-into-state@1",
            params: {},
          },
        ],
      },
    ],
  });

  it("throws when lookbackOffsets is empty", () => {
    expect(() =>
      runSpec(makeSpec({ lookbackOffsets: [] }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/lookbackOffsets must be non-empty/);
  });

  it("throws when lookbackOffsets contains 0", () => {
    // Offset 0 would read the not-yet-written current iteration's entry —
    // semantically meaningless, surfaces loudly per the doc-comment.
    expect(() =>
      runSpec(makeSpec({ lookbackOffsets: [0, 1] }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/positive integer/);
  });

  it("throws when lookbackOffsets contains a negative offset", () => {
    expect(() =>
      runSpec(makeSpec({ lookbackOffsets: [-1, 1] }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/positive integer/);
  });

  it("throws when lookbackOffsets contains a non-integer offset", () => {
    expect(() =>
      runSpec(makeSpec({ lookbackOffsets: [1.5] }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/positive integer/);
  });

  it("throws when historyEntryByteLength is zero", () => {
    expect(() =>
      runSpec(makeSpec({ historyEntryByteLength: 0 }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/historyEntryByteLength must be a positive integer/);
  });

  it("throws when historyEntryByteLength is non-integer", () => {
    expect(() =>
      runSpec(makeSpec({ historyEntryByteLength: 0.5 }), buildRegistry(), {
        initialState: seedsTwo,
      }),
    ).toThrow(/historyEntryByteLength must be a positive integer/);
  });

  it("throws when seed count is fewer than max(lookbackOffsets)", () => {
    // 2 seeds × entry=1, but max offset = 3 → can't satisfy iteration 0's
    // prior-3 read.
    expect(() =>
      runSpec(makeSpec({ lookbackOffsets: [1, 2, 3] }), buildRegistry(), {
        initialState: seedsTwo,
      }),
    ).toThrow(/need at least max\(lookbackOffsets\)=3 seeds/);
  });

  it("throws when parent state.bytes.length is not a multiple of historyEntryByteLength", () => {
    // 3 bytes, entry=2 → 3 % 2 != 0.
    const oddInitial: BytesState = { shape: "bytes", bytes: new Uint8Array([1, 2, 3]) };
    expect(() =>
      runSpec(makeSpec({ historyEntryByteLength: 2 }), buildRegistry(), {
        initialState: oddInitial,
      }),
    ).toThrow(/is not a multiple of historyEntryByteLength/);
  });

  it("throws when body exit state.bytes.length != historyEntryByteLength", () => {
    // Body returns 2 bytes; entry=1 → mismatch.
    expect(() =>
      runSpec(makeSpec({ bodyType: "test.return-two-bytes@1" }), buildRegistry(), {
        initialState: seedsTwo,
      }),
    ).toThrow(/!= historyEntryByteLength/);
  });

  it("throws when iterationCount is negative", () => {
    expect(() =>
      runSpec(makeSpec({ iterationCount: -1 }), buildRegistry(), { initialState: seedsTwo }),
    ).toThrow(/iterationCount must be a non-negative integer/);
  });

  // ─── Aux snapshot+restore semantics (per-outer-reset enforcement) ────────
  //
  // Q3 user pick: per-outer reset. The history buffer is local to each
  // invocation of `runForEachSubgraphWithHistory`, so freshness across
  // invocations is correctness-by-construction. The externally observable
  // proxy for "the node didn't leak runtime state to its scope" is the
  // aux key snapshot+restore protocol: `prior-{N}` keys that were absent
  // before the node ran stay absent after; keys present with a
  // pre-existing value get that value restored verbatim.

  it("aux cleanup: prior-{N} keys absent after node exits when absent before", () => {
    // Spec: FES-with-history, then a sibling leaf that throws if
    // aux["prior-1"] or aux["prior-2"] is present. Verifies cleanup.
    const cleanupSpec: CipherSpec = {
      id: "test-fes-history-cleanup@1",
      name: "cleanup",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "loop",
          iterationCount: 2,
          lookbackOffsets: [1, 2],
          historyEntryByteLength: 1,
          children: [
            {
              kind: "step",
              id: "xor-priors",
              type: "test.xor-priors-into-state@1",
              params: {},
            },
          ],
        },
        {
          kind: "step",
          id: "assert-1-absent",
          type: "test.assert-aux-absent@1",
          params: { key: "prior-1" },
        },
        {
          kind: "step",
          id: "assert-2-absent",
          type: "test.assert-aux-absent@1",
          params: { key: "prior-2" },
        },
      ],
    };
    expect(() => runSpec(cleanupSpec, buildRegistry(), { initialState: seedsTwo })).not.toThrow();
  });

  it("aux restore: pre-existing prior-{N} value preserved across node lifetime", () => {
    // Spec: FES-with-history (which sets aux["prior-1"] inside its loop),
    // then a sibling leaf that verifies aux["prior-1"] still equals the
    // PRE-EXISTING value seeded via initialAux. Snapshot+restore should
    // overwrite the runtime's intermediate values with the original.
    const restoreSpec: CipherSpec = {
      id: "test-fes-history-restore@1",
      name: "restore",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "loop",
          iterationCount: 2,
          lookbackOffsets: [1, 2],
          historyEntryByteLength: 1,
          children: [
            {
              kind: "step",
              id: "xor-priors",
              type: "test.xor-priors-into-state@1",
              params: {},
            },
          ],
        },
        {
          kind: "step",
          id: "assert-1-restored",
          type: "test.assert-aux-equals@1",
          params: { key: "prior-1", expectedHex: "aa" },
        },
        {
          kind: "step",
          id: "assert-2-restored",
          type: "test.assert-aux-equals@1",
          params: { key: "prior-2", expectedHex: "bb" },
        },
      ],
    };
    const initialAux = new Map<string, AuxValue>([
      ["prior-1", new Uint8Array([0xaa])],
      ["prior-2", new Uint8Array([0xbb])],
    ]);
    expect(() =>
      runSpec(restoreSpec, buildRegistry(), { initialState: seedsTwo, initialAux }),
    ).not.toThrow();
  });
});

// ─── A2 container port contract (scaffolding-suppression plan) ─────────────
//
// A2 lets the FES-with-history source its initial history from an explicit
// upstream output port (`seedInput`) and capture each iteration's result
// from a named body node's output port (`bodyOutput`), instead of moving
// data through `state` via `bytes-to-state@1` bridge leaves. These tests
// pin the new port path AND the deferred-kind loud failures, using real
// port-native steps (`constant-load@1` / `aux-load-bytes@1` / `xor@1`) from
// the default registry so the dispatch path matches the shipped SHA-256
// message schedule it's modeled on.
//
// The body mirrors the state-mode XOR toy above (seeds [0x05, 0x03],
// offsets [1, 2]) so the same hand-computed cycle is the KAT — if seedInput
// or bodyOutput resolution is wrong, the final concatenated history diverges
// from the value the legacy state path already pins.

const port = (node: string, p: string) => ({ node, port: p });

describe("runtime — FES-with-history container port contract (A2)", () => {
  // constant-load "seeds" → seedInput; body XORs prior-1 + prior-2; the
  // xor leaf's output → bodyOutput. Same 8-iteration cycle as the
  // state-mode happy-path test, so the expected history is identical.
  const buildPortModeSpec = (overrides?: {
    readonly seedInput?: { readonly node: string; readonly port: string };
    readonly bodyOutput?: { readonly node: string; readonly port: string };
  }): CipherSpec => ({
    id: "test-fes-history-port@1",
    name: "A2 port-mode FES-with-history",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "seeds",
        type: "constant-load@1",
        params: { bytes: [0x05, 0x03] },
      },
      {
        kind: "for-each-subgraph-with-history",
        id: "loop",
        iterationCount: 8,
        lookbackOffsets: [1, 2],
        historyEntryByteLength: 1,
        seedInput: overrides?.seedInput ?? port("seeds", "output"),
        bodyOutput: overrides?.bodyOutput ?? port("xor-priors", "output"),
        children: [
          {
            kind: "step",
            id: "fetch-p1",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-1", byteLength: 1 },
          },
          {
            kind: "step",
            id: "fetch-p2",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-2", byteLength: 1 },
          },
          {
            kind: "step",
            id: "xor-priors",
            type: "xor@1",
            params: { inputCount: 2 },
            portInputs: {
              operand0: port("fetch-p1", "output"),
              operand1: port("fetch-p2", "output"),
            },
          },
        ],
      },
    ],
  });

  it("port mode: seedInput seeds history + bodyOutput captures per-iteration result (KAT matches state mode)", () => {
    const trace = runSpec(buildPortModeSpec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      portedDispatchEnabled: true,
    });
    // Exit state = full concatenated history (seeds + 8 outputs) — the
    // SAME value the legacy state-mode test pins, proving seedInput +
    // bodyOutput resolution carries the right bytes.
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05, 0x03, 0x06, 0x05,
    ]);
    // Body still emits :r{i}-suffixed frames; the bodyOutput capture
    // doesn't change frame emission.
    const xorFrames = trace.frames.filter((f) => canonicalStepId(f.stepId) === "xor-priors");
    expect(xorFrames).toHaveLength(8);
    expect(xorFrames.map((f) => f.stepId)).toEqual([
      "xor-priors:r0",
      "xor-priors:r1",
      "xor-priors:r2",
      "xor-priors:r3",
      "xor-priors:r4",
      "xor-priors:r5",
      "xor-priors:r6",
      "xor-priors:r7",
    ]);
  });

  it("port mode throws when seedInput references a non-same-scope node", () => {
    expect(() =>
      runSpec(
        buildPortModeSpec({ seedInput: port("no-such-producer", "output") }),
        buildDefaultRegistry(),
        {
          initialState: { shape: "bytes", bytes: new Uint8Array(0) },
          portedDispatchEnabled: true,
        },
      ),
    ).toThrow(/seedInput references 'no-such-producer\.output'.*not a same-scope upstream output/);
  });

  it("port mode throws when bodyOutput references a node outside the body's direct children", () => {
    // `seeds` is a top-level sibling, NOT a direct child of the body, so
    // it's absent from the body-scope nodeOutputs map.
    expect(() =>
      runSpec(buildPortModeSpec({ bodyOutput: port("seeds", "output") }), buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
        portedDispatchEnabled: true,
      }),
    ).toThrow(/bodyOutput references 'seeds\.output'.*not a same-scope body output/);
  });

  // Port-mode iterate (B1.4): `seedInput` is now WIRED (no longer deferred).
  // It resolves the binding in the parent scope, so an unresolvable reference
  // throws the same same-scope-upstream error the group/FES branches use.
  it("port-mode iterate: unresolvable seedInput throws the same-scope upstream error", () => {
    const spec: CipherSpec = {
      id: "test-iterate-seedinput@1",
      name: "iterate seedInput unresolvable",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "iterate",
          id: "blocks",
          seedInput: port("nowhere", "output"),
          blockByteLength: 4,
          bodyOutput: port("leaf", "output"),
          children: [],
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      }),
    ).toThrow(
      /iterate 'blocks': seedInput references 'nowhere\.output'.*not a same-scope upstream output/,
    );
  });

  // Port mode requires `blockByteLength` (the split width); a `seedInput`
  // without it is a half-wired port-mode iterate and throws loudly.
  it("port-mode iterate: seedInput without blockByteLength throws", () => {
    const spec: CipherSpec = {
      id: "test-iterate-no-blocklen@1",
      name: "iterate missing blockByteLength",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "iterate",
          id: "blocks",
          // blockByteLength is validated before seedInput resolves, so the
          // (unresolvable) seed value is irrelevant to this assertion.
          seedInput: port("nowhere", "output"),
          bodyOutput: port("leaf", "output"),
          children: [],
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      }),
    ).toThrow(/iterate 'blocks': blockByteLength must be a positive integer in port mode/);
  });

  it("deferred-kind: for-each-subgraph with bodyOutput throws a Phase-B1-deferred error", () => {
    const spec: CipherSpec = {
      id: "test-fes-bodyoutput@1",
      name: "for-each-subgraph bodyOutput deferred",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "for-each-subgraph",
          id: "fes",
          iterationCount: 2,
          bodyOutput: port("nowhere", "output"),
          children: [],
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      }),
    ).toThrow(
      /for-each-subgraph 'fes': seedInput\/bodyOutput port-seeding is deferred to Phase B1/,
    );
  });
});

// ─── A3b group port contract (scaffolding-suppression plan) ────────────────
//
// A3b extends `seedInput`/`bodyOutput` to a plain `group` (a single body walk,
// no iteration) so a round body can cross its scope wall in bytes instead of
// through `state-to-bytes@1` (entry) + `bytes-to-state@1` (exit) bridge leaves.
// The runtime injects `seedInput`'s bytes into the body scope as
// `port(groupId, "in")`, and `bodyOutput` names the body node whose port
// becomes the group's published exit. This is the mechanism SHA-256's 64
// compression rounds use to carry the working variables port-to-port.

describe("runtime — group container port contract (A3b)", () => {
  // seeds → group{ seedInput: seeds.output; body NOTs the seed; bodyOutput:
  // not.output }. The group publishes not's output on "out"; spec.outputFrom
  // surfaces it as finalState. NOT([0x05, 0x03]) = [0xFA, 0xFC].
  const buildGroupPortModeSpec = (overrides?: {
    readonly seedInput?: { readonly node: string; readonly port: string };
    readonly bodyOutput?: { readonly node: string; readonly port: string };
  }): CipherSpec => ({
    id: "test-group-port@1",
    name: "A3b group port-mode",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "seeds",
        type: "constant-load@1",
        params: { bytes: [0x05, 0x03] },
      },
      {
        kind: "group",
        id: "g",
        label: "G",
        seedInput: overrides?.seedInput ?? port("seeds", "output"),
        bodyOutput: overrides?.bodyOutput ?? port("g.not", "output"),
        children: [
          {
            kind: "step",
            id: "g.not",
            type: "not@1",
            params: {},
            // Reads the carried bytes off the group's seedInput port.
            portInputs: { input: port("g", "in") },
          },
        ],
      },
    ],
    outputFrom: port("g", "out"),
  });

  it("port mode: seedInput injects bytes as port(groupId,'in'); bodyOutput becomes the group's published exit", () => {
    const trace = runSpec(buildGroupPortModeSpec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      portedDispatchEnabled: true,
    });
    // finalState = spec.outputFrom = port("g","out") = bodyOutput = NOT(seed).
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0xfa, 0xfc]);
    // The body leaf saw the seed bytes on its input port (proving the
    // runtime injected seedInput as port(groupId,"in")).
    const notFrame = trace.frames.find((f) => canonicalStepId(f.stepId) === "g.not");
    if (!notFrame || notFrame.stateBefore.shape !== "bytes") throw new Error("g.not frame");
    expect(notFrame.portInputs?.get("input")).toEqual(new Uint8Array([0x05, 0x03]));
  });

  it("port mode throws when group seedInput references a non-same-scope node", () => {
    expect(() =>
      runSpec(
        buildGroupPortModeSpec({ seedInput: port("no-such-producer", "output") }),
        buildDefaultRegistry(),
        {
          initialState: { shape: "bytes", bytes: new Uint8Array(0) },
          portedDispatchEnabled: true,
        },
      ),
    ).toThrow(
      /group 'g': seedInput references 'no-such-producer\.output'.*not a same-scope upstream output/,
    );
  });

  it("port mode throws when group bodyOutput references a node outside the body's direct children", () => {
    // `seeds` is a top-level sibling, NOT a direct child of the group body,
    // so it's absent from the body-scope nodeOutputs map.
    expect(() =>
      runSpec(
        buildGroupPortModeSpec({ bodyOutput: port("seeds", "output") }),
        buildDefaultRegistry(),
        {
          initialState: { shape: "bytes", bytes: new Uint8Array(0) },
          portedDispatchEnabled: true,
        },
      ),
    ).toThrow(/group 'g': bodyOutput references 'seeds\.output'.*not a same-scope body output/);
  });

  it("port mode throws when group bodyOutput references a grandchild (nested) node, not a direct child", () => {
    // ⓔ (runtime half — validator half lives in tests/spec-shapes.test.ts).
    // `bodyOutput` must name a DIRECT child of the body. `g.inner.leaf` lives
    // inside `g.inner` (a child group), one scope deeper than g's body, so
    // it's absent from g's body-scope `nodeOutputs` (which records `g.inner`,
    // the direct child container, not its descendants). The runtime resolves
    // bodyOutput against that body scope AFTER walking the body, so the body
    // runs fine and the throw isolates the direct-only contract — pinning it
    // against a future "recurse into nested scopes" regression.
    const spec: CipherSpec = {
      id: "test-group-bodyoutput-grandchild@1",
      name: "A3b group bodyOutput grandchild",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "seeds", type: "constant-load@1", params: { bytes: [0x05, 0x03] } },
        {
          kind: "group",
          id: "g",
          label: "G",
          seedInput: port("seeds", "output"),
          bodyOutput: port("g.inner.leaf", "output"),
          children: [
            {
              kind: "group",
              id: "g.inner",
              label: "inner",
              children: [
                {
                  kind: "step",
                  id: "g.inner.leaf",
                  type: "constant-load@1",
                  params: { bytes: [0xab] },
                },
              ],
            },
          ],
        },
      ],
      outputFrom: port("g", "out"),
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
        portedDispatchEnabled: true,
      }),
    ).toThrow(
      /group 'g': bodyOutput references 'g\.inner\.leaf\.output'.*not a same-scope body output/,
    );
  });
});
