/**
 * Slice 2.0a — toy fixture for the `for-each-subgraph` spec node kind.
 *
 * The slice introduces a port-native iteration primitive that THREADS
 * state across iterations (unlike `iterate`, which clobbers state from an
 * aux array each iteration). SHA-256's 64-round compression body is the
 * first shipped consumer; this toy validates the runtime contract on a
 * synthetic body before SHA-256 specifics land.
 *
 * The four contract-design decisions baked into these tests
 * (per `docs/plans/universal-port-phase-2-slices.md`):
 *
 *  - **Q-2.0a-1 (node shape) = mirror iterate.** Body inline as
 *    `children: StepNode[]`. Implicit state-thread: first child reads
 *    parent-scope `state`; subsequent iterations re-enter with the
 *    previous iteration's body-final state.
 *  - **Q-2.0a-2 (iterationCount source) = number-or-fromParam.** This
 *    toy exercises ONLY the number form; param-form throws by design
 *    (Slice 2.0a defers the lookup mechanism to the first param-form
 *    consumer — SHA-256 compression uses literal 64).
 *  - **Q-2.0a-3 (nested-suffix convention) = `:r{i}` rounds, composed
 *    `:b{i}:r{j}` under iterate-wrapping-for-each-subgraph.** The rule
 *    is fixed type-order `:t` < `:b` < `:r` with outer-first walk-order
 *    within a type — pinned by the nested case below.
 *  - **Q-2.0a-4 (toy content) = 5-iter XOR-with-constant.** Each
 *    iteration XORs state with a fixed 4-byte constant. Final state =
 *    start XOR (5 × constant) = start XOR constant (odd-count
 *    self-cancellation). Easier to reason per-iteration than ROT13⁵.
 *
 * Pass/fail gate (per the slice spec):
 *  - Inner-only toy: 5 frames emit with `:r0`..`:r4` suffixes; per-
 *    iteration state thread reads correctly; final state byte-equal to
 *    start XOR constant.
 *  - Nested toy: 6 body frames emit with composed `:b{i}:r{j}` suffixes;
 *    state threads within each block's iteration but resets at the
 *    iterate boundary per the iterate contract.
 *  - Number-form vs. param-form: number form runs; param-form throws
 *    with a clear "deferred to first consumer" error.
 */

import { framePrimaryInBytes, framePrimaryOutBytes } from "@/core/frame-state";
import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { canonicalStepId } from "@/core/step-id";
import type {
  AuxValue,
  BytesState,
  CipherSpec,
  PortedExecutor,
  StepRegistration,
} from "@/core/types";
import { describe, expect, it } from "vitest";

// XOR-with-constant body. The constant is hardcoded per-test; we surface it
// via params so the executor stays cipher-agnostic. Each iteration reads the
// threaded state off the `"state"` input port (which threads across iterations
// under for-each-subgraph), XORs each byte with the param's `constant` array
// (cycled to the state byte length so the toy works on any state size), and
// writes the new block to the `"state"` output port.
//
// **Port-native since Slice 5.3e Batch 4.** Originally a legacy
// `(state) → { state }` executor; converted to a hybrid-ported step
// (`meta.stateInputPort`/`stateOutputPort = "state"`, so the runtime projects
// the threaded state into/out of the `"state"` port and captures it as frame
// port I/O). The reason for the conversion: XOR is self-inverse, so a 5×
// application's `finalState` (= s0 ^ c) is IDENTICAL whether the state threads
// correctly or each iteration re-seeds from s0 — `finalState` cannot
// discriminate. The per-iteration thread invariant below (`out[i-1] == in[i]`)
// is the only check that catches mis-threading, and it now reads the captured
// port I/O via `frameStateIn/OutBytes` (the `stateBefore`/`stateAfter` State
// fields it used to read retired in Batch 4). The runtime threads the closure
// state byte-identically either way; only the observation surface changed.
const xorWithConstantExecutor: PortedExecutor = (inputs, params) => {
  const state = inputs.get("state");
  if (!state) throw new Error("xorWithConstant expects a 'state' input port");
  const constantRaw = (params as unknown as { readonly constant: readonly number[] }).constant;
  const out = new Uint8Array(state);
  for (let i = 0; i < out.length; i++) {
    out[i] = (out[i] ?? 0) ^ (constantRaw[i % constantRaw.length] ?? 0);
  }
  return new Map([["state", out]]);
};

const xorWithConstant: StepRegistration = {
  kind: "ported",
  executor: xorWithConstantExecutor,
  shape: {
    inputs: new Map([["state", { layout: "raw" }]]),
    outputs: new Map([["state", { layout: "raw" }]]),
  },
  meta: { stateLayout: "bytes", stateInputPort: "state", stateOutputPort: "state" },
  doc: {
    name: "Test: XOR with constant",
    summary: "Toy for-each-subgraph body — XORs the threaded state with a fixed constant.",
    detail: "Slice 2.0a fixture (port-native since 5.3e Batch 4).",
  },
};

// Increment-byte-0 body for the nested iterate-wrapping case. Each
// iteration of the inner for-each-subgraph bumps byte 0 by 1; with state
// threading, after 3 inner iterations byte 0 advances from i → i+3.
//
// **Port-native since Phase C (universal-port Phase 5).** Converted from a
// legacy `(state) → { state }` executor to a hybrid-ported step when the
// legacy executor contract was retired: the runtime projects the threaded
// state into/out of the `"state"` port via `meta.stateInputPort`/
// `stateOutputPort`, so the increment math is unchanged and the nested
// state-thread invariant still holds byte-for-byte.
const incrementByte0Executor: PortedExecutor = (inputs) => {
  const state = inputs.get("state");
  if (!state) throw new Error("incrementByte0 expects a 'state' input port");
  const out = new Uint8Array(state);
  out[0] = ((out[0] ?? 0) + 1) & 0xff;
  return new Map([["state", out]]);
};

const incrementByte0: StepRegistration = {
  kind: "ported",
  executor: incrementByte0Executor,
  shape: {
    inputs: new Map([["state", { layout: "raw" }]]),
    outputs: new Map([["state", { layout: "raw" }]]),
  },
  meta: { stateLayout: "bytes", stateInputPort: "state", stateOutputPort: "state" },
  doc: {
    name: "Test: increment byte 0",
    summary: "Toy body — bumps byte 0 of the threaded state by 1.",
    detail: "Nested iterate × for-each-subgraph fixture (port-native since Phase C).",
  },
};

const buildRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("test.xor-with-constant@1", xorWithConstant);
  r.register("test.increment@1", incrementByte0);
  return r;
};

// ─── Inner-only toy: 5-iter XOR-with-constant ─────────────────────────────

const innerToySpec: CipherSpec = {
  id: "test-fes-inner@1",
  name: "5-iter XOR-with-constant",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "for-each-subgraph",
      id: "loop",
      label: "5x xor",
      iterationCount: 5,
      children: [
        {
          kind: "step",
          id: "xor",
          type: "test.xor-with-constant@1",
          params: { constant: [0x01, 0x02, 0x03, 0x04] },
        },
      ],
    },
  ],
};

describe("runtime — for-each-subgraph node (Slice 2.0a)", () => {
  it("inner-only toy: 5 iterations thread state and emit :r{i}-suffixed frames", () => {
    const initial: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    };
    const trace = runSpec(innerToySpec, buildRegistry(), {
      initialState: initial,
    });

    // Five iterations × one body leaf = five frames.
    expect(trace.frames).toHaveLength(5);

    // StepId suffixes pin Q-2.0a-3: each frame appends `:r{i}` to the
    // leaf id. Order is iteration-major (i goes 0..4).
    const stepIds = trace.frames.map((f) => f.stepId);
    expect(stepIds).toEqual(["xor:r0", "xor:r1", "xor:r2", "xor:r3", "xor:r4"]);

    // Canonical stepId strips back to the spec-leaf id — this is what
    // `setTrace`'s frame-preservation across re-runs depends on.
    for (const f of trace.frames) {
      expect(canonicalStepId(f.stepId)).toBe("xor");
    }

    // State-thread invariant: each iteration's `"state"` INPUT port equals the
    // PREVIOUS iteration's `"state"` OUTPUT port, and iteration 0's input
    // equals the runtime's initial state. Read off the captured port I/O via
    // the `frameStateIn/OutBytes` helpers (the `stateBefore`/`stateAfter`
    // fields retired in Slice 5.3e Batch 4). THIS is the load-bearing
    // threading check for the self-inverse XOR body — `finalState` (= s0 ^ c)
    // can't distinguish correct threading from per-iteration re-seeding.
    const f0 = trace.frames[0];
    if (!f0) throw new Error("frame 0 missing");
    expect(Array.from(framePrimaryInBytes(f0) ?? [])).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);

    for (let i = 1; i < trace.frames.length; i++) {
      const prev = trace.frames[i - 1];
      const cur = trace.frames[i];
      if (!prev || !cur) throw new Error(`frame ${i} or ${i - 1} missing`);
      expect(Array.from(framePrimaryInBytes(cur) ?? [])).toEqual(
        Array.from(framePrimaryOutBytes(prev) ?? []),
      );
    }

    // Final state = start XOR constant (odd application count — XOR is
    // its own inverse pairwise, so 5 applications net 1).
    const expectedFinal = [0xaa ^ 0x01, 0xbb ^ 0x02, 0xcc ^ 0x03, 0xdd ^ 0x04];
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(expectedFinal);
  });

  it("inner-only toy: an even iteration count returns the start state (XOR self-cancels)", () => {
    const evenSpec: CipherSpec = {
      ...innerToySpec,
      steps: [
        {
          kind: "for-each-subgraph",
          id: "loop",
          iterationCount: 4,
          children: [
            {
              kind: "step",
              id: "xor",
              type: "test.xor-with-constant@1",
              params: { constant: [0x01, 0x02, 0x03, 0x04] },
            },
          ],
        },
      ],
    };
    const initial: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    };
    const trace = runSpec(evenSpec, buildRegistry(), {
      initialState: initial,
    });
    expect(trace.frames).toHaveLength(4);
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    // 4 odd? No — 4 is even. Pairs cancel; final == initial.
    expect(Array.from(trace.finalState.bytes)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it("iterationCount=0 emits zero frames and leaves state untouched", () => {
    const emptySpec: CipherSpec = {
      ...innerToySpec,
      steps: [
        {
          kind: "for-each-subgraph",
          id: "loop",
          iterationCount: 0,
          children: [
            {
              kind: "step",
              id: "xor",
              type: "test.xor-with-constant@1",
              params: { constant: [0x01, 0x02, 0x03, 0x04] },
            },
          ],
        },
      ],
    };
    const initial: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    };
    const trace = runSpec(emptySpec, buildRegistry(), {
      initialState: initial,
    });
    expect(trace.frames).toHaveLength(0);
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it("iterationCount.fromParam throws with a clear Slice-2.0a-deferred error", () => {
    const paramSpec: CipherSpec = {
      ...innerToySpec,
      steps: [
        {
          kind: "for-each-subgraph",
          id: "loop",
          iterationCount: { fromParam: "rounds" },
          children: [
            {
              kind: "step",
              id: "xor",
              type: "test.xor-with-constant@1",
              params: { constant: [0x01, 0x02, 0x03, 0x04] },
            },
          ],
        },
      ],
    };
    const initial: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    };
    expect(() => runSpec(paramSpec, buildRegistry(), { initialState: initial })).toThrow(
      /Slice 2\.0a/,
    );
  });

  // ─── Nested toy: 2-block outer iterate × 3-iter inner for-each-subgraph ──
  //
  // Pins Q-2.0a-3 + Open #N6: composed `:b{i}:r{j}` suffix when an iterate
  // wraps a for-each-subgraph. The iterate seeds each block from an aux
  // array (per its existing contract); the inner for-each-subgraph then
  // threads state across its 3 iterations within that block. The
  // composition rule (fixed type order `:t` < `:b` < `:r`, outer-first
  // within a type) places `:b{i}` before `:r{j}` because the for-each-
  // subgraph is INSIDE the iterate, but `:b` is type-order-before `:r`
  // regardless of nesting depth — see `core/step-id.ts`.

  it("nested toy: 2-block iterate wrapping 3-iter for-each-subgraph composes :b{i}:r{j}", () => {
    const block16 = (b0: number): BytesState => {
      const bytes = new Uint8Array(16);
      bytes[0] = b0;
      return { shape: "bytes", bytes };
    };
    const nestedSpec: CipherSpec = {
      id: "test-fes-nested@1",
      name: "nested iterate × for-each-subgraph",
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
            {
              kind: "for-each-subgraph",
              id: "rounds",
              iterationCount: 3,
              children: [{ kind: "step", id: "inc", type: "test.increment@1", params: {} }],
            },
          ],
        },
      ],
    };

    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array(0) };
    const blocks: readonly BytesState[] = [block16(0), block16(0x10)];
    const trace = runSpec(nestedSpec, buildRegistry(), {
      initialState: initial,
      initialAux: new Map<string, AuxValue>([
        ["count", 2],
        ["in-blocks", blocks],
      ]),
    });

    // 2 blocks × 3 inner rounds × 1 child leaf = 6 frames.
    expect(trace.frames).toHaveLength(6);

    // Suffix composition: outer iterate is `:b{i}` (type-order before
    // `:r`), inner for-each-subgraph is `:r{j}`. Block 0's iterations
    // come first in the flat trace because the iterate fully expands
    // each block before moving to the next.
    expect(trace.frames.map((f) => f.stepId)).toEqual([
      "inc:b0:r0",
      "inc:b0:r1",
      "inc:b0:r2",
      "inc:b1:r0",
      "inc:b1:r1",
      "inc:b1:r2",
    ]);

    // Canonical stepId strips both suffixes back to the spec-leaf id.
    for (const f of trace.frames) {
      expect(canonicalStepId(f.stepId)).toBe("inc");
    }

    // Each frame carries blockIndex matching its `:b{i}` suffix.
    expect(trace.frames.map((f) => f.blockIndex)).toEqual([0, 0, 0, 1, 1, 1]);

    // State-thread within a block + per-block reset are verified through the
    // surviving `finalState` (the per-frame `stateAfter` snapshots retired in
    // Slice 5.3e Batch 4). The iterate seeds block 1
    // fresh from aux (resetting byte0 to 0x10) and the inner for-each-subgraph
    // threads 3 increments within it, leaving the exit state's byte0 at 0x13.
    // That value holds ONLY if BOTH happened correctly: a re-seed-each-inner-
    // iteration bug would leave 0x11, and a missing per-block reset (block 1
    // continuing block 0's 0x03) would leave 0x06. The exit `state` is the
    // last block's threaded result (runtime.ts:444-447 — NOT a concat).
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(trace.finalState.bytes.length).toBe(16);
    expect(trace.finalState.bytes[0]).toBe(0x13);
  });
});
