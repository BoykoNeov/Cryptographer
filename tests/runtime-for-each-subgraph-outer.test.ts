/**
 * Slice 2.0b — toy fixture for `for-each-subgraph` ITEM-ARRAY mode.
 *
 * Slice 2.0a shipped the state-thread mode (SHA-256-compression-shaped:
 * one inner round body that re-enters with the previous iteration's
 * final state). Slice 2.0b widens the same spec node kind to subsume the
 * legacy `IterateGroup` pattern under one universal-port construct:
 * **parent-scope BytesState splits into fixed-size chunks; each chunk
 * seeds the body's state; per-iteration body output concatenates back
 * to a flat BytesState on node exit.** SHA-256's outer per-block loop
 * (later in Phase 2) is the first shipped consumer; this toy validates
 * the runtime contract on a 3-block synthetic body.
 *
 * The two user picks baked into this fixture
 * (per `docs/plans/universal-port-phase-2-slices.md`):
 *
 *  - **Open #N1 = (b) Concatenated single port.** `split-blocks`-style
 *    inputs flatten to one byte sequence; for-each-subgraph re-splits at
 *    iteration entry via `blockByteLength`. No PortShapeMap contract
 *    extension — block count is run-time-derived, not spec-time.
 *  - **Slice 2.0b sub-decision = (X) Node-explicit fields.** The
 *    for-each-subgraph node carries `inputArrayPort` + `outputsPort` +
 *    `blockByteLength` + `blockLayout` directly. iterationCount
 *    auto-derives as `state.bytes.length / blockByteLength`. Mirrors
 *    legacy iterate's `blocksFromAux/countFromAux/outBlocksAux` pattern;
 *    no graph-introspection coupling.
 *
 * Pass/fail gate (per the slice spec):
 *  - 3 :r{i} frames emit with sequential block bytes as their stateBefore.
 *  - Each iteration's body sees its block as a 4-byte BytesState.
 *  - Final state == concat of (block_i XOR constant) for i in 0..2.
 *  - iterationCount auto-derives — no field is set on the node.
 *  - Mode-exclusivity throw: setting both `iterationCount` AND
 *    item-array fields raises a noisy authoring-bug error.
 *  - Length-divisibility throw: `state.bytes.length % blockByteLength
 *    !== 0` raises a noisy error.
 *  - Phase 1 frame-parity matrix is untouched (legacy ciphers don't use
 *    for-each-subgraph).
 */

import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { canonicalStepId } from "@/core/step-id";
import type { BytesState, CipherSpec, PortedExecutor, StepRegistration } from "@/core/types";
import { describe, expect, it } from "vitest";

// Body executor: XOR each byte of the 4-byte block state with a constant
// from params. Same pattern as the inner-only toy, just shaped for the
// per-block decode/encode round-trip. The constant length is independent
// of block length (zero-pads / cycles via `i % constant.length`) so the
// fixture can swap block sizes without retuning constants.
//
// **Port-native since Phase C (universal-port Phase 5).** Hybrid-ported:
// the runtime projects each per-block seed state into the `"state"` port via
// `meta.stateInputPort` and reconstructs the node-exit concat from the
// `"state"` output port. XOR math unchanged; finalState byte-for-byte equal.
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
    name: "Test: XOR with constant (item-array)",
    summary: "Toy per-block body — XORs each block with a fixed constant.",
    detail: "for-each-subgraph item-array fixture (port-native since Phase C).",
  },
};

const buildRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("test.xor-with-constant@1", xorWithConstant);
  return r;
};

// 3-block (3 × 4 bytes) XOR-with-constant spec. Block 0 = [10,11,12,13],
// Block 1 = [20,21,22,23], Block 2 = [30,31,32,33]. Constant = [1,2,3,4].
// Expected per-block output: block ^ constant byte-wise.
const outerToySpec: CipherSpec = {
  id: "test-fes-outer@1",
  name: "3-block per-block XOR-with-constant",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "for-each-subgraph",
      id: "loop",
      label: "per-block xor",
      // Item-array mode: parent-scope state.bytes splits into 4-byte
      // chunks; each chunk seeds the body as a BytesState; bodies emit
      // BytesState; node-exit state = concat of per-iteration outputs.
      inputArrayPort: "items",
      outputsPort: "outs",
      blockByteLength: 4,
      blockLayout: "bytes",
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

describe("runtime — for-each-subgraph item-array mode (Slice 2.0b)", () => {
  it("3 blocks × 1 body leaf produces 3 :r{i} frames; finalState concats per-block outputs", () => {
    const initial: BytesState = {
      shape: "bytes",
      // 3 blocks: [10..13][20..23][30..33]
      bytes: new Uint8Array([
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33,
      ]),
    };
    const trace = runSpec(outerToySpec, buildRegistry(), {
      initialState: initial,
      portedDispatchEnabled: true,
    });

    // 3 iterations × 1 body leaf = 3 frames. (Plus zero coercion frames —
    // toy spec has no port-length-coerced inputs.)
    expect(trace.frames).toHaveLength(3);

    // Suffix composition: each body frame carries `:r{i}` from
    // for-each-subgraph's roundPath. No outer iterate / Feistel here, so
    // no other suffixes compose in.
    expect(trace.frames.map((f) => f.stepId)).toEqual(["xor:r0", "xor:r1", "xor:r2"]);

    // Canonical stepId strips back to the spec-leaf id — what
    // `setTrace`'s frame-preservation across re-runs depends on.
    for (const f of trace.frames) {
      expect(canonicalStepId(f.stepId)).toBe("xor");
    }

    // Per-iteration seeding + transform are verified through the surviving
    // `finalState` (the per-frame `stateBefore`/`stateAfter` State snapshots
    // retired in Slice 5.3e Batch 4). In item-array mode each iteration is
    // independent — seeded from its OWN block (NOT the previous body output) —
    // so `finalState` is the concat of each block ^ constant. That concat
    // discriminates BOTH per-block seeding (a mis-seeded block would change
    // its slice) AND the transform: it could not hold if any block were seeded
    // from the wrong source or transformed wrong.
    //
    // Final state: concat of per-iteration outputs as a flat BytesState.
    // This is what the node "writes back" to parent-scope state at exit
    // — the legacy concat-blocks step becomes redundant in port-native
    // specs.
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0x10 ^ 0x01,
      0x11 ^ 0x02,
      0x12 ^ 0x03,
      0x13 ^ 0x04,
      0x20 ^ 0x01,
      0x21 ^ 0x02,
      0x22 ^ 0x03,
      0x23 ^ 0x04,
      0x30 ^ 0x01,
      0x31 ^ 0x02,
      0x32 ^ 0x03,
      0x33 ^ 0x04,
    ]);
  });

  it("empty input (zero blocks) emits zero frames and leaves state as zero-length BytesState", () => {
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array(0) };
    const trace = runSpec(outerToySpec, buildRegistry(), {
      initialState: initial,
      portedDispatchEnabled: true,
    });
    expect(trace.frames).toHaveLength(0);
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(trace.finalState.bytes.length).toBe(0);
  });

  it("single-block input (1 × blockByteLength) emits one :r0 frame", () => {
    const initial: BytesState = { shape: "bytes", bytes: new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3]) };
    const trace = runSpec(outerToySpec, buildRegistry(), {
      initialState: initial,
      portedDispatchEnabled: true,
    });
    expect(trace.frames).toHaveLength(1);
    expect(trace.frames[0]?.stepId).toBe("xor:r0");
    if (trace.finalState.shape !== "bytes") throw new Error("finalState shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0xa0 ^ 0x01,
      0xa1 ^ 0x02,
      0xa2 ^ 0x03,
      0xa3 ^ 0x04,
    ]);
  });

  it("length-divisibility throws when input bytes don't evenly divide blockByteLength", () => {
    // 5 bytes with blockByteLength = 4 is a noisy authoring error.
    const initial: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]),
    };
    expect(() =>
      runSpec(outerToySpec, buildRegistry(), {
        initialState: initial,
        portedDispatchEnabled: true,
      }),
    ).toThrow(/is not a multiple of blockByteLength/);
  });

  it("mode-exclusivity throws when both iterationCount AND item-array fields are set", () => {
    const mixedSpec: CipherSpec = {
      ...outerToySpec,
      steps: [
        {
          kind: "for-each-subgraph",
          id: "loop",
          // Both modes' fields present — runtime catches the authoring bug.
          iterationCount: 3,
          inputArrayPort: "items",
          outputsPort: "outs",
          blockByteLength: 4,
          blockLayout: "bytes",
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
    expect(() => runSpec(mixedSpec, buildRegistry(), { initialState: initial })).toThrow(
      /forbids iterationCount/,
    );
  });

  it("partial-field config throws (item-array mode requires ALL four fields)", () => {
    const partialSpec: CipherSpec = {
      ...outerToySpec,
      steps: [
        {
          kind: "for-each-subgraph",
          id: "loop",
          // Only inputArrayPort set; the other three absent → noisy throw.
          inputArrayPort: "items",
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
    expect(() => runSpec(partialSpec, buildRegistry(), { initialState: initial })).toThrow(
      /item-array mode requires ALL of/,
    );
  });

  // The "non-bytes parent state throws" and "blockLayout matrix4x4-bytes
  // round-trip" cases were retired in Phase 5 Slice 5.1 (2026-05-30) with
  // the MatrixState shape: with `bytes` the only State shape, there is no
  // wrong-shape parent state to construct and no non-bytes `blockLayout` to
  // exercise. The bytes-mode item-array path above carries the coverage.
});
