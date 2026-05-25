/**
 * split-bytes@1 — port-native N-way partitioning primitive tests
 * (universal-port plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * Symmetric to `concat.test.ts` (its inverse primitive). Two layers:
 *
 *  1. **Executor unit tests** — direct invocation against `inputs` Map.
 *     Verifies sub-range correctness across symmetric and asymmetric
 *     width arrays.
 *
 *  2. **Runtime integration tests** — `concat → split-bytes` round-trip
 *     (and the reverse), proving the two primitives compose into
 *     identity at the byte level.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { splitBytes, splitBytesOutputPortName } from "@/steps/split-bytes";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (input: Uint8Array, params: Json): ReadonlyMap<string, Uint8Array> =>
  splitBytes(new Map([["input", input]]), params, CTX);

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("split-bytes@1 — executor N-way partitioning", () => {
  it("partitions 8 bytes into two 4-byte words (symmetric 2-way)", () => {
    const input = new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23]);
    const outs = callExecutor(input, { widths: [4, 4] });
    expect(Array.from(outs.get("output0") as Uint8Array)).toEqual([0x10, 0x11, 0x12, 0x13]);
    expect(Array.from(outs.get("output1") as Uint8Array)).toEqual([0x20, 0x21, 0x22, 0x23]);
  });

  it("partitions 32 bytes into 8 × 4-byte words (SHA-256 working-vars case)", () => {
    const input = new Uint8Array(32);
    for (let i = 0; i < 32; i++) input[i] = i;
    const outs = callExecutor(input, { widths: [4, 4, 4, 4, 4, 4, 4, 4] });
    expect(outs.size).toBe(8);
    for (let i = 0; i < 8; i++) {
      const out = outs.get(`output${i}`) as Uint8Array;
      expect(Array.from(out)).toEqual([4 * i, 4 * i + 1, 4 * i + 2, 4 * i + 3]);
    }
  });

  it("partitions asymmetric widths (5 + 3 = 8)", () => {
    const input = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0xa1, 0xa2, 0xa3]);
    const outs = callExecutor(input, { widths: [5, 3] });
    expect(Array.from(outs.get("output0") as Uint8Array)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05]);
    expect(Array.from(outs.get("output1") as Uint8Array)).toEqual([0xa1, 0xa2, 0xa3]);
  });

  it("N=1 identity passthrough (single output equal to input)", () => {
    const input = new Uint8Array([0xab, 0xcd, 0xef]);
    const outs = callExecutor(input, { widths: [3] });
    expect(outs.size).toBe(1);
    expect(Array.from(outs.get("output0") as Uint8Array)).toEqual([0xab, 0xcd, 0xef]);
  });

  it("preserves declaration order in the output map", () => {
    const input = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const outs = callExecutor(input, { widths: [1, 1, 1, 1, 1] });
    const keys = Array.from(outs.keys());
    expect(keys).toEqual(["output0", "output1", "output2", "output3", "output4"]);
  });

  it("each output is a fresh buffer — mutating one does not affect others", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const outs = callExecutor(input, { widths: [2, 2] });
    const o0 = outs.get("output0") as Uint8Array;
    o0[0] = 0xff;
    expect(input[0]).toBe(0xa);
    expect((outs.get("output1") as Uint8Array)[0]).toBe(0xc);
  });

  it("throws when input port is missing", () => {
    expect(() => splitBytes(new Map(), { widths: [4, 4] }, CTX)).toThrow(
      /missing required input port 'input'/,
    );
  });

  it("uses the helper-exported port-naming convention", () => {
    expect(splitBytesOutputPortName(0)).toBe("output0");
    expect(splitBytesOutputPortName(7)).toBe("output7");
  });
});

// ─── Param validation ──────────────────────────────────────────────────────

describe("split-bytes@1 — param validation throws on misuse", () => {
  it("throws when params is null", () => {
    expect(() => callExecutor(new Uint8Array(4), null)).toThrow(/params must be an object/);
  });

  it("throws when widths is missing", () => {
    expect(() => callExecutor(new Uint8Array(4), {})).toThrow(
      /params.widths must be an array of positive integers/,
    );
  });

  it("throws when widths is not an array", () => {
    expect(() => callExecutor(new Uint8Array(4), { widths: 4 })).toThrow(
      /params.widths must be an array of positive integers/,
    );
  });

  it("throws when widths is empty", () => {
    expect(() => callExecutor(new Uint8Array(0), { widths: [] })).toThrow(
      /params.widths must contain at least one entry/,
    );
  });

  it("throws when a width entry is zero", () => {
    expect(() => callExecutor(new Uint8Array(4), { widths: [4, 0] })).toThrow(
      /params.widths\[1\] must be a positive integer/,
    );
  });

  it("throws when a width entry is negative", () => {
    expect(() => callExecutor(new Uint8Array(4), { widths: [4, -1] })).toThrow(
      /params.widths\[1\] must be a positive integer/,
    );
  });

  it("throws when a width entry is not an integer", () => {
    expect(() => callExecutor(new Uint8Array(4), { widths: [2.5, 1.5] })).toThrow(
      /params.widths\[0\] must be a positive integer/,
    );
  });
});

// ─── Runtime integration ───────────────────────────────────────────────────

describe("split-bytes@1 — runtime integration via port wiring", () => {
  /**
   * Round-trip: concat → split-bytes → concat → state. The interior
   * concat → split-bytes pair is an identity at the byte level, so the
   * final state should equal the plaintext.
   */
  it("concat → split-bytes is identity at the byte level", () => {
    const plaintext = new Uint8Array([
      0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42,
      0x43,
    ]);
    const spec: CipherSpec = {
      id: "toy-split-bytes-roundtrip",
      name: "concat → split-bytes round-trip (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "src", type: "state-to-bytes@1", params: {} },
        // First concat — identity on input (N=1 passthrough) so we have a
        // single wire to feed split-bytes from.
        {
          kind: "step",
          id: "wrap",
          type: "concat@1",
          params: { inputCount: 1 },
          portInputs: { input0: { node: "src", port: "output" } },
        },
        // Split into 4 × 4-byte words.
        {
          kind: "step",
          id: "split",
          type: "split-bytes@1",
          params: { widths: [4, 4, 4, 4] },
          portInputs: { input: { node: "wrap", port: "output" } },
        },
        // Rejoin via concat — should give back the plaintext.
        {
          kind: "step",
          id: "rejoin",
          type: "concat@1",
          params: { inputCount: 4 },
          portInputs: {
            input0: { node: "split", port: "output0" },
            input1: { node: "split", port: "output1" },
            input2: { node: "split", port: "output2" },
            input3: { node: "split", port: "output3" },
          },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: { input: { node: "rejoin", port: "output" } },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(plaintext));
  });

  /**
   * Outputs flow into different downstream consumers — exercise the
   * "one input → many consumers" topology that's the primary win over
   * N separate byte-slice leaves.
   */
  it("each output port can be consumed independently", () => {
    // Split a 4-byte input into 4 × 1-byte words, xor pairs, then concat
    // the two results. Verifies each output reaches the right consumer.
    const plaintext = new Uint8Array([0x01, 0x02, 0x04, 0x08]);
    const spec: CipherSpec = {
      id: "toy-split-bytes-fanout",
      name: "split fan-out to xor pairs (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "src", type: "state-to-bytes@1", params: {} },
        {
          kind: "step",
          id: "split",
          type: "split-bytes@1",
          params: { widths: [1, 1, 1, 1] },
          portInputs: { input: { node: "src", port: "output" } },
        },
        // xor0 = output0 ⊕ output1 = 0x01 ⊕ 0x02 = 0x03
        {
          kind: "step",
          id: "xor0",
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "split", port: "output0" },
            operand1: { node: "split", port: "output1" },
          },
        },
        // xor1 = output2 ⊕ output3 = 0x04 ⊕ 0x08 = 0x0c
        {
          kind: "step",
          id: "xor1",
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "split", port: "output2" },
            operand1: { node: "split", port: "output3" },
          },
        },
        {
          kind: "step",
          id: "rejoin",
          type: "concat@1",
          params: { inputCount: 2 },
          portInputs: {
            input0: { node: "xor0", port: "output" },
            input1: { node: "xor1", port: "output" },
          },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: { input: { node: "rejoin", port: "output" } },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0x03, 0x0c]);
  });

  it("off-flag dispatch throws (port-native, no legacy executor)", () => {
    const spec: CipherSpec = {
      id: "toy-split-bytes-offflag",
      name: "off-flag throw",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "src", type: "state-to-bytes@1", params: {} },
        {
          kind: "step",
          id: "split",
          type: "split-bytes@1",
          params: { widths: [2, 2] },
          portInputs: { input: { node: "src", port: "output" } },
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array([0x01, 0x02, 0x03, 0x04]) },
      }),
    ).toThrow(/port-native; requires portedDispatchEnabled: true/);
  });
});
