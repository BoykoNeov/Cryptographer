/**
 * Tests for `permute@1` — port-native byte-permutation primitive
 * (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * The byte-native replacement for the matrix-shaped `generic.shift-rows@1`.
 * Coverage:
 *   1. Executor: gather KAT, reversal, the AES forward-ShiftRows index map
 *      applied to a labelled 0..15 block, and a duplicating/dropping map.
 *   2. PortContract is static raw (A4-clean).
 *   3. Param + wiring + range validation.
 *   4. Dispatch-path guards.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { permute, permutePortContract } from "@/steps/permute";
import { describe, expect, it } from "vitest";

const callPermute = (input: readonly number[], indices: readonly number[]): number[] => {
  const inputs = new Map([["input", new Uint8Array(input)]]);
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = permute(inputs, { indices: [...indices] } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("permute: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// AES forward ShiftRows on a column-major 4×4 (shift schedule [0,1,2,3]):
//   indices[r + 4c] = r + 4·((c + shift[r]) mod 4)
const AES_SHIFT_ROWS_INDICES = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

describe("permute@1 — executor (direct invocation)", () => {
  it("gathers output[i] = input[indices[i]]", () => {
    expect(callPermute([10, 20, 30, 40], [2, 0, 3, 1])).toEqual([30, 10, 40, 20]);
  });

  it("reversal", () => {
    expect(callPermute([1, 2, 3, 4], [3, 2, 1, 0])).toEqual([4, 3, 2, 1]);
  });

  it("AES forward ShiftRows permutation on the labelled 0..15 block", () => {
    const block = Array.from({ length: 16 }, (_, i) => i);
    expect(callPermute(block, AES_SHIFT_ROWS_INDICES)).toEqual(AES_SHIFT_ROWS_INDICES);
  });

  it("output length equals indices.length (may differ from input length)", () => {
    expect(callPermute([5, 6, 7, 8], [0, 0, 3])).toEqual([5, 5, 8]);
  });

  it("returns a fresh buffer", () => {
    const inputBytes = new Uint8Array([0xaa, 0xbb]);
    const out = permute(new Map([["input", inputBytes]]), { indices: [1, 0] } as unknown as Json, {
      stepId: "t",
      path: [],
      aux: new Map(),
    }).get("output") as Uint8Array;
    out[0] = 0xff;
    expect(inputBytes[0]).toBe(0xaa);
  });

  describe("validation", () => {
    const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
    it("throws when indices is missing/empty", () => {
      expect(() => permute(new Map([["input", new Uint8Array([0])]]), {} as Json, ctx)).toThrow(
        /indices must be a non-empty array/,
      );
    });
    it("throws on a negative index", () => {
      expect(() =>
        permute(
          new Map([["input", new Uint8Array([0])]]),
          { indices: [-1] } as unknown as Json,
          ctx,
        ),
      ).toThrow(/non-negative integer/);
    });
    it("throws when input is not wired", () => {
      expect(() => permute(new Map(), { indices: [0] } as unknown as Json, ctx)).toThrow(
        /input port "input" is not wired/,
      );
    });
    it("throws on an out-of-range index at run time", () => {
      expect(() =>
        permute(
          new Map([["input", new Uint8Array([1, 2])]]),
          { indices: [0, 5] } as unknown as Json,
          ctx,
        ),
      ).toThrow(/index 5 .* out of range for a 2-byte input/);
    });
  });
});

describe("permute@1 — PortContract is A4-clean (static raw)", () => {
  it("input + output are static raw maps", () => {
    if (typeof permutePortContract.inputs === "function")
      throw new Error("inputs should be static");
    if (typeof permutePortContract.outputs === "function")
      throw new Error("outputs should be static");
    expect(permutePortContract.inputs.get("input")?.layout).toBe("raw");
    expect(permutePortContract.outputs.get("output")?.layout).toBe("raw");
  });
});

describe("permute@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-permute@1",
    name: "test permute",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [{ kind: "step", id: "s", type: "permute@1", params: { indices: [0] } }],
  });

  it("on-flag dispatch with no portInputs throws 'input port input is not wired'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
