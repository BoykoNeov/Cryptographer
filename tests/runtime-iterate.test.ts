/**
 * Tests for the `iterate` loop primitive in `src/core/runtime.ts`.
 *
 * Focuses on the runtime contract: per-iteration stepId `:b{i}` suffix,
 * `blockIndex` frame stamp, aux read/write of the blocks arrays, and
 * graceful error handling for malformed specs. The AES-on-multi-block
 * end-to-end behavior is covered by `tests/aes-128-ecb-kat.test.ts`.
 */

import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, BytesState, CipherSpec, StepDefinition } from "@/core/types";
import { describe, expect, it } from "vitest";

// Tiny "passthrough then write a marker to aux" step. Lets us tell each
// iteration's frame apart in the test without standing up real AES.
const markerStep: StepDefinition = {
  executor: (state, _params, ctx) => {
    const auxWrites = new Map<string, AuxValue>([[`mark@${ctx.stepId}`, 1]]);
    return { state, auxWrites };
  },
};

// Identity-ish step that increments byte 0 of a 16-byte block so each
// iteration produces a distinct output.
const incrementByte0: StepDefinition = {
  executor: (state) => {
    if (state.shape !== "bytes") throw new Error("expects bytes");
    const out = new Uint8Array(state.bytes);
    out[0] = ((out[0] ?? 0) + 1) & 0xff;
    const result: BytesState = { shape: "bytes", bytes: out };
    return { state: result };
  },
};

const buildRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("test.marker@1", markerStep);
  r.register("test.increment@1", incrementByte0);
  return r;
};

const makeBlocks = (count: number): BytesState[] => {
  const blocks: BytesState[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = new Uint8Array(16);
    bytes[0] = i; // distinguishable per-block
    blocks.push({ shape: "bytes", bytes });
  }
  return blocks;
};

const iterateSpec: CipherSpec = {
  id: "test-iterate@1",
  name: "test iterate",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "iterate",
      id: "loop",
      label: "test loop",
      countFromAux: "count",
      blocksFromAux: "in-blocks",
      outBlocksAux: "out-blocks",
      children: [
        { kind: "step", id: "inc", type: "test.increment@1", params: {} },
        { kind: "step", id: "mark", type: "test.marker@1", params: {} },
      ],
    },
  ],
};

const initialBytes: BytesState = { shape: "bytes", bytes: new Uint8Array(0) };

describe("runtime — iterate node", () => {
  it("emits frames for each child step in each iteration with :b{i} suffixed stepIds", () => {
    const blocks = makeBlocks(3);
    const trace = runSpec(iterateSpec, buildRegistry(), {
      initialState: initialBytes,
      initialAux: new Map<string, AuxValue>([
        ["count", 3],
        ["in-blocks", blocks],
      ]),
    });

    // 3 iterations × 2 children = 6 frames.
    expect(trace.frames.length).toBe(6);

    const ids = trace.frames.map((f) => f.stepId);
    expect(ids).toEqual(["inc:b0", "mark:b0", "inc:b1", "mark:b1", "inc:b2", "mark:b2"]);
  });

  it("stamps blockIndex on every frame emitted inside the loop", () => {
    const blocks = makeBlocks(2);
    const trace = runSpec(iterateSpec, buildRegistry(), {
      initialState: initialBytes,
      initialAux: new Map<string, AuxValue>([
        ["count", 2],
        ["in-blocks", blocks],
      ]),
    });

    const indices = trace.frames.map((f) => f.blockIndex);
    expect(indices).toEqual([0, 0, 1, 1]);
  });

  it("accumulates each iteration's final state into aux[outBlocksAux]", () => {
    const blocks = makeBlocks(3);
    const trace = runSpec(iterateSpec, buildRegistry(), {
      initialState: initialBytes,
      initialAux: new Map<string, AuxValue>([
        ["count", 3],
        ["in-blocks", blocks],
      ]),
    });

    const out = trace.finalAux.get("out-blocks");
    expect(Array.isArray(out)).toBe(true);
    const arr = out as readonly BytesState[];
    expect(arr.length).toBe(3);
    // Each block had byte0 = i; increment adds 1; expect byte0 = i+1.
    expect(arr[0]?.bytes[0]).toBe(1);
    expect(arr[1]?.bytes[0]).toBe(2);
    expect(arr[2]?.bytes[0]).toBe(3);
  });

  it("exposes aux['blockIndex'] to executors during iteration i", () => {
    // The marker step writes `mark@inc` regardless of blockIndex, but the
    // runtime sets aux['blockIndex'] before each iteration. A CTR-style
    // step (Phase 3) will rely on this. Verify it's exposed and final.
    const blocks = makeBlocks(4);
    const trace = runSpec(iterateSpec, buildRegistry(), {
      initialState: initialBytes,
      initialAux: new Map<string, AuxValue>([
        ["count", 4],
        ["in-blocks", blocks],
      ]),
    });
    // After all iterations, blockIndex remains at the last value (3).
    expect(trace.finalAux.get("blockIndex")).toBe(3);
  });

  it("handles count = 0 as a no-op (no frames, empty out-blocks)", () => {
    const trace = runSpec(iterateSpec, buildRegistry(), {
      initialState: initialBytes,
      initialAux: new Map<string, AuxValue>([
        ["count", 0],
        ["in-blocks", []],
      ]),
    });
    expect(trace.frames.length).toBe(0);
    const out = trace.finalAux.get("out-blocks");
    expect(Array.isArray(out)).toBe(true);
    expect((out as readonly BytesState[]).length).toBe(0);
  });

  it("throws if aux[countFromAux] is missing or not a number", () => {
    expect(() =>
      runSpec(iterateSpec, buildRegistry(), {
        initialState: initialBytes,
        initialAux: new Map<string, AuxValue>([["in-blocks", []]]),
      }),
    ).toThrow(/aux\["count"\] must be a non-negative integer/);
  });

  it("throws if blocks.length does not match count", () => {
    expect(() =>
      runSpec(iterateSpec, buildRegistry(), {
        initialState: initialBytes,
        initialAux: new Map<string, AuxValue>([
          ["count", 5],
          ["in-blocks", makeBlocks(3)],
        ]),
      }),
    ).toThrow(/length \(3\) does not match.*\(5\)/);
  });
});
