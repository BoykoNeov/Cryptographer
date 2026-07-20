/**
 * Toy fixture for the port-mode `iterate`'s `allowPartialFinalBlock` —
 * CTR's ragged-tail relaxation (2026-07-20).
 *
 * By default the iterate requires `seedInput.length` to be a whole multiple of
 * `blockByteLength`, because ECB and CBC feed each block THROUGH the cipher and
 * a block cipher has no meaning for a partial block. CTR does not — it XORs
 * the message with keystream — so it opts into `ceil` iteration with a short
 * final `in` block.
 *
 * This toy is deliberately cipher-free: a 4-byte-block iterate whose body is a
 * bare identity passthrough of `port(it,"in")`. That isolates the RUNTIME
 * behaviour (the throw, the iteration count, the short slice, the length-
 * generic concat) from anything CTR or any cipher core does with it. The
 * concatenated output is therefore byte-equal to the input, which makes a
 * dropped or over-long final block immediately visible.
 *
 * The two directions that matter:
 *   • flag ABSENT + ragged seed → throws (ECB/CBC keep their guarantee)
 *   • flag PRESENT + ragged seed → ceil(len/B) iterations, last one short
 *
 * Plus the degenerate case the flag must NOT change: a seed that already
 * divides evenly behaves byte-identically either way, since `ceil` degenerates
 * to exact division.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

/**
 * A 4-byte-block iterate over `bytes`, whose body simply republishes the
 * injected block. `allowPartialFinalBlock` is threaded from the argument so
 * the two branches share one fixture and can't drift apart.
 */
const buildSplitSpec = (bytes: readonly number[], allowPartial: boolean): CipherSpec => ({
  id: `toy-iterate-partial-${allowPartial ? "on" : "off"}`,
  name: "Iterate partial-final-block toy",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    { kind: "step", id: "src", type: "constant-load@1", params: { bytes: [...bytes] } },
    {
      kind: "iterate",
      id: "it",
      label: "Per-block passthrough",
      blockByteLength: 4,
      seedInput: { node: "src", port: "output" },
      bodyOutput: { node: "passthrough", port: "output" },
      ...(allowPartial ? { allowPartialFinalBlock: true } : {}),
      children: [
        {
          // `concat@1` with a single input is the cheapest identity on a port:
          // it republishes exactly the bytes it was handed, whatever the width.
          // Note the port is `input0`, not `operand0` — `concat` numbers its
          // inputs `inputN` while `xor`/`and` use `operandN`.
          kind: "step",
          id: "passthrough",
          type: "concat@1",
          params: { inputCount: 1 },
          portInputs: { input0: { node: "it", port: "in" } },
        },
      ],
    },
  ],
  outputFrom: { node: "it", port: "out" },
});

const runToy = (bytes: readonly number[], allowPartial: boolean): number[] => {
  const trace = runSpec(buildSplitSpec(bytes, allowPartial), buildDefaultRegistry(), {
    initialState: emptyBytes(),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return Array.from(trace.finalState.bytes);
};

/** Per-iteration frame ids for the body leaf (`:b{i}` suffixed). */
const blockFrameIds = (bytes: readonly number[], allowPartial: boolean): string[] => {
  const trace = runSpec(buildSplitSpec(bytes, allowPartial), buildDefaultRegistry(), {
    initialState: emptyBytes(),
  });
  return trace.frames.map((f) => f.stepId).filter((id) => id.startsWith("passthrough:"));
};

// 9 bytes over a 4-byte block = 2 whole blocks + a 1-byte tail.
const RAGGED = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const WHOLE = [1, 2, 3, 4, 5, 6, 7, 8];

describe("port-mode iterate — allowPartialFinalBlock", () => {
  it("WITHOUT the flag, a ragged seed throws (ECB/CBC keep the whole-block guarantee)", () => {
    expect(() => runToy(RAGGED, false)).toThrow(/not a multiple of blockByteLength 4/);
  });

  it("WITH the flag, a ragged seed runs ceil(len/B) iterations", () => {
    // 9 bytes / 4 = 3 iterations, not 2 (floor) and not a throw.
    expect(blockFrameIds(RAGGED, true)).toEqual([
      "passthrough:b0",
      "passthrough:b1",
      "passthrough:b2",
    ]);
  });

  it("WITH the flag, the final iteration receives a SHORT block and the concat stays length-generic", () => {
    // The whole point: 9 bytes in, 9 bytes out. A final block padded up to 4
    // would give 12; a dropped tail would give 8.
    expect(runToy(RAGGED, true)).toEqual(RAGGED);
  });

  it("the short block is the TAIL of the seed, in order (the subarray clamps correctly)", () => {
    // Byte 9 must be the last iteration's sole input — not byte 1, and not a
    // wrapped or zero-filled block.
    const trace = runSpec(buildSplitSpec(RAGGED, true), buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const last = trace.frames.find((f) => f.stepId === "passthrough:b2");
    if (last === undefined) throw new Error("expected a b2 frame");
    expect(Array.from(last.portOutputs?.get("output") ?? [])).toEqual([9]);
  });

  it("a seed that already divides evenly is byte-identical with and without the flag", () => {
    // `ceil` degenerates to exact division, so the flag must be inert here.
    // This is the regression guard for every whole-block CTR vector.
    expect(runToy(WHOLE, true)).toEqual(runToy(WHOLE, false));
    expect(blockFrameIds(WHOLE, true)).toEqual(blockFrameIds(WHOLE, false));
  });

  it("a seed SHORTER than one block yields exactly one short iteration", () => {
    // The headline case for CTR: a whole message smaller than a cipher block,
    // which the unflagged path cannot represent at all.
    expect(runToy([7, 7], true)).toEqual([7, 7]);
    expect(blockFrameIds([7, 7], true)).toEqual(["passthrough:b0"]);
  });
});
