/**
 * Port-provenance node tests (inspector-cell-hover plan, Slice 1, 2026-06-04).
 *
 * Three layers of coverage:
 *
 *  1. **Hand-computed mappings** — each of the 10 exact provenance fns against a
 *     known (params, port-lengths, outCell) → expected `ProvenanceCell[]`.
 *  2. **Value-independence property** — running a fn with two DIFFERENT byte
 *     *value* fillings (same lengths + params) returns the identical cell set.
 *     This is the formal statement of "pure index math, never a value lookup" —
 *     the property that keeps the feature from rotting onto a per-frame snapshot.
 *  3. **Executor perturbation cross-check (the desync guard)** — for each
 *     gather/linear primitive, perturb every input cell of the REAL executor and
 *     assert the provenance set equals the set of cells whose perturbation
 *     changes the output cell. This ties provenance to executor *behaviour*
 *     (it would catch a gather→scatter drift), replacing co-location's eyeball
 *     guard with a behavioural one. `and@1` is value-dependent (AND with a 0 mask
 *     hides a dependency), so its cross-check uses an all-`0xFF`
 *     dependency-transparent operand setup — documented at its case below.
 */

import {
  PROVENANCE_FN_STEP_TYPES,
  type ProvenanceCell,
  lookupProvenance,
} from "@/core/port-provenance";
import type { Json, PortedExecutor, StepContext } from "@/core/types";
import { and } from "@/steps/and";
import { byteSlice } from "@/steps/byte-slice";
import { byteSubstitute } from "@/steps/byte-substitute";
import { concat } from "@/steps/concat";
import { gfMatrixMultiply } from "@/steps/gf-matrix-multiply";
import { not } from "@/steps/not";
import { permute } from "@/steps/permute";
import { splitBytes } from "@/steps/split-bytes";
import { xor } from "@/steps/xor";
import { xorWithAux } from "@/steps/xor-with-aux";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };

/** Deterministic pseudo-random byte fill (avoids importing a RNG; two calls with
 *  different seeds give two distinct value fillings for the independence test). */
const fill = (len: number, seed: number): Uint8Array => {
  const out = new Uint8Array(len);
  let s = seed >>> 0;
  for (let i = 0; i < len; i++) {
    s = (s * 1664525 + 1013904223) >>> 0;
    out[i] = (s >>> 16) & 0xff;
  }
  return out;
};

/** Stringify a ProvenanceCell list to an order-independent `port:index(label)` set. */
const cellKeys = (cells: readonly ProvenanceCell[]): Set<string> =>
  new Set(cells.map((c) => `${c.portName}:${c.cellIndex}${c.label ? `(${c.label})` : ""}`));

const prov = (
  stepType: string,
  params: Json,
  inputs: ReadonlyMap<string, Uint8Array>,
  outPort: string,
  outCellIndex: number,
): readonly ProvenanceCell[] => {
  const fn = lookupProvenance(stepType);
  if (fn === undefined) throw new Error(`no provenance fn for ${stepType}`);
  return fn({ params, portInputs: inputs, portOutputs: new Map(), outPort, outCellIndex });
};

// ─── 1. Hand-computed mappings ──────────────────────────────────────────────

describe("port-provenance — hand-computed mappings", () => {
  it("xor@1: output[i] ← operand0[i] … operand{N-1}[i] (same column)", () => {
    const inputs = new Map([
      ["operand0", new Uint8Array(4)],
      ["operand1", new Uint8Array(4)],
      ["operand2", new Uint8Array(4)],
    ]);
    expect(cellKeys(prov("xor@1", { inputCount: 3 }, inputs, "output", 2))).toEqual(
      new Set(["operand0:2", "operand1:2", "operand2:2"]),
    );
  });

  it("and@1: same column mapping as xor (shared fn)", () => {
    const inputs = new Map([
      ["operand0", new Uint8Array(2)],
      ["operand1", new Uint8Array(2)],
    ]);
    expect(cellKeys(prov("and@1", { inputCount: 2 }, inputs, "output", 1))).toEqual(
      new Set(["operand0:1", "operand1:1"]),
    );
  });

  it("not@1: output[i] ← input[i]", () => {
    const inputs = new Map([["input", new Uint8Array(4)]]);
    expect(cellKeys(prov("not@1", {}, inputs, "output", 3))).toEqual(new Set(["input:3"]));
  });

  it("byte-substitute@1: output[i] ← input[i] (S-box swap preserves position)", () => {
    const inputs = new Map([["input", new Uint8Array(16)]]);
    const sbox = Array.from({ length: 256 }, (_, i) => (i + 1) & 0xff);
    expect(cellKeys(prov("byte-substitute@1", { sbox }, inputs, "output", 7))).toEqual(
      new Set(["input:7"]),
    );
  });

  it("xor-with-aux@1: output[i] ← input[i], operand[i] (AddRoundKey)", () => {
    const inputs = new Map([
      ["input", new Uint8Array(16)],
      ["operand", new Uint8Array(16)],
    ]);
    expect(
      cellKeys(prov("xor-with-aux@1", { auxName: "roundKey.1" }, inputs, "output", 5)),
    ).toEqual(new Set(["input:5", "operand:5"]));
  });

  it("xor-with-aux@1 half-wired: operand port absent ⇒ only {input,i} (no phantom)", () => {
    const inputs = new Map([["input", new Uint8Array(16)]]); // operand missing (auxReadMissing)
    expect(cellKeys(prov("xor-with-aux@1", { auxName: "" }, inputs, "output", 5))).toEqual(
      new Set(["input:5"]),
    );
  });

  it("permute@1: output[i] ← input[indices[i]] (forward gather)", () => {
    const inputs = new Map([["input", new Uint8Array(4)]]);
    const indices = [3, 1, 2, 0];
    expect(cellKeys(prov("permute@1", { indices }, inputs, "output", 0))).toEqual(
      new Set(["input:3"]),
    );
    expect(cellKeys(prov("permute@1", { indices }, inputs, "output", 3))).toEqual(
      new Set(["input:0"]),
    );
  });

  it("concat@1: output global index maps into the covering input port", () => {
    const inputs = new Map([
      ["input0", new Uint8Array(2)],
      ["input1", new Uint8Array(3)],
    ]);
    // input0 covers global 0..1, input1 covers global 2..4.
    expect(cellKeys(prov("concat@1", { inputCount: 2 }, inputs, "output", 1))).toEqual(
      new Set(["input0:1"]),
    );
    expect(cellKeys(prov("concat@1", { inputCount: 2 }, inputs, "output", 2))).toEqual(
      new Set(["input1:0"]),
    );
    expect(cellKeys(prov("concat@1", { inputCount: 2 }, inputs, "output", 4))).toEqual(
      new Set(["input1:2"]),
    );
  });

  it("split-bytes@1: output{k}[j] ← input[(Σ widths<k) + j]", () => {
    const inputs = new Map([["input", new Uint8Array(5)]]);
    const widths = [2, 3];
    expect(cellKeys(prov("split-bytes@1", { widths }, inputs, "output0", 1))).toEqual(
      new Set(["input:1"]),
    );
    expect(cellKeys(prov("split-bytes@1", { widths }, inputs, "output1", 0))).toEqual(
      new Set(["input:2"]),
    );
    expect(cellKeys(prov("split-bytes@1", { widths }, inputs, "output1", 2))).toEqual(
      new Set(["input:4"]),
    );
  });

  it("byte-slice@1: output[i] ← input[offset + i]", () => {
    const inputs = new Map([["input", new Uint8Array(256)]]);
    const params = { sourceByteLength: 256, offset: 20, length: 4 };
    expect(cellKeys(prov("byte-slice@1", params, inputs, "output", 0))).toEqual(
      new Set(["input:20"]),
    );
    expect(cellKeys(prov("byte-slice@1", params, inputs, "output", 3))).toEqual(
      new Set(["input:23"]),
    );
  });

  it("gf-matrix-multiply@1 (AES matrix): out[r+4c] ← 4 same-column cells with GF labels", () => {
    const inputs = new Map([["input", new Uint8Array(16)]]);
    const matrix = [
      [2, 3, 1, 1],
      [1, 2, 3, 1],
      [1, 1, 2, 3],
      [3, 1, 1, 2],
    ];
    // Output cell 5 ⇒ column c=1, row r=1; row1 coeffs [1,2,3,1] over input {4,5,6,7}.
    expect(cellKeys(prov("gf-matrix-multiply@1", { matrix }, inputs, "output", 5))).toEqual(
      new Set(["input:4(×1)", "input:5(×2)", "input:6(×3)", "input:7(×1)"]),
    );
  });

  it("gf-matrix-multiply@1 (identity): ONE source, not four (zero-coeff skip)", () => {
    const inputs = new Map([["input", new Uint8Array(16)]]);
    const matrix = [
      [1, 0, 0, 0],
      [0, 1, 0, 0],
      [0, 0, 1, 0],
      [0, 0, 0, 1],
    ];
    // The "swap in the identity matrix and watch diffusion collapse" pedagogy:
    // output cell 5 (c=1,r=1) ← only input 5 (the diagonal), labelled ×1.
    const cells = prov("gf-matrix-multiply@1", { matrix }, inputs, "output", 5);
    expect(cells.length).toBe(1);
    expect(cellKeys(cells)).toEqual(new Set(["input:5(×1)"]));
  });
});

// ─── 2. Value-independence property ─────────────────────────────────────────

describe("port-provenance — value independence (pure index math)", () => {
  // Each case: stepType, params, input port lengths, an outPort + outCell to probe.
  const cases: {
    name: string;
    stepType: string;
    params: Json;
    ports: readonly [string, number][];
    outPort: string;
    outCell: number;
  }[] = [
    {
      name: "xor@1",
      stepType: "xor@1",
      params: { inputCount: 3 },
      ports: [
        ["operand0", 4],
        ["operand1", 4],
        ["operand2", 4],
      ],
      outPort: "output",
      outCell: 2,
    },
    {
      name: "and@1",
      stepType: "and@1",
      params: { inputCount: 2 },
      ports: [
        ["operand0", 4],
        ["operand1", 4],
      ],
      outPort: "output",
      outCell: 1,
    },
    {
      name: "not@1",
      stepType: "not@1",
      params: {},
      ports: [["input", 4]],
      outPort: "output",
      outCell: 3,
    },
    {
      name: "byte-substitute@1",
      stepType: "byte-substitute@1",
      params: { sbox: Array.from({ length: 256 }, (_, i) => (i + 1) & 0xff) },
      ports: [["input", 16]],
      outPort: "output",
      outCell: 9,
    },
    {
      name: "xor-with-aux@1",
      stepType: "xor-with-aux@1",
      params: { auxName: "roundKey.1" },
      ports: [
        ["input", 16],
        ["operand", 16],
      ],
      outPort: "output",
      outCell: 5,
    },
    {
      name: "permute@1",
      stepType: "permute@1",
      params: { indices: [3, 1, 2, 0] },
      ports: [["input", 4]],
      outPort: "output",
      outCell: 0,
    },
    {
      name: "concat@1",
      stepType: "concat@1",
      params: { inputCount: 2 },
      ports: [
        ["input0", 2],
        ["input1", 3],
      ],
      outPort: "output",
      outCell: 3,
    },
    {
      name: "split-bytes@1",
      stepType: "split-bytes@1",
      params: { widths: [2, 3] },
      ports: [["input", 5]],
      outPort: "output1",
      outCell: 1,
    },
    {
      name: "byte-slice@1",
      stepType: "byte-slice@1",
      params: { sourceByteLength: 256, offset: 20, length: 4 },
      ports: [["input", 256]],
      outPort: "output",
      outCell: 2,
    },
    {
      name: "gf-matrix-multiply@1",
      stepType: "gf-matrix-multiply@1",
      params: {
        matrix: [
          [2, 3, 1, 1],
          [1, 2, 3, 1],
          [1, 1, 2, 3],
          [3, 1, 1, 2],
        ],
      },
      ports: [["input", 16]],
      outPort: "output",
      outCell: 5,
    },
  ];

  for (const c of cases) {
    it(`${c.name}: shuffling input byte values leaves the cell set unchanged`, () => {
      const a = new Map(c.ports.map(([n, len], k) => [n, fill(len, 1000 + k)]));
      const b = new Map(c.ports.map(([n, len], k) => [n, fill(len, 9000 + k)]));
      const ka = cellKeys(prov(c.stepType, c.params, a, c.outPort, c.outCell));
      const kb = cellKeys(prov(c.stepType, c.params, b, c.outPort, c.outCell));
      expect(ka).toEqual(kb);
    });
  }
});

// ─── 3. Executor perturbation cross-check (desync guard) ─────────────────────

/**
 * Brute-force the TRUE data-dependency set of one output cell: perturb every
 * input cell of the real executor and record which ones change the output. The
 * provenance fn must return exactly this set (modulo labels). This is what ties
 * the index math to executor behaviour.
 */
const dependencySet = (
  exec: PortedExecutor,
  params: Json,
  inputs: ReadonlyMap<string, Uint8Array>,
  outPort: string,
  outCell: number,
): Set<string> => {
  const base = exec(inputs, params, ctx).get(outPort);
  if (base === undefined) throw new Error(`executor produced no ${outPort}`);
  const baseVal = base[outCell];
  const deps = new Set<string>();
  for (const [name, bytes] of inputs) {
    for (let j = 0; j < bytes.length; j++) {
      const clone = new Map<string, Uint8Array>();
      for (const [n2, b2] of inputs) clone.set(n2, b2.slice());
      const arr = clone.get(name);
      if (arr === undefined) continue;
      const orig = arr[j];
      if (orig === undefined) continue;
      arr[j] = orig ^ 0xff;
      const out = exec(clone, params, ctx).get(outPort);
      if (out !== undefined && out[outCell] !== baseVal) deps.add(`${name}:${j}`);
    }
  }
  return deps;
};

describe("port-provenance — executor perturbation cross-check", () => {
  const sbox = Array.from({ length: 256 }, (_, i) => (i + 1) & 0xff); // a bijection
  const aesMatrix = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
  ];

  // Each case wires the REAL executor + a (params, inputs) fixture chosen so that
  // every structural contributor is also a genuine data dependency. `and@1` uses
  // all-0xFF operands (AND-transparent): with a 0 mask, AND would hide a real
  // structural dependency and the cross-check would (correctly) under-report.
  const cases: {
    name: string;
    stepType: string;
    exec: PortedExecutor;
    params: Json;
    inputs: ReadonlyMap<string, Uint8Array>;
    outPorts: readonly string[];
  }[] = [
    {
      name: "xor@1",
      stepType: "xor@1",
      exec: xor,
      params: { inputCount: 3 },
      inputs: new Map([
        ["operand0", fill(4, 1)],
        ["operand1", fill(4, 2)],
        ["operand2", fill(4, 3)],
      ]),
      outPorts: ["output"],
    },
    {
      name: "and@1",
      stepType: "and@1",
      exec: and,
      params: { inputCount: 2 },
      inputs: new Map([
        ["operand0", new Uint8Array(4).fill(0xff)],
        ["operand1", new Uint8Array(4).fill(0xff)],
      ]),
      outPorts: ["output"],
    },
    {
      name: "not@1",
      stepType: "not@1",
      exec: not,
      params: {},
      inputs: new Map([["input", fill(4, 4)]]),
      outPorts: ["output"],
    },
    {
      name: "byte-substitute@1",
      stepType: "byte-substitute@1",
      exec: byteSubstitute,
      params: { sbox },
      inputs: new Map([["input", fill(16, 5)]]),
      outPorts: ["output"],
    },
    {
      name: "xor-with-aux@1",
      stepType: "xor-with-aux@1",
      exec: xorWithAux,
      params: { auxName: "k" },
      inputs: new Map([
        ["input", fill(16, 6)],
        ["operand", fill(16, 7)],
      ]),
      outPorts: ["output"],
    },
    {
      name: "permute@1",
      stepType: "permute@1",
      exec: permute,
      params: { indices: [3, 1, 2, 0] },
      inputs: new Map([["input", fill(4, 8)]]),
      outPorts: ["output"],
    },
    {
      name: "concat@1",
      stepType: "concat@1",
      exec: concat,
      params: { inputCount: 2 },
      inputs: new Map([
        ["input0", fill(2, 9)],
        ["input1", fill(3, 10)],
      ]),
      outPorts: ["output"],
    },
    {
      name: "split-bytes@1",
      stepType: "split-bytes@1",
      exec: splitBytes,
      params: { widths: [2, 3] },
      inputs: new Map([["input", fill(5, 11)]]),
      outPorts: ["output0", "output1"],
    },
    {
      name: "byte-slice@1",
      stepType: "byte-slice@1",
      exec: byteSlice,
      params: { sourceByteLength: 8, offset: 3, length: 4 },
      inputs: new Map([["input", fill(8, 12)]]),
      outPorts: ["output"],
    },
    {
      name: "gf-matrix-multiply@1",
      stepType: "gf-matrix-multiply@1",
      exec: gfMatrixMultiply,
      params: { matrix: aesMatrix },
      inputs: new Map([["input", fill(16, 13)]]),
      outPorts: ["output"],
    },
  ];

  for (const c of cases) {
    it(`${c.name}: provenance set == executor data-dependency set, every output cell`, () => {
      for (const outPort of c.outPorts) {
        const out = c.exec(c.inputs, c.params, ctx).get(outPort);
        if (out === undefined) throw new Error(`no ${outPort}`);
        for (let i = 0; i < out.length; i++) {
          const truth = dependencySet(c.exec, c.params, c.inputs, outPort, i);
          const claimed = new Set(
            prov(c.stepType, c.params, c.inputs, outPort, i).map(
              (cell) => `${cell.portName}:${cell.cellIndex}`,
            ),
          );
          expect(claimed, `${c.name} ${outPort}[${i}]`).toEqual(truth);
        }
      }
    });
  }
});

// ─── Sanity: the fn registry is the 10 exact mappings ────────────────────────

describe("port-provenance — registry shape", () => {
  it("registers exactly the 11 exact-mapping step types", () => {
    expect(PROVENANCE_FN_STEP_TYPES).toEqual(
      new Set([
        "xor@1",
        "and@1",
        "not@1",
        "xor-with-aux@1",
        "byte-substitute@1",
        "permute@1",
        "concat@1",
        "split-bytes@1",
        "byte-slice@1",
        "gf-matrix-multiply@1",
        // @2 (Twofish MDS) reuses @1's index-only provenance fn.
        "gf-matrix-multiply@2",
      ]),
    );
  });

  it("returns undefined for an allowlisted (approximate) primitive", () => {
    expect(lookupProvenance("add-mod-32@1")).toBeUndefined();
    expect(lookupProvenance("rotate-bits-right@1")).toBeUndefined();
  });
});
