/**
 * Tests for `src/core/spec-shapes.ts` — the static state-shape walker
 * that powers (a) drop-anchor greying in the graph view, (b) the
 * pre-Run `state-shape-mismatch` warning kind.
 *
 * Test classes:
 *
 *   - **Zero-false-positives baseline.** Every shipped CipherSpec, fed
 *     through `validateShapes`, must produce ZERO warnings. If a future
 *     refactor accidentally introduces a `shapeContract` mismatch in a
 *     hand-written spec, this test is the canary.
 *
 *   - **Headline mismatch repro.** The exact scenario from the user's
 *     report: drag `generic.compute-block-count@1` into the middle of an
 *     AES round body (where state is matrix4x4-bytes). The walker should
 *     emit exactly one `state-shape-mismatch` warning naming the
 *     dropped leaf with `expected: "bytes"`, `got: "matrix4x4-bytes"`.
 *
 *   - **`inferShapesAtAnchors` shape-map.** A small spec with a
 *     shape-changing leaf (`generic.load-block@1`: bytes → matrix)
 *     produces the expected shape both BEFORE and AFTER the boundary.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { inferShapesAtAnchors, validateShapes } from "@/core/spec-shapes";
import type { CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

describe("validateShapes — zero false positives on shipped specs", () => {
  // Each shipped spec was hand-written to type-check its state shape
  // through every step. The walker should agree.

  it("AES-128 encrypt", () => {
    expect(validateShapes(aes128Spec, registry)).toEqual([]);
  });

  it("AES-128 decrypt", () => {
    expect(validateShapes(aes128DecryptSpec, registry)).toEqual([]);
  });

  it("AES-128 ECB (with iterate primitive)", () => {
    // The riskiest case: state is bytes → bytes (load-block→matrix
    // inside the iterate body) → bytes (concat-blocks→bytes after the
    // iterate). If iterate scope handling were wrong, concat-blocks
    // would be flagged because its input contract is matrix4x4-bytes.
    expect(validateShapes(aes128EcbSpec, registry)).toEqual([]);
  });

  it("AES-192 encrypt", () => {
    expect(validateShapes(aes192Spec, registry)).toEqual([]);
  });

  it("AES-256 encrypt", () => {
    expect(validateShapes(aes256Spec, registry)).toEqual([]);
  });

  it("Speck32/64 (BE)", () => {
    expect(validateShapes(speck32_64BeSpec, registry)).toEqual([]);
  });

  it("Serpent-128", () => {
    expect(validateShapes(serpent128Spec, registry)).toEqual([]);
  });
});

describe("validateShapes — headline mismatch repro", () => {
  // Reproduces the user's reported bug: a `compute-block-count` leaf
  // inserted into a position where state has already become
  // matrix4x4-bytes. The walker should emit exactly one warning naming
  // that leaf with the right expected/got pair.

  it("flags compute-block-count inserted after the load-block boundary", () => {
    // Synthesize a tiny spec resembling the post-drop AES state: the
    // first step converts bytes → matrix, then we inject a stray
    // bytes-input step. The walker should flag the second leaf.
    const badSpec: CipherSpec = {
      id: "test-bad-shape@1",
      name: "Bad Shape Test",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        // Bytes → matrix (legal at the start).
        {
          kind: "step",
          id: "load",
          type: "generic.load-block@1",
          params: { blockSize: 16 },
        },
        // Bytes-input step landed in a matrix-state position. SHOULD
        // flag.
        {
          kind: "step",
          id: "bad-bcc",
          type: "generic.compute-block-count@1",
          params: { blockSize: 16, countAux: "blockCount" },
        },
      ] satisfies readonly StepNode[],
    };
    const warnings = validateShapes(badSpec, registry);
    expect(warnings).toHaveLength(1);
    const w = warnings[0];
    expect(w).toBeDefined();
    if (!w) throw new Error("unreachable");
    expect(w.kind).toBe("state-shape-mismatch");
    if (w.kind !== "state-shape-mismatch") throw new Error("unreachable");
    expect(w.stepId).toBe("bad-bcc");
    expect(w.expected).toBe("bytes");
    expect(w.got).toBe("matrix4x4-bytes");
  });

  it("flags a matrix-input step landed where state is still bytes", () => {
    // The inverse: an AES round step inserted at the root of a
    // bytes-input spec, before any load-block. Realistically what
    // happens when the user drops `sub-bytes` into the empty area
    // above the rounds.
    const badSpec: CipherSpec = {
      id: "test-bad-shape-2@1",
      name: "Bad Shape Test 2",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        {
          kind: "step",
          id: "stray-sub-bytes",
          type: "generic.byte-substitution@1",
          // SBox value doesn't matter — the walker stops at the shape
          // mismatch before any executor runs.
          params: { sbox: Array.from({ length: 256 }, (_, i) => i) },
        },
      ] satisfies readonly StepNode[],
    };
    const warnings = validateShapes(badSpec, registry);
    expect(warnings).toHaveLength(1);
    const w = warnings[0];
    expect(w).toBeDefined();
    if (!w) throw new Error("unreachable");
    if (w.kind !== "state-shape-mismatch") throw new Error("unreachable");
    expect(w.stepId).toBe("stray-sub-bytes");
    expect(w.expected).toBe("matrix4x4-bytes");
    expect(w.got).toBe("bytes");
  });
});

describe("inferShapesAtAnchors", () => {
  it("threads bytes → matrix → bytes through the load/store boundary", () => {
    // Hand-crafted spec exercising both shape-changing boundary steps in
    // sequence. Each leaf id gets a shape-after entry.
    const spec: CipherSpec = {
      id: "test-load-store@1",
      name: "Load/Store Test",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        { kind: "step", id: "load", type: "generic.load-block@1", params: { blockSize: 16 } },
        {
          kind: "step",
          id: "shift",
          type: "generic.shift-rows@1",
          params: { shifts: [0, 1, 2, 3] },
        },
        { kind: "step", id: "store", type: "generic.store-block@1", params: {} },
      ],
    };
    const map = inferShapesAtAnchors(spec, registry);
    // After load-block: bytes → matrix.
    expect(map.get("load")).toBe("matrix4x4-bytes");
    // shift-rows is matrix → matrix (preserveInput).
    expect(map.get("shift")).toBe("matrix4x4-bytes");
    // After store-block: matrix → bytes.
    expect(map.get("store")).toBe("bytes");
  });

  it("records matrix4x4-bytes on every leaf inside an AES round group", () => {
    // The shipped AES-128 spec is the cleanest existing example: every
    // round step is matrix4x4-bytes (preserveInput), and the spec
    // starts in matrix (inputs.plaintext.shape).
    const map = inferShapesAtAnchors(aes128Spec, registry);
    // Pick a leaf known to be inside a round (id format: "round.N.sub-bytes").
    const roundLeaf = aes128Spec.steps.flatMap((n) =>
      n.kind === "group" ? n.children.filter((c) => c.kind === "step").map((c) => c.id) : [],
    )[0];
    expect(roundLeaf).toBeDefined();
    if (!roundLeaf) throw new Error("unreachable");
    expect(map.get(roundLeaf)).toBe("matrix4x4-bytes");
  });

  it("leaves the iterate's exit shape at matrix4x4-bytes for ECB", () => {
    // The iterate's id maps to matrix4x4-bytes (last block's state), and
    // the subsequent concat-blocks leaf maps to bytes (matrix→bytes).
    const map = inferShapesAtAnchors(aes128EcbSpec, registry);
    // Find the iterate node id.
    const iterId = aes128EcbSpec.steps.find((n) => n.kind === "iterate")?.id;
    expect(iterId).toBeDefined();
    if (!iterId) throw new Error("unreachable");
    expect(map.get(iterId)).toBe("matrix4x4-bytes");
    // The concat-blocks leaf following it should map to bytes.
    const concatId = aes128EcbSpec.steps.find(
      (n) => n.kind === "step" && n.type === "generic.concat-blocks@1",
    )?.id;
    expect(concatId).toBeDefined();
    if (!concatId) throw new Error("unreachable");
    expect(map.get(concatId)).toBe("bytes");
  });
});

describe("validateShapes — A2 container port-binding resolution", () => {
  // A FES-with-history declaring `seedInput` (same-scope preceding sibling)
  // and `bodyOutput` (direct body child). The validator reuses the
  // `port-input-unresolvable` warning so an unresolvable reference surfaces
  // pre-Run; `portName` carries the field name ("seedInput"/"bodyOutput").
  const buildSpec = (overrides?: {
    readonly seedInput?: { readonly node: string; readonly port: string };
    readonly bodyOutput?: { readonly node: string; readonly port: string };
  }): CipherSpec => ({
    id: "test-a2-bindings@1",
    name: "A2 binding resolution",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      { kind: "step", id: "producer", type: "constant-load@1", params: { bytes: [0x00, 0x01] } },
      {
        kind: "for-each-subgraph-with-history",
        id: "loop",
        iterationCount: 2,
        lookbackOffsets: [1, 2],
        historyEntryByteLength: 1,
        seedInput: overrides?.seedInput ?? { node: "producer", port: "output" },
        bodyOutput: overrides?.bodyOutput ?? { node: "xor-priors", port: "output" },
        children: [
          {
            kind: "step",
            id: "p1",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-1", byteLength: 1 },
          },
          {
            kind: "step",
            id: "p2",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-2", byteLength: 1 },
          },
          {
            kind: "step",
            id: "xor-priors",
            type: "xor@1",
            params: { inputCount: 2 },
            portInputs: {
              operand0: { node: "p1", port: "output" },
              operand1: { node: "p2", port: "output" },
            },
          },
        ],
      },
    ] satisfies readonly StepNode[],
  });

  const bindingWarnings = (spec: CipherSpec) =>
    validateShapes(spec, registry).filter(
      (w) =>
        w.kind === "port-input-unresolvable" &&
        (w.portName === "seedInput" || w.portName === "bodyOutput"),
    );

  it("flags seedInput referencing a nonexistent node (missing-node)", () => {
    const warnings = validateShapes(
      buildSpec({ seedInput: { node: "nope", port: "output" } }),
      registry,
    );
    expect(warnings).toContainEqual({
      kind: "port-input-unresolvable",
      stepId: "loop",
      portName: "seedInput",
      targetNode: "nope",
      targetPort: "output",
      reason: "missing-node",
    });
  });

  it("flags seedInput referencing a real node but wrong port (missing-port)", () => {
    const warnings = validateShapes(
      buildSpec({ seedInput: { node: "producer", port: "result" } }),
      registry,
    );
    expect(warnings).toContainEqual({
      kind: "port-input-unresolvable",
      stepId: "loop",
      portName: "seedInput",
      targetNode: "producer",
      targetPort: "result",
      reason: "missing-port",
    });
  });

  it("flags bodyOutput referencing a node outside the body's direct children (missing-node)", () => {
    // `producer` is a top-level sibling, not a direct child of the body.
    const warnings = validateShapes(
      buildSpec({ bodyOutput: { node: "producer", port: "output" } }),
      registry,
    );
    expect(warnings).toContainEqual({
      kind: "port-input-unresolvable",
      stepId: "loop",
      portName: "bodyOutput",
      targetNode: "producer",
      targetPort: "output",
      reason: "missing-node",
    });
  });

  it("emits no seedInput/bodyOutput warning when both bindings resolve", () => {
    expect(bindingWarnings(buildSpec())).toEqual([]);
  });
});

describe("validateShapes — A3b group seedInput/bodyOutput self-reference + grandchild guards", () => {
  // ⓐ regression. A `group` whose `seedInput` references its OWN output
  // (`port("<self>","out")`) must warn pre-Run. The runtime throws on this at
  // run, but the walker's `recordContainerOutputs()` records the group's own
  // `out` into the scope map BEFORE the seedInput binding is validated — so
  // without the explicit self-reference guard in `validateContainerBinding`
  // the validator finds the freshly-recorded own output and stays silent. That
  // silent-validator/loud-runtime split is the exact divergence class this
  // plan exists to prevent. This test was RED before the guard landed.
  it("flags a group seedInput that references its own output (self-reference)", () => {
    const selfRefSpec: CipherSpec = {
      id: "test-group-selfref-seed@1",
      name: "group self-ref seedInput",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "producer", type: "constant-load@1", params: { bytes: [0x00] } },
        {
          kind: "group",
          id: "g",
          label: "G",
          // Self-reference: a container's own `out` is published only on
          // exit, so it can never seed itself.
          seedInput: { node: "g", port: "out" },
          children: [
            {
              kind: "step",
              id: "g.leaf",
              type: "not@1",
              params: {},
              portInputs: { input: { node: "g", port: "in" } },
            },
          ],
        },
      ] satisfies readonly StepNode[],
    };
    expect(validateShapes(selfRefSpec, registry)).toContainEqual({
      kind: "port-input-unresolvable",
      stepId: "g",
      portName: "seedInput",
      targetNode: "g",
      targetPort: "out",
      reason: "missing-node",
    });
  });

  // ⓔ (validator half — runtime half lives in
  // tests/runtime-for-each-subgraph-with-history.test.ts). `bodyOutput` must
  // name a DIRECT child of the body. A grandchild (a leaf nested inside a
  // child group) is absent from `collectDirectChildOutputs`'s non-recursing
  // scope, so it warns. This pins the direct-only contract against a future
  // "recurse into nested groups" change to that helper — which would silently
  // start accepting a grandchild that the runtime still throws on (the same
  // validator/runtime divergence as the self-ref case above). Green today.
  it("flags a group bodyOutput that references a grandchild (nested) node", () => {
    const grandchildSpec: CipherSpec = {
      id: "test-group-bodyoutput-grandchild@1",
      name: "group bodyOutput grandchild",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "producer", type: "constant-load@1", params: { bytes: [0x00] } },
        {
          kind: "group",
          id: "g",
          label: "G",
          seedInput: { node: "producer", port: "output" },
          // `g.inner.leaf` lives inside `g.inner`, one level deeper than g's
          // direct children — not a same-scope body output.
          bodyOutput: { node: "g.inner.leaf", port: "output" },
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
      ] satisfies readonly StepNode[],
    };
    expect(validateShapes(grandchildSpec, registry)).toContainEqual({
      kind: "port-input-unresolvable",
      stepId: "g",
      portName: "bodyOutput",
      targetNode: "g.inner.leaf",
      targetPort: "output",
      reason: "missing-node",
    });
  });
});
