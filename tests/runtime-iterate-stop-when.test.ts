/**
 * The repeat-until loop — the port-mode `iterate`'s `stopWhen` field
 * (`docs/plans/refactored-petting-tide.md`, P4 step 1, 2026-10-18).
 *
 * ML-DSA signing is "try, check, try again": each attempt makes a candidate
 * signature and the loop ends at the first one that passes its four bounds. The
 * number of attempts depends on intermediate values, so it cannot be counted in
 * advance. `stopWhen` names a body port carrying a 1-byte flag; a non-zero byte
 * ends the loop after that iteration. The cap is the ordinary iteration count.
 *
 * This toy is built from shipped primitives only. Its chain is two bytes,
 * `counter ‖ accepted`:
 *
 *     cap    = constant-load (8 zero bytes)  → at most 8 attempts
 *     start  = constant-load [c0, 0]
 *     iterate "attempts" (blockByteLength = 1)
 *         seedInput   ← cap/output
 *         chainInput  ← start/output
 *         body:
 *           split   = split-bytes [1,1] (chain)      → counter, old flag
 *           inc     = increment-counter (counter)    → counter + 1
 *           mask    = constant-load [m]
 *           flag    = and(inc, mask)                 → non-zero ⇔ accepted
 *           pack    = concat(inc, flag)              → the next chain value
 *         chainFeedback ← pack/output
 *         bodyOutput    ← inc/output   (so `out` is one byte per attempt RUN)
 *         stopWhen      ← flag/output
 *         chainOutput   = "result"
 *     harvest = split-bytes [1,1] (attempts/result) → final counter, accepted
 *
 * The chain value differs on every pass (the counter climbs), so "harvested
 * attempt 3" and "harvested attempt 2" are distinguishable. And `accepted`
 * rides OUT of the loop, so "accepted on the last allowed attempt" and "hit
 * the cap without accepting" — both 8 passes — are distinguishable too: the
 * advisor's catch, since a pass count alone cannot tell them apart.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { CipherDocumentSchema } from "@/core/document-schema";
import { collapseGraph, deriveAuxGraph, expandCollapsedIterates } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { validateShapes } from "@/core/spec-shapes";
import { iterateScopeKey } from "@/core/step-id";
import type { BytesState, CipherSpec, IterateGroup, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

type Toy = {
  /** The counter's starting value. */
  readonly start: number;
  /** The bit(s) that mean "accepted" once the counter reaches them. */
  readonly mask: number;
  /** Maximum attempts. */
  readonly cap?: number;
  /** Strip `stopWhen` to show what the loop does without it. */
  readonly noStop?: boolean;
};

const buildToy = ({ start, mask, cap = 8, noStop = false }: Toy): CipherSpec => {
  const iterate: IterateGroup = {
    kind: "iterate",
    id: "attempts",
    label: "Attempts",
    blockByteLength: 1,
    seedInput: { node: "cap", port: "output" },
    chainInput: { node: "start", port: "output" },
    chainFeedback: { node: "pack", port: "output" },
    bodyOutput: { node: "inc", port: "output" },
    chainOutput: "result",
    ...(noStop ? {} : { stopWhen: { node: "flag", port: "output" } }),
    children: [
      {
        kind: "step",
        id: "split",
        type: "split-bytes@1",
        params: { widths: [1, 1] },
        portInputs: { input: { node: "attempts", port: "chain" } },
      },
      {
        kind: "step",
        id: "inc",
        type: "increment-counter@1",
        params: {},
        portInputs: { counter: { node: "split", port: "output0" } },
      },
      { kind: "step", id: "mask", type: "constant-load@1", params: { bytes: [mask] } },
      {
        kind: "step",
        id: "flag",
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: { node: "inc", port: "output" },
          operand1: { node: "mask", port: "output" },
        },
      },
      {
        kind: "step",
        id: "pack",
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: {
          input0: { node: "inc", port: "output" },
          input1: { node: "flag", port: "output" },
        },
      },
    ],
  };
  return {
    id: "toy-iterate-stop-when",
    name: "Repeat-until toy (ML-DSA P4 spike)",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "cap",
        type: "constant-load@1",
        params: { bytes: new Array<number>(cap).fill(0) },
      },
      { kind: "step", id: "start", type: "constant-load@1", params: { bytes: [start, 0] } },
      iterate,
      {
        kind: "step",
        id: "harvest",
        type: "split-bytes@1",
        params: { widths: [1, 1] },
        portInputs: { input: { node: "attempts", port: "result" } },
      },
    ],
    outputFrom: { node: "attempts", port: "result" },
  };
};

const run = (spec: CipherSpec): Trace =>
  runSpec(spec, buildDefaultRegistry(), { initialState: emptyBytes() });

/** Distinct iteration indices the loop actually ran. */
const passes = (trace: Trace): number =>
  new Set(trace.frames.filter((f) => f.path.includes("attempts")).map((f) => f.blockIndex)).size;

/** The harvested `counter ‖ accepted`, read off the sibling split's frame. */
const harvested = (trace: Trace): { counter: number; accepted: number } => {
  const f = trace.frames.find((fr) => fr.stepId === "harvest");
  if (f === undefined) throw new Error("no harvest frame");
  return {
    counter: f.portOutputs?.get("output0")?.[0] ?? -1,
    accepted: f.portOutputs?.get("output1")?.[0] ?? -1,
  };
};

/** The iterate's concatenated `out` (one byte per attempt that ran). */
const outWidth = (trace: Trace): number => {
  // `out` is consumed by nobody here; read it through the frames instead — one
  // `inc` frame per attempt, and `out` concatenates exactly those.
  return trace.frames.filter((f) => f.stepId.startsWith("inc:b")).length;
};

describe("port-mode iterate stopWhen — the repeat-until loop", () => {
  it("stops on the attempt whose flag fires: 3 passes of a cap of 8", () => {
    // counter 1 → 2, 3, 4; mask 0x04 fires at 4, the third attempt.
    const trace = run(buildToy({ start: 1, mask: 0x04 }));
    expect(passes(trace)).toBe(3);
    expect(outWidth(trace)).toBe(3);
    // No frame from a fourth attempt exists at all.
    expect(trace.frames.some((f) => f.stepId.endsWith(":b3"))).toBe(false);
  });

  it("harvests the ACCEPTED attempt's chain, not the one before it", () => {
    // The check runs after `chainFeedback` advances. Checked before it, the
    // harvest would read counter 3 / accepted 0 — attempt 2's chain.
    const trace = run(buildToy({ start: 1, mask: 0x04 }));
    expect(harvested(trace)).toEqual({ counter: 4, accepted: 4 });
    expect(Array.from((trace.finalState as BytesState).bytes)).toEqual([4, 4]);
  });

  it("stops after one pass when the first attempt succeeds", () => {
    const trace = run(buildToy({ start: 3, mask: 0x04 }));
    expect(passes(trace)).toBe(1);
    expect(harvested(trace)).toEqual({ counter: 4, accepted: 4 });
  });

  it("runs to the cap without throwing when no attempt succeeds, and says so", () => {
    // mask 0x80: counters 1..8 never set bit 7.
    const trace = run(buildToy({ start: 0, mask: 0x80 }));
    expect(passes(trace)).toBe(8);
    expect(harvested(trace)).toEqual({ counter: 8, accepted: 0 });
  });

  it("tells 'accepted on the last allowed attempt' apart from 'hit the cap'", () => {
    // Both run 8 passes; only the harvested flag differs.
    const lastGasp = run(buildToy({ start: 0, mask: 0x08 }));
    const capHit = run(buildToy({ start: 0, mask: 0x80 }));
    expect(passes(lastGasp)).toBe(8);
    expect(passes(capHit)).toBe(8);
    expect(harvested(lastGasp).accepted).not.toBe(0);
    expect(harvested(capHit).accepted).toBe(0);
  });

  it("without stopWhen the same body runs every attempt (the field is what stops it)", () => {
    const trace = run(buildToy({ start: 1, mask: 0x04, noStop: true }));
    expect(passes(trace)).toBe(8);
    expect(harvested(trace)).toEqual({ counter: 9, accepted: 0 });
  });

  it("throws on a flag that is not exactly one byte", () => {
    const spec = buildToy({ start: 1, mask: 0x04 });
    const bad: CipherSpec = {
      ...spec,
      steps: spec.steps.map((n) =>
        n.kind === "iterate" ? { ...n, stopWhen: { node: "pack", port: "output" } } : n,
      ),
    };
    expect(() => run(bad)).toThrow(/stopWhen must name a 1-byte flag, got 2 bytes/);
  });

  it("throws on stopWhen in aux mode, which has no body ports", () => {
    const spec: CipherSpec = {
      id: "aux-mode-stop-when",
      name: "aux-mode stopWhen",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "iterate",
          id: "loop",
          countFromAux: "n",
          blocksFromAux: "blocks",
          outBlocksAux: "outs",
          stopWhen: { node: "x", port: "output" },
          children: [],
        },
      ],
    };
    expect(() => run(spec)).toThrow(/stopWhen requires port mode/);
  });
});

describe("stopWhen — every count reader shows the attempts RUN, not the cap", () => {
  it("the badge's per-loop count (App.tsx `blockCounts`) is 3", () => {
    const trace = run(buildToy({ start: 1, mask: 0x04 }));
    let max = -1;
    for (const f of trace.frames) {
      if (f.blockIndex === undefined) continue;
      expect(iterateScopeKey(f.path)).toBe("attempts");
      max = Math.max(max, f.blockIndex);
    }
    expect(max + 1).toBe(3);
  });

  it("the graph's iterate span is 3, and collapsing it draws 3 chips", () => {
    const spec = buildToy({ start: 1, mask: 0x04 });
    const trace = run(spec);
    const graph = deriveAuxGraph(trace, spec);
    const container = graph.containers.find((c) => c.id === "attempts");
    expect(container?.blockSpan).toBe(3);

    const collapsed = new Set(["attempts"]);
    const chips = expandCollapsedIterates(collapseGraph(graph, collapsed), collapsed).nodes.filter(
      (n) => n.blockChipOf === "attempts",
    );
    // A `stopWhen` loop's passes are attempts (`core/iteration-noun.ts`), so the
    // chips say so — and there are three of them, not the cap's worth.
    expect(chips.map((c) => c.label)).toEqual(["attempt 1", "attempt 2", "attempt 3"]);
  });

  it("the static validator accepts the binding and flags a dangling one", () => {
    const registry = buildDefaultRegistry();
    const spec = buildToy({ start: 1, mask: 0x04 });
    expect(validateShapes(spec, registry)).toEqual([]);

    const dangling: CipherSpec = {
      ...spec,
      steps: spec.steps.map((n) =>
        n.kind === "iterate" ? { ...n, stopWhen: { node: "nope", port: "output" } } : n,
      ),
    };
    const warnings = validateShapes(dangling, registry);
    expect(warnings).toContainEqual(
      expect.objectContaining({ stepId: "attempts", portName: "stopWhen", targetNode: "nope" }),
    );
  });
});

describe("stopWhen survives Save/Load and URL-share", () => {
  /** Serialize → validate → parse back, exactly as save-to-file / URL-share does. */
  const roundTrip = (spec: CipherSpec): CipherSpec => {
    const doc = { schemaVersion: 3 as const, algorithm: "ml-kem-768" as const, spec };
    const result = CipherDocumentSchema.safeParse(JSON.parse(JSON.stringify(doc)));
    if (!result.success) throw new Error(`document failed validation: ${result.error.message}`);
    return result.data.spec as unknown as CipherSpec;
  };

  it("the reloaded spec still stops at 3 — behaviour, not just the key", () => {
    // Zod strips undeclared keys. Without the schema entry the reloaded loop
    // runs all 8 attempts and harvests counter 9 — with no error anywhere.
    const reloaded = roundTrip(buildToy({ start: 1, mask: 0x04 }));
    const trace = run(reloaded);
    expect(passes(trace)).toBe(3);
    expect(harvested(trace)).toEqual({ counter: 4, accepted: 4 });
  });
});
