/**
 * Slice 1.12 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`). Closes Phase 1.
 *
 * Pins Q2 of the parent plan (`docs/plans/universal-port-dataflow.md`):
 * "Warn-and-run, deterministic coercion. Right-pad with zeros to target
 * length when source is shorter; truncate from the right when source is
 * longer. Coercion appears as a visible trace step."
 *
 * Surfacing mechanism (user pick 2026-05-24): synthetic `__coerce__`
 * trace frame per affected input port, emitted BEFORE the consumer leaf.
 * Same shape pattern as `__rejoin__` — runtime-synthesized stepType,
 * never registered with an executor, surfaces in the linear scrubber
 * via the existing frame iteration + a registered narrator
 * (`src/ui/narration/coerce.tsx`).
 *
 * Five test surfaces:
 *
 *   (a) **Right-pad coercion** — source 8 bytes → port declares 16 →
 *       padded to 16 with 8 trailing zeros. Synthetic frame emitted.
 *
 *   (b) **Truncate-from-right coercion** — source 8 bytes → port
 *       declares 4 → keeps first 4 bytes, discards last 4. Synthetic
 *       frame emitted.
 *
 *   (c) **Multiple ports coerced on one leaf** — both above mismatches
 *       on the same leaf emit TWO synthetic frames in declaration order
 *       of `meta.auxReadPorts`, followed by the consumer leaf frame.
 *
 *   (d) **Absent byteLength opts out** — polymorphic port (byteLength
 *       absent per the Slice 1.2 user pick "absent means wiring-
 *       determined") never coerces, no synthetic frame, regardless of
 *       source byte count.
 *
 *   (e) **Exact length match is a no-op** — when source.length matches
 *       port.byteLength, NO synthetic frame emits. The runtime's `===`
 *       short-circuit means a shipped spec with matched declarations
 *       adds zero frames to its trace.
 *
 * **Frame-parity intentionally NOT tested here** — coercion is
 * flag-on-only by design (the legacy path has no byteLength check).
 * Frame-count divergence between the two paths on these fixtures is
 * the FEATURE under test; comparing them would defeat the surface.
 * The shipped-spec frame-parity gate lives in Slice 1.11's matrix
 * (`tests/runtime-ported-dispatch-frame-parity.test.ts`), which runs
 * on real ciphers whose declared byteLengths match by construction.
 *
 * **Why a synthetic step type, not a real one** — real shipped ports
 * have matched byteLengths (pinned by the per-cipher frame-parity
 * tests). To exercise coercion at all, we need a deliberately
 * mismatched fixture. Authoring it as a test-local synthetic step
 * type registered inline keeps the mismatch out of `default-registry`
 * (where it could poison a real cipher's parity gate) and keeps the
 * test self-contained.
 */

import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type {
  AuxValue,
  CipherSpec,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Shared test-local step type infrastructure ─────────────────────────

/**
 * Aux-only no-op port-native executor (hybrid-ported: `meta` present, NO
 * `legacy` — the only kind that survives post-5.3e). It emits no output
 * ports; the runtime's coercion check runs AGAINST the declared input ports
 * BEFORE this executor sees anything, so its body never observes coercion.
 *
 * Why a no-op: the test isn't about what the executor does with the bytes —
 * it's about what the runtime emits when a port-length mismatch is detected.
 * Coercion fires on any ported step's declared input ports regardless of
 * `legacy`, so a meta-bearing port-native step exercises it just as the
 * lifted-legacy carrier did pre-5.3e.
 */
const passthroughExecutor: PortedExecutor = () => new Map();

const passthroughDoc: StepDocumentation = {
  name: "Coercion fixture",
  summary: "Test-local aux-only passthrough exercising input-port coercion.",
  detail:
    "Slice 1.12 fixture. Declares aux input ports with intentionally mismatched byteLengths " +
    "to drive the runtime's port-length coercion path. Never registered in the default registry.",
};

/**
 * Build a fresh registry with ONE synthetic step type — `test.coerce-fixture@1`.
 *
 * `inputShapes` is the table the test varies per case. `auxReadBindings`
 * pairs each declared input port to an aux key the test pre-populates
 * via `initialAux`. The ProjectionMetadata's `auxReadPorts` returns the
 * same map for every params (the test doesn't exercise params-driven
 * port counts; Slice 1.4 already pinned that pattern via AES
 * key-expansion's 11-port case).
 *
 * Returns the test-local registry. Callers build a synthetic spec with
 * the single leaf `type: "test.coerce-fixture@1"` and pass this
 * registry into `runSpec`.
 */
const buildCoerceRegistry = (
  inputShapes: ReadonlyMap<string, { byteLength?: number; layout?: string }>,
  auxReadBindings: ReadonlyMap<string, string>,
): StepRegistry => {
  const registry = new StepRegistry();
  const shape: PortContract = {
    inputs: inputShapes,
    outputs: new Map(),
  };
  const meta: ProjectionMetadata = {
    stateLayout: "bytes",
    // No stateInputPort / stateOutputPort — aux-only step, same pattern
    // as the Slice-1.2 aux-only primitives (`iv-load`, `aux-load`, etc.).
    // The lift adapter creates a sentinel zero-length state for the
    // legacy executor; the runtime preserves the caller's actual state
    // across the call.
    auxReadPorts: () => auxReadBindings,
    // No auxWritePorts — the synthetic step writes no aux.
  };
  // Hybrid-ported registration: `meta` projects the aux reads into input
  // ports, `executor` is the port-native no-op above, and there is NO
  // `legacy` field (the lifted-legacy path retired in Slice 5.3e). The
  // runtime's coercion check fires on the declared input ports regardless.
  registry.register("test.coerce-fixture@1", {
    kind: "ported",
    executor: passthroughExecutor,
    shape,
    meta,
    doc: passthroughDoc,
  });
  return registry;
};

/**
 * Synthetic spec with a single leaf consuming the fixture step type.
 * State shape `bytes` so the (aux-only) passthrough's sentinel state
 * matches what the legacy adapter creates.
 */
const buildCoerceSpec = (): CipherSpec => ({
  id: "test-coerce-fixture@1",
  name: "Slice 1.12 — coercion fixture",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "consumer",
      type: "test.coerce-fixture@1",
      params: {},
    },
  ],
});

// 8-byte sample source used across the cases. Distinct increasing bytes
// so the truncation case's keep-vs-discard is unambiguous in the assertions.
const SOURCE_8 = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

// ─── (a) Right-pad coercion ─────────────────────────────────────────────

describe("runtime — ported dispatch, Slice 1.12 coercion (Q2)", () => {
  describe("(a) right-pad coercion — source shorter than declared port byteLength", () => {
    it("source 8 bytes, port declares 16 → padded to 16 with 8 trailing zeros", () => {
      const registry = buildCoerceRegistry(
        new Map([["port-a", { byteLength: 16, layout: "raw" }]]),
        new Map([["port-a", "src-a"]]),
      );
      const spec = buildCoerceSpec();
      const trace = runSpec(spec, registry, {
        initialState: makeBytesState(new Uint8Array(0)),
        initialAux: new Map<string, AuxValue>([["src-a", new Uint8Array(SOURCE_8)]]),
        portedDispatchEnabled: true,
      });

      // Frame stream: [__coerce__ for port-a, consumer leaf].
      expect(trace.frames.length).toBe(2);

      const coerceFrame = trace.frames[0];
      const consumerFrame = trace.frames[1];
      if (!coerceFrame || !consumerFrame) throw new Error("missing frames");

      expect(coerceFrame.stepType).toBe("__coerce__");
      expect(coerceFrame.stepId).toBe("consumer:coerce:port-a");
      expect(coerceFrame.params).toEqual({
        portName: "port-a",
        mode: "right-pad",
        sourceLen: 8,
        targetLen: 16,
      });

      // The coerce frame surfaces the morph via its port I/O keyed by
      // `portName` (the `stateBefore`/`stateAfter` State fields retired in
      // Slice 5.3e Batch 4): the input port carries the original 8 bytes, the
      // output port the 16-byte padded result (first 8 = source, last 8 zeros).
      const coercedIn = coerceFrame.portInputs?.get("port-a");
      const coercedOut = coerceFrame.portOutputs?.get("port-a");
      expect(coercedIn).toBeDefined();
      expect(coercedOut).toBeDefined();
      expect(Array.from(coercedIn ?? [])).toEqual(Array.from(SOURCE_8));
      const expectedPadded = new Uint8Array(16);
      expectedPadded.set(SOURCE_8, 0);
      expect(Array.from(coercedOut ?? [])).toEqual(Array.from(expectedPadded));

      // Consumer leaf follows the coerce frame in the same path. Path
      // and blockIndex/branchPath stamping match what a real leaf would
      // carry — sanity check.
      expect(consumerFrame.stepId).toBe("consumer");
      expect(consumerFrame.stepType).toBe("test.coerce-fixture@1");
      expect(consumerFrame.path).toEqual(coerceFrame.path);
    });
  });

  // ─── (b) Truncate-from-right coercion ────────────────────────────────

  describe("(b) truncate-from-right coercion — source longer than declared port byteLength", () => {
    it("source 8 bytes, port declares 4 → keeps first 4, discards last 4", () => {
      const registry = buildCoerceRegistry(
        new Map([["port-b", { byteLength: 4, layout: "raw" }]]),
        new Map([["port-b", "src-b"]]),
      );
      const spec = buildCoerceSpec();
      const trace = runSpec(spec, registry, {
        initialState: makeBytesState(new Uint8Array(0)),
        initialAux: new Map<string, AuxValue>([["src-b", new Uint8Array(SOURCE_8)]]),
        portedDispatchEnabled: true,
      });

      expect(trace.frames.length).toBe(2);
      const coerceFrame = trace.frames[0];
      if (!coerceFrame) throw new Error("missing coerce frame");

      expect(coerceFrame.stepType).toBe("__coerce__");
      expect(coerceFrame.stepId).toBe("consumer:coerce:port-b");
      expect(coerceFrame.params).toEqual({
        portName: "port-b",
        mode: "truncate-right",
        sourceLen: 8,
        targetLen: 4,
      });

      // "Truncate from the right" keeps the LEFTMOST targetLen bytes —
      // Q2 names the discard side, not the keep side. Pin both halves
      // unambiguously: keep = bytes [0..4), discard = bytes [4..8). Read the
      // morph off the output port (the State fields retired in 5.3e Batch 4).
      const coercedOut = coerceFrame.portOutputs?.get("port-b");
      expect(coercedOut).toBeDefined();
      expect(Array.from(coercedOut ?? [])).toEqual([0x01, 0x02, 0x03, 0x04]);
    });
  });

  // ─── (c) Multiple ports on one leaf — emit two synthetic frames ──────

  describe("(c) multiple ports coerced on one leaf", () => {
    it("two declared ports both mismatched → two synthetic frames in declaration order", () => {
      // declaration order: port-a (right-pad), port-b (truncate-right).
      // Map iteration is insertion-ordered in JS — pinned because the
      // runtime walks `meta.auxReadPorts(params)` and emits coerce
      // frames in iteration order. Drift here would surface as a
      // re-ordered frame stream.
      const inputShapes: ReadonlyMap<string, { byteLength?: number; layout?: string }> = new Map([
        ["port-a", { byteLength: 16, layout: "raw" }],
        ["port-b", { byteLength: 4, layout: "raw" }],
      ]);
      const auxBindings: ReadonlyMap<string, string> = new Map([
        ["port-a", "src-a"],
        ["port-b", "src-b"],
      ]);
      const registry = buildCoerceRegistry(inputShapes, auxBindings);
      const spec = buildCoerceSpec();
      const trace = runSpec(spec, registry, {
        initialState: makeBytesState(new Uint8Array(0)),
        initialAux: new Map<string, AuxValue>([
          ["src-a", new Uint8Array(SOURCE_8)],
          ["src-b", new Uint8Array(SOURCE_8)],
        ]),
        portedDispatchEnabled: true,
      });

      // Expected: [coerce port-a, coerce port-b, consumer leaf]
      expect(trace.frames.length).toBe(3);
      const firstCoerce = trace.frames[0];
      const secondCoerce = trace.frames[1];
      const leaf = trace.frames[2];
      if (!firstCoerce || !secondCoerce || !leaf) throw new Error("missing frames");

      expect(firstCoerce.stepType).toBe("__coerce__");
      expect(firstCoerce.stepId).toBe("consumer:coerce:port-a");
      expect((firstCoerce.params as { mode: string }).mode).toBe("right-pad");

      expect(secondCoerce.stepType).toBe("__coerce__");
      expect(secondCoerce.stepId).toBe("consumer:coerce:port-b");
      expect((secondCoerce.params as { mode: string }).mode).toBe("truncate-right");

      expect(leaf.stepId).toBe("consumer");
      expect(leaf.stepType).toBe("test.coerce-fixture@1");

      // Frame indices monotonic across the run — both coerce frames
      // increment `frameIndex` before the consumer leaf.
      expect(firstCoerce.index).toBe(0);
      expect(secondCoerce.index).toBe(1);
      expect(leaf.index).toBe(2);
    });
  });

  // ─── (d) Absent byteLength opts out ──────────────────────────────────

  describe("(d) polymorphic port (byteLength absent) opts out of coercion", () => {
    it("source 8 bytes, port declares NO byteLength → no synthetic frame", () => {
      const registry = buildCoerceRegistry(
        // Port shape with byteLength deliberately absent — matches the
        // Slice 1.2 user pick "absent means wiring-determined" for
        // polymorphic ports (e.g., aux-xor / aux-copy / Speck state).
        new Map([["port-poly", { layout: "raw" }]]),
        new Map([["port-poly", "src-poly"]]),
      );
      const spec = buildCoerceSpec();
      const trace = runSpec(spec, registry, {
        initialState: makeBytesState(new Uint8Array(0)),
        initialAux: new Map<string, AuxValue>([["src-poly", new Uint8Array(SOURCE_8)]]),
        portedDispatchEnabled: true,
      });

      // Frame stream is just the consumer leaf — no coercion fires.
      expect(trace.frames.length).toBe(1);
      const leaf = trace.frames[0];
      if (!leaf) throw new Error("missing leaf");
      expect(leaf.stepType).toBe("test.coerce-fixture@1");
      // Negative pin: confirm no __coerce__ frame anywhere in the trace.
      expect(trace.frames.filter((f) => f.stepType === "__coerce__").length).toBe(0);
    });
  });

  // ─── (e) Exact length match is a no-op ───────────────────────────────

  describe("(e) source length matches declared byteLength — no synthetic frame", () => {
    it("source 8 bytes, port declares 8 → no coerce frame, exact-length short-circuit", () => {
      const registry = buildCoerceRegistry(
        new Map([["port-exact", { byteLength: 8, layout: "raw" }]]),
        new Map([["port-exact", "src-exact"]]),
      );
      const spec = buildCoerceSpec();
      const trace = runSpec(spec, registry, {
        initialState: makeBytesState(new Uint8Array(0)),
        initialAux: new Map<string, AuxValue>([["src-exact", new Uint8Array(SOURCE_8)]]),
        portedDispatchEnabled: true,
      });

      // The runtime's exact-length short-circuit avoids both the
      // synthetic frame emit AND the unnecessary buffer copy. Critical
      // invariant: a shipped spec with matched declarations adds zero
      // frames to its trace — Slice 1.11's frame-parity matrix relies
      // on this.
      expect(trace.frames.length).toBe(1);
      expect(trace.frames.filter((f) => f.stepType === "__coerce__").length).toBe(0);
    });
  });
});
