// @vitest-environment jsdom

/**
 * Slice 1.12 follow-up — caveat 3 ("UI plumbed-met, not demonstrated-met")
 * from `docs/plans/universal-port-phase-1-slices.md`.
 *
 * Pins that synthetic `__coerce__` frames emitted by the ported-dispatch
 * runtime (when an input port's source bytes don't match the port's
 * declared `byteLength`) surface as a visible ⚠ badge in the scrubber
 * timeline — parallel to ⇄ for `__rejoin__` frames.
 *
 * Without this surfacing, a learner could land on a coerce frame by
 * scrubbing onto it but would have no visual cue that something
 * interesting lives at that index. The badge is the loud-on-purpose
 * signal that mismatched wiring fired here.
 *
 * Why this test exists: Slice 1.12 closed Phase 1 with the synthetic
 * frame plumbed and the narrator (`src/ui/narration/coerce.tsx`)
 * registered, but no shipped cipher triggers coercion so the UI
 * behavior was never demonstrated end-to-end. This test builds the same
 * mismatched-fixture infrastructure that
 * `tests/runtime-ported-dispatch-coercion.test.ts` uses, drives the
 * trace into the live store, mounts `<TraceTimeline>` exactly as the
 * app does, and asserts the badge renders with the right glyph and
 * position.
 *
 * The companion narrator unit-test (`coerceNarration()` returning the
 * right prose for a given frame) is covered by direct function tests in
 * `tests/runtime-ported-dispatch-coercion.test.ts` and via the
 * narration-registry contract. This file's scope is timeline surfacing.
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
import { TraceTimeline } from "@/ui/components/TraceTimeline";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixture infrastructure (mirrors runtime-ported-dispatch-coercion.test) ──
// Hybrid-ported (meta present, no `legacy`) aux-only no-op: coercion fires on
// its declared input ports regardless of `legacy`. (Pre-5.3e this used the
// lifted-legacy carrier via `liftLegacyExecutor`.)

const passthroughExecutor: PortedExecutor = () => new Map();

const passthroughDoc: StepDocumentation = {
  name: "Coercion timeline fixture",
  summary: "Test-local aux-only passthrough driving the timeline badge surface.",
  detail:
    "Slice 1.12 follow-up. Declares one aux input port with a mismatched byteLength " +
    "so the ported-dispatch runtime emits a synthetic __coerce__ frame; this test " +
    "asserts the scrubber surfaces it as a ⚠ badge.",
};

const buildCoerceRegistry = (
  inputShapes: ReadonlyMap<string, { byteLength?: number; layout?: string }>,
  auxReadBindings: ReadonlyMap<string, string>,
): StepRegistry => {
  const registry = new StepRegistry();
  const shape: PortContract = { inputs: inputShapes, outputs: new Map() };
  const meta: ProjectionMetadata = {
    stateLayout: "bytes",
    auxReadPorts: () => auxReadBindings,
  };
  registry.register("test.coerce-timeline-fixture@1", {
    kind: "ported",
    executor: passthroughExecutor,
    shape,
    meta,
    doc: passthroughDoc,
  });
  return registry;
};

const buildCoerceSpec = (): CipherSpec => ({
  id: "test-coerce-timeline-fixture@1",
  name: "Slice 1.12 follow-up — timeline badge fixture",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "consumer",
      type: "test.coerce-timeline-fixture@1",
      params: {},
    },
  ],
});

const seedCoerceTrace = (
  inputShapes: ReadonlyMap<string, { byteLength?: number; layout?: string }>,
  auxBindings: ReadonlyMap<string, string>,
  initialAux: ReadonlyArray<readonly [string, Uint8Array]>,
) => {
  const registry = buildCoerceRegistry(inputShapes, auxBindings);
  const spec = buildCoerceSpec();
  const trace = runSpec(spec, registry, {
    initialState: makeBytesState(new Uint8Array(0)),
    initialAux: new Map<string, AuxValue>(initialAux),
    portedDispatchEnabled: true,
  });
  setTrace(trace);
  return trace;
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("TraceTimeline — Slice 1.12 follow-up: coerce badge surfacing", () => {
  beforeEach(() => __resetTraceForTests());
  afterEach(() => {
    cleanup();
    __resetTraceForTests();
  });

  it("renders one ⚠ badge for a single mismatched input port (right-pad case)", () => {
    seedCoerceTrace(
      new Map([["port-a", { byteLength: 16, layout: "raw" }]]),
      new Map([["port-a", "src-a"]]),
      [["src-a", new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])]],
    );
    const { container } = render(() => <TraceTimeline />);

    // The badge strip should appear (frames.length > 1 means coerce + consumer).
    expect(container.querySelector(".trace-timeline-badge-strip")).not.toBeNull();

    // Exactly one coerce badge with the ⚠ glyph.
    const coerceBadges = container.querySelectorAll(".trace-timeline-badge-coerce");
    expect(coerceBadges.length).toBe(1);
    expect(coerceBadges[0]?.textContent).toBe("⚠");

    // Tooltip on the badge names the port and explains the kind so a learner
    // hovering can map ⚠ → "coerce" without scrubbing onto the frame first.
    expect(coerceBadges[0]?.getAttribute("title")).toContain("coerce");
    expect(coerceBadges[0]?.getAttribute("title")).toContain("byteLength mismatch");
  });

  it("emits two ⚠ badges for two mismatched input ports on one leaf", () => {
    seedCoerceTrace(
      new Map([
        ["port-a", { byteLength: 16, layout: "raw" }],
        ["port-b", { byteLength: 4, layout: "raw" }],
      ]),
      new Map([
        ["port-a", "src-a"],
        ["port-b", "src-b"],
      ]),
      [
        ["src-a", new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])],
        ["src-b", new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])],
      ],
    );
    const { container } = render(() => <TraceTimeline />);

    // Two coerce frames precede the consumer leaf → two ⚠ badges, each ⚠.
    const coerceBadges = container.querySelectorAll(".trace-timeline-badge-coerce");
    expect(coerceBadges.length).toBe(2);
    for (const b of Array.from(coerceBadges)) {
      expect(b.textContent).toBe("⚠");
    }
  });

  it("badge position lines up with the coerce frame's index in the trace", () => {
    const trace = seedCoerceTrace(
      new Map([["port-a", { byteLength: 16, layout: "raw" }]]),
      new Map([["port-a", "src-a"]]),
      [["src-a", new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])]],
    );
    const { container } = render(() => <TraceTimeline />);
    const badge = container.querySelector<HTMLElement>(".trace-timeline-badge-coerce");
    expect(badge).not.toBeNull();

    // Frame 0 is the coerce frame; consumer is frame 1. Max index = 1.
    const coerceIdx = trace.frames.findIndex((f) => f.stepType === "__coerce__");
    expect(coerceIdx).toBe(0);
    const maxIdx = trace.frames.length - 1;
    const expectedPct = (coerceIdx / maxIdx) * 100;
    expect(badge?.style.left).toBe(`${expectedPct}%`);
  });

  it("renders no coerce badge when port byteLengths match (exact-match short-circuit)", () => {
    // Same fixture machinery, but the port declares byteLength === source.length
    // so the runtime's === short-circuit fires and no __coerce__ frame is emitted.
    seedCoerceTrace(
      new Map([["port-exact", { byteLength: 8, layout: "raw" }]]),
      new Map([["port-exact", "src-exact"]]),
      [["src-exact", new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])]],
    );
    const { container } = render(() => <TraceTimeline />);

    // The strip itself is hidden when there are no badges of any kind.
    expect(container.querySelector(".trace-timeline-badge-strip")).toBeNull();
    expect(container.querySelectorAll(".trace-timeline-badge-coerce").length).toBe(0);
  });
});
