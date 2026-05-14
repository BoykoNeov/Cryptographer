// @vitest-environment jsdom

/**
 * Phase 3 of the trace-coupling-bug-fix plan: ParamEditor must resolve and
 * render a step's params without a TraceFrame.
 *
 * Background (`docs/plans/trace-coupling-bug-fix.md`):
 * The pre-fix ParamEditor took `frame: TraceFrame | null` and looked up the
 * step via the frame's stepId. Two real-world failure modes flowed from that:
 *   1. A palette-dropped step has empty params and the debounced auto-rerun
 *      hasn't produced a new trace yet — frame is null → editor renders the
 *      "no step selected" fallback even though the user just clicked the
 *      leaf in the graph view.
 *   2. A step inserted after an upstream executor that threw never gets a
 *      frame at all — even after the debounced rerun, the editor stays
 *      stuck on the fallback.
 *
 * The fix: ParamEditor takes `stepId: string | null`. It resolves the live
 * spec leaf via `findStep(spec, stepId)`. The selection signal (in
 * `stores/trace.ts`) is the source of truth, and clicking a leaf in the
 * graph view calls `setSelectedStepId(stepId)` directly — no frame
 * required.
 *
 * This test exercises that property end-to-end through the full app shell:
 * render App → switch to graph → click a freshly-dropped aux-xor's leaf
 * BEFORE the auto-rerun has produced a frame for it → assert the editor
 * renders the aux-xor's editable fields, not the "no step selected"
 * fallback.
 */

import { App } from "@/ui/App";
import { STEP_TYPE_DRAG_MIME } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests, setViewMode } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: (_mime: string, _value: string) => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

const fireDropAt = (target: Element, stepType: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({
      [STEP_TYPE_DRAG_MIME]: stepType,
      "text/plain": stepType,
    }),
  });
  target.dispatchEvent(event);
};

describe("ParamEditor decoupled from TraceFrame — bug-2 fix", () => {
  beforeEach(() => {
    resetAll();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("clicking a freshly-dropped aux-xor leaf opens the editor for it (no manual Run needed)", async () => {
    const { container } = render(() => <App />);
    setViewMode("graph");

    // Drop aux-xor onto the key-expansion leaf (a root-level anchor so
    // the insertion lands in the top-level spec.steps array).
    const anchor = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="key-expansion"]',
    );
    expect(anchor, "key-expansion leaf must be drop-targetable").not.toBeNull();
    if (!anchor) return;
    fireDropAt(anchor, "generic.aux-xor@1");

    // Wait until the new leaf is in the spec. The drop synchronously
    // mutates the spec store, but the SVG re-render is reactive.
    await waitFor(() => {
      const dropped = container.querySelector('g.graph-leaf[data-drop-anchor="aux-xor-1"]');
      expect(dropped, "the dropped aux-xor must render as a graph leaf").not.toBeNull();
    });

    // Sanity: the spec store has the new leaf with the empty params
    // shape that palette inserts produce.
    const droppedStep = useSpec()().steps.find((n) => n.kind === "step" && n.id === "aux-xor-1");
    expect(droppedStep, "spec store must hold the dropped step").not.toBeUndefined();

    // "Click" the dropped leaf. Root-level leaves are draggable, so their
    // `<g>` doesn't carry `onClick` directly — clicks flow through the
    // drag handler's sub-threshold fallback (pointerdown → small move →
    // pointerup), and keyboard activation goes through onKeyDown's Enter
    // branch. We use Enter here because it's a single deterministic event
    // that exercises the same `handleLeafClick` boundary and isn't
    // sensitive to the drag threshold heuristic.
    const droppedLeaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="aux-xor-1"]',
    );
    if (!droppedLeaf) throw new Error("dropped leaf not found after waitFor confirmed it");
    fireEvent.keyDown(droppedLeaf, { key: "Enter" });

    // The editor's title row carries the resolved step id. If the prior
    // `frame`-based wiring were still in effect, no frame would exist
    // (rerun debounced) and we'd see the "no step selected" fallback.
    await waitFor(() => {
      const title = container.querySelector(".param-editor-title");
      expect(title, "param editor title must be visible").not.toBeNull();
      expect(title?.textContent ?? "", "title should reference the clicked step id").toContain(
        "aux-xor-1",
      );
    });

    // Specific UI surface: aux-xor's editor renders two AuxNameInput
    // fields (`from` and `into`). Asserting both inputs are present pins
    // the dispatch through Switch/Match to AuxXorBlock — i.e. the
    // editor isn't just rendering the "no editor for step type" fallback
    // with the title set.
    const auxInputs = container.querySelectorAll<HTMLInputElement>("input.aux-name-input");
    expect(auxInputs.length, "aux-xor block renders two aux-name inputs").toBe(2);

    // Second-order regression guard. The debounced auto-rerun fires 200ms
    // after the spec mutation, calling `setTrace(newTrace)`. A naive
    // implementation of `setTrace` would unconditionally re-bind
    // `selectedStepId` to whichever frame the scrubber landed on,
    // overwriting the user's explicit aux-xor-1 selection (the scrubber
    // never moved because aux-xor-1 had no frame when the user clicked it).
    // The fix: setTrace prefers `selectedStepId()` over the previous
    // frame's stepId, AND only initializes selectedStepId when it's null
    // (app boot). This assertion pins both properties — wait past the
    // debounce, then re-check the editor is still bound to aux-xor-1.
    await new Promise<void>((resolve) => setTimeout(resolve, 350));
    await waitFor(() => {
      const titleAfter = container.querySelector(".param-editor-title");
      expect(
        titleAfter?.textContent ?? "",
        "editor must still bind to aux-xor-1 after the auto-rerun debounce fires",
      ).toContain("aux-xor-1");
    });
  });

  // Graph-UX polish item #3 — aux-load label clarification.
  //
  // The aux-load ParamEditor block historically rendered its byte sequence
  // under a bare `Value (bytes — N)` label, with no in-context explanation
  // of what bytes belong there. Users reaching the step via the palette
  // had no prior context for aux primitives and would back out of the
  // step entirely. The fix adds a `.aux-byte-hint` line citing the three
  // canonical use cases (IV, counter start, mode constant). This test
  // exercises the same drop-then-click path as the bug-2 fix above, but
  // for aux-load, and asserts the hint text is rendered.
  it("aux-load editor renders a pedagogical hint beneath the byte cells", async () => {
    const { container } = render(() => <App />);
    setViewMode("graph");

    // Drop aux-load onto the key-expansion leaf (same root-level anchor
    // as the bug-2 test — keeps the insertion at the top of spec.steps).
    const anchor = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="key-expansion"]',
    );
    expect(anchor, "key-expansion leaf must be drop-targetable").not.toBeNull();
    if (!anchor) return;
    fireDropAt(anchor, "generic.aux-load@1");

    // Wait for the dropped aux-load to render in the graph.
    await waitFor(() => {
      const dropped = container.querySelector('g.graph-leaf[data-drop-anchor="aux-load-1"]');
      expect(dropped, "the dropped aux-load must render as a graph leaf").not.toBeNull();
    });

    // Click (via Enter key — same reason as the bug-2 test) to bind the
    // editor to the new aux-load leaf.
    const droppedLeaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="aux-load-1"]',
    );
    if (!droppedLeaf) throw new Error("dropped leaf not found after waitFor confirmed it");
    fireEvent.keyDown(droppedLeaf, { key: "Enter" });

    // Assert the editor opened for aux-load-1, then assert the hint is
    // present. The hint is a `.aux-byte-hint` div with a stable copy
    // fragment that won't drift on minor reword polish.
    await waitFor(() => {
      const title = container.querySelector(".param-editor-title");
      expect(title?.textContent ?? "", "title binds to aux-load-1").toContain("aux-load-1");
    });

    const hint = container.querySelector(".aux-byte-hint");
    expect(hint, "aux-byte-hint must be rendered beneath the byte cells").not.toBeNull();
    expect(
      hint?.textContent ?? "",
      "hint mentions IV use case (one of the three canonical aux-load shapes)",
    ).toContain("IV");
    expect(hint?.textContent ?? "", "hint mentions counter use case").toContain("counter");
  });
});
