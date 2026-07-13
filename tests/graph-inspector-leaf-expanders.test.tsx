// @vitest-environment jsdom

/**
 * Component test for the LEAF-inspector expanders in the graph value inspector.
 *
 * When a LEAF node is selected, the inspector renders two collapsible
 * disclosures below the single value row (the linear view's per-step surfaces,
 * brought into the graph inspector):
 *
 *   1. "all port values" → `<PortFlowView>` (every input/output port of the
 *      selected leaf's frame — verified via `.port-flow-view` + `.port-row`).
 *   2. "what this step does" → `<StepNarration>`, GUARDED on a registered
 *      narrator so leaves without one show no empty disclosure.
 *
 * DES is the fixture because it exercises BOTH guard branches with two leaves
 * inside the same visible round:
 *   - `round.1.s-boxes` (`des.s-boxes@1`) HAS a narrator → both expanders.
 *   - `round.1.split` (`split-bytes@1`) has NO narrator → port values only.
 *
 * And it pins the negative case: endpoint pills resolve to no leaf frame
 * (`resolveNodeFrame` returns null), so neither expander renders for them.
 *
 * The pure frame-resolution (`resolveNodeFrame`) is unit-tested in
 * `node-value-lookup.test.ts`; this file pins only the UI wiring + the
 * has-narrator guard.
 */

import "@/ui/narration/index"; // eagerly register narrators (App.tsx does this at startup)
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipher } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import {
  __resetValueInspectorForTests,
  setInspectorPanelOpen,
} from "@/ui/stores/view-value-inspector";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_KEY = "133457799bbcdff1";
const DES_PT = "0123456789abcdef";

const seedDes = (): void => {
  setCipher("des"); // point the spec store + selector at DES
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
  });
  setTrace(trace);
  // Deterministic: no fan-out replica chips inflating the leaf set.
  setReplicationEnabled(false);
  setInspectorPanelOpen(true);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
  __resetValueInspectorForTests();
};

/** Synthetic pointer event (jsdom lacks `PointerEvent`) — matches the shim the
 *  value-inspector + drag tests use. */
const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

/** Click a draggable leaf through the pointer path (its sub-threshold release
 *  runs the drag handler's `onClickFallback` = the same scrub + inspector
 *  select the old `onClick` did). `fireEvent.click` does NOT reach it. */
const clickLeaf = (leaf: SVGGElement): void => {
  leaf.dispatchEvent(pointerEvt("pointerdown", 100, 100));
  window.dispatchEvent(pointerEvt("pointerup", 100, 100));
};

/** Resolve a leaf's wrapping <g> by its full stepId via the `<title>` text —
 *  the stable selector for a nested leaf (matches the value-inspector test). */
const findLeafByStepId = (container: HTMLElement, stepId: string): SVGGElement | null => {
  const leaves = container.querySelectorAll<SVGGElement>("g.graph-leaf");
  for (const g of Array.from(leaves)) {
    const title = g.querySelector("title")?.textContent ?? "";
    if (title.startsWith(`${stepId} `) || title === stepId) return g;
  }
  return null;
};

const findEndpointPill = (container: HTMLElement, side: "input" | "output"): SVGGElement | null =>
  container.querySelector<SVGGElement>(`g.graph-endpoint-${side}`);

/** The expander <details> elements inside the inspector body, by summary text. */
const expanderSummaries = (container: HTMLElement): string[] =>
  Array.from(
    container.querySelectorAll<HTMLElement>(".graph-value-inspector-expander-summary"),
  ).map((el) => el.textContent?.trim() ?? "");

describe("GraphView — leaf-inspector expanders", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders BOTH expanders for a leaf with a registered narrator (des.s-boxes)", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    const leaf = findLeafByStepId(container as HTMLElement, "round.1.s-boxes");
    expect(leaf).not.toBeNull();
    clickLeaf(leaf as SVGGElement);

    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body).not.toBeNull();
    const summaries = expanderSummaries(container as HTMLElement);
    expect(summaries).toContain("all port values");
    expect(summaries).toContain("what this step does");
    // The port-values expander actually mounts PortFlowView with port rows.
    expect(body?.querySelector(".port-flow-view")).not.toBeNull();
    expect(body?.querySelector(".port-row")).not.toBeNull();
  });

  it("renders ONLY the port-values expander for a leaf with no narrator (split-bytes)", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    const leaf = findLeafByStepId(container as HTMLElement, "round.1.split");
    expect(leaf).not.toBeNull();
    clickLeaf(leaf as SVGGElement);

    const summaries = expanderSummaries(container as HTMLElement);
    expect(summaries).toContain("all port values");
    // `split-bytes@1` has no registered narrator → the guard hides the second
    // disclosure rather than showing an empty "what this step does" box.
    expect(summaries).not.toContain("what this step does");
    // PortFlowView still renders — a split leaf has an input + two output ports.
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body?.querySelector(".port-flow-view")).not.toBeNull();
  });

  it("renders NO expanders for an endpoint pill (no leaf frame to expand)", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    const pill = findEndpointPill(container as HTMLElement, "input");
    expect(pill).not.toBeNull();
    fireEvent.click(pill as SVGGElement);

    // The pill still selects + shows its value row, but there is no leaf frame,
    // so neither expander mounts.
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body).not.toBeNull();
    expect(expanderSummaries(container as HTMLElement)).toHaveLength(0);
    expect(body?.querySelector(".port-flow-view")).toBeNull();
  });
});
