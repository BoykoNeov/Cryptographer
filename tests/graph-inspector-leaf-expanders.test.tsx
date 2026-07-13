// @vitest-environment jsdom

/**
 * Component test for the LEAF-inspector expanders in the graph value inspector.
 *
 * When a LEAF node is selected, the inspector renders up to three collapsible
 * disclosures below the single value row (the linear view's per-step surfaces,
 * brought into the graph inspector):
 *
 *   1. "all port values" → `<PortFlowView>` (every input/output port of the
 *      selected leaf's frame — verified via `.port-flow-view` + `.port-row`).
 *   2. "where each byte comes from" (Tier B) → `<CellProvenanceView>`, GUARDED
 *      on a registered provenance fn (`.cell-provenance-view`).
 *   3. "what this step does" (Tier A) → `<StepNarration>` for a narrated leaf,
 *      else a type-prose fallback (`<StepDescription compact>`). Every leaf with
 *      a registered doc gets SOME description now.
 *
 * DES is the fixture because it exercises the branches with leaves inside one
 * visible round:
 *   - `round.1.s-boxes` (`des.s-boxes@1`) HAS a narrator, NO provenance fn →
 *     port values + narration (no Tier B).
 *   - `round.1.split` (`split-bytes@1`) has NO narrator but HAS a provenance fn →
 *     port values + per-cell provenance + type-prose fallback.
 *   - `round.1.xor` (`xor@1`) has a same-index provenance fn → Tier B collapses
 *     to a single summary line.
 *
 * And it pins the negative case: endpoint pills resolve to no leaf frame
 * (`resolveNodeFrame` returns null), so NO expander renders for them.
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

  it("narrated leaf (des.s-boxes): port values + VALUE-prose narration, no Tier B", () => {
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
    // `des.s-boxes@1` has no exact provenance fn (bit-level) → no Tier B expander.
    expect(summaries).not.toContain("where each byte comes from");
    // The port-values expander actually mounts PortFlowView with port rows.
    expect(body?.querySelector(".port-flow-view")).not.toBeNull();
    expect(body?.querySelector(".port-row")).not.toBeNull();
    // "what this step does" shows the VALUE-prose narrator (not the type-prose
    // fallback): StepNarration renders `.step-narration`, StepDescription would
    // render `.step-description`.
    expect(body?.querySelector(".step-narration")).not.toBeNull();
    expect(body?.querySelector(".step-description")).toBeNull();
  });

  it("un-narrated leaf (split-bytes): port values + per-cell Tier B + TYPE-prose fallback", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    const leaf = findLeafByStepId(container as HTMLElement, "round.1.split");
    expect(leaf).not.toBeNull();
    clickLeaf(leaf as SVGGElement);

    const body = container.querySelector('[data-testid="value-inspector-body"]');
    const summaries = expanderSummaries(container as HTMLElement);
    expect(summaries).toContain("all port values");
    // Tier B: split-bytes@1 HAS a provenance fn → the always-on map appears,
    // and (multi-output) enumerates per-cell rows.
    expect(summaries).toContain("where each byte comes from");
    expect(body?.querySelector(".cell-provenance-view")).not.toBeNull();
    expect(body?.querySelector(".cell-provenance-row")).not.toBeNull();
    // Tier A: `split-bytes@1` has NO narrator, so "what this step does" now
    // falls back to the registry TYPE-prose (StepDescription) rather than being
    // hidden — every leaf gets a description.
    expect(summaries).toContain("what this step does");
    expect(body?.querySelector(".step-description")).not.toBeNull();
    expect(body?.querySelector(".step-narration")).toBeNull();
    expect(body?.querySelector(".port-flow-view")).not.toBeNull();
  });

  it("same-index leaf (round fxor): Tier B collapses to a single summary line", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    // The DES round's `xor@1` (L ⊕ f(R,K)) is the `fxor` leaf.
    const leaf = findLeafByStepId(container as HTMLElement, "round.1.fxor");
    expect(leaf).not.toBeNull();
    clickLeaf(leaf as SVGGElement);

    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(expanderSummaries(container as HTMLElement)).toContain("where each byte comes from");
    // `xor@1` is same-index → collapsed one-liner, NOT a per-cell enumeration.
    expect(body?.querySelector(".cell-provenance-summary-line")).not.toBeNull();
    expect(body?.querySelector(".cell-provenance-row")).toBeNull();
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
