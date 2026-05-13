// @vitest-environment jsdom

/**
 * Component + integration tests for the read-only graph view (Slice 2).
 *
 * Two layers:
 *   1. Component-level: render <GraphView /> after seeding the spec store
 *      with aes128Spec and running a trace through setTrace. Asserts the
 *      structural rendering (leaf rects, container rects, clickable nodes).
 *   2. App-level: render <App />, drive the view-mode tab bar, confirm the
 *      graph tab swaps the per-frame content out and back without losing
 *      the trace scrubber's stepId-anchored focus.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { App } from "@/ui/App";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import {
  __resetTraceForTests,
  getTrace,
  setFrame,
  setTrace,
  useFrameIndex,
} from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

/** Populate the trace store with a real AES-128 trace so GraphView's
 *  click-to-navigate path has something to navigate INTO. */
const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
};

const findButton = (container: HTMLElement, textPrefix: string): HTMLButtonElement => {
  const all = Array.from(container.querySelectorAll("button"));
  const match = all.find((b) => b.textContent?.trim().startsWith(textPrefix));
  if (!match) throw new Error(`button starting with "${textPrefix}" not found`);
  return match as HTMLButtonElement;
};

// ─── Component-level GraphView tests ──────────────────────────────────────

describe("GraphView — component-level (AES-128 fixture)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders one leaf rectangle per leaf in the spec (41 for AES-128)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Each leaf is an SVG <g class="graph-leaf">; the rect inside it is
    // `.graph-leaf-rect`.
    const leafRects = container.querySelectorAll(".graph-leaf-rect");
    expect(leafRects.length).toBe(41);
  });

  it("renders one container rectangle per group (10 round groups)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const containerRects = container.querySelectorAll(".graph-container-rect");
    expect(containerRects.length).toBe(10);
  });

  it("renders aux-flow edges from the trace (11 key-expansion fan-out edges)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Edge paths each carry a <title> with the auxKey. Round-key fan-out
    // gives us 11 paths whose title starts with "roundKey." — sanity check.
    const edges = container.querySelectorAll(".graph-edge");
    expect(edges.length).toBeGreaterThanOrEqual(11);
    const roundKeyEdges = Array.from(edges).filter((e) =>
      e.querySelector("title")?.textContent?.startsWith("roundKey."),
    );
    expect(roundKeyEdges.length).toBe(11);
  });

  // Sequence commits 1 + 2: every edge in today's graph is rendered with
  // a kind-tagged class AND references the matching arrow marker. Aux
  // edges (trace-derived) carry `.graph-edge-aux` + `url(#graph-arrow-aux)`;
  // state edges (spec-derived spine) carry `.graph-edge-state` +
  // `url(#graph-arrow-state)`. Both populations are non-empty for AES-128
  // — round-key fan-out on the aux side, the 40-edge spine on the state side.
  it("tags every edge with its kind class and the matching arrow marker", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const edges = container.querySelectorAll(".graph-edge");
    expect(edges.length).toBeGreaterThan(0);
    let auxCount = 0;
    let stateCount = 0;
    for (const edge of Array.from(edges)) {
      const isAux = edge.classList.contains("graph-edge-aux");
      const isState = edge.classList.contains("graph-edge-state");
      // Exactly one kind class per edge.
      expect(isAux !== isState).toBe(true);
      if (isAux) {
        expect(edge.getAttribute("marker-end")).toBe("url(#graph-arrow-aux)");
        auxCount++;
      } else {
        expect(edge.getAttribute("marker-end")).toBe("url(#graph-arrow-state)");
        stateCount++;
      }
    }
    expect(auxCount).toBeGreaterThan(0);
    expect(stateCount).toBeGreaterThan(0);
    // Both marker defs render so the matching `url(#…)` references resolve.
    expect(container.querySelector("#graph-arrow-aux")).not.toBeNull();
    expect(container.querySelector("#graph-arrow-state")).not.toBeNull();
  });

  it("clicking a leaf node moves the trace scrubber to the matching frame", () => {
    seedAes128Trace();
    // Park the scrubber on frame 0 so the click-induced jump is observable.
    setFrame(0);
    expect(useFrameIndex()()).toBe(0);

    const { container } = render(() => <GraphView />);

    // Find the leaf rect for round.5.mix-columns and click it. The <title>
    // inside the leaf <g> carries the full stepId, so we use it to disambiguate.
    const leaves = container.querySelectorAll(".graph-leaf");
    const target = Array.from(leaves).find((g) =>
      g.querySelector("title")?.textContent?.startsWith("round.5.mix-columns"),
    );
    expect(target).toBeDefined();
    fireEvent.click(target as Element);

    // After click, the scrubber must point at the trace frame for round.5.mix-columns.
    const trace = getTrace();
    if (!trace) throw new Error("trace was lost");
    const expectedIdx = trace.frames.findIndex((f) => f.stepId === "round.5.mix-columns");
    expect(useFrameIndex()()).toBe(expectedIdx);
  });

  it("renders without a trace (structural skeleton + spec-derived spine, no aux edges)", () => {
    // Don't seed a trace; just render. The graph still draws the spec's
    // nodes/containers AND the 40-edge AES-128 state spine — the spine is
    // spec-derived, so it shows up before the first run (one of the
    // pedagogical payoffs of commit 2 in the readability sequence).
    const { container } = render(() => <GraphView />);
    const leaves = container.querySelectorAll(".graph-leaf-rect");
    expect(leaves.length).toBe(41);
    // No aux edges pre-run (those require a trace).
    expect(container.querySelectorAll(".graph-edge-aux").length).toBe(0);
    // Full 40-edge state spine across AES-128's leaves.
    expect(container.querySelectorAll(".graph-edge-state").length).toBe(40);
  });
});

// ─── App-level tab integration ────────────────────────────────────────────

describe("App — view-mode tab bar (linear / graph / JSON)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders all three tabs in the tab bar with the linear tab active by default", () => {
    const { container } = render(() => <App />);
    const tabs = container.querySelectorAll(".view-mode-tab");
    expect(tabs.length).toBe(3);
    const labels = Array.from(tabs).map((t) => t.textContent?.trim());
    expect(labels).toEqual(["linear", "graph", "JSON"]);
    // First tab (linear) is active by default.
    const active = container.querySelector(".view-mode-tab.active");
    expect(active?.textContent?.trim()).toBe("linear");
  });

  it("clicking the graph tab swaps in the SVG graph view", () => {
    const { container } = render(() => <App />);
    // Run first so the trace exists; otherwise graph would render only the
    // structural skeleton (still fine, but less interesting to assert).
    fireEvent.click(findButton(container, "run"));
    // Before click: no SVG.
    expect(container.querySelector(".graph-view-svg")).toBeNull();
    // Click the graph tab.
    fireEvent.click(findButton(container, "graph"));
    expect(container.querySelector(".graph-view-svg")).not.toBeNull();
    // And the linear-tab specific frame header is gone.
    expect(container.querySelector(".frame-header")).toBeNull();
  });

  it("clicking the JSON tab swaps in the spec's pretty-printed JSON", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "JSON"));
    const json = container.querySelector(".view-mode-json");
    expect(json).not.toBeNull();
    // The spec's id ("aes-128@1") must appear in the JSON pretty-print.
    expect(json?.textContent).toContain("aes-128@1");
  });

  it("switching tabs preserves the scrubber's stepId-anchored frame focus", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "run"));
    // Move the scrubber to a non-zero frame so the assertion is non-trivial.
    const trace = getTrace();
    if (!trace) throw new Error("trace was not set");
    const targetIdx = trace.frames.findIndex((f) => f.stepId === "round.3.shift-rows");
    expect(targetIdx).toBeGreaterThan(0);
    setFrame(targetIdx);
    expect(useFrameIndex()()).toBe(targetIdx);
    // Flip to graph, then back to linear. The frame index must survive.
    fireEvent.click(findButton(container, "graph"));
    fireEvent.click(findButton(container, "linear"));
    expect(useFrameIndex()()).toBe(targetIdx);
  });
});
