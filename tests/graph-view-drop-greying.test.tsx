// @vitest-environment jsdom

/**
 * Tests for the palette → graph-view drop-anchor greying signal flow.
 *
 * What we pin here:
 *   1. Starting a drag from a palette entry whose `shapeContract.input ===
 *      "bytes"` flips the `<div class="graph-view">` to carry the class
 *      `dragging-bytes`.
 *   2. Same for `matrix4x4-bytes` → `dragging-matrix`.
 *   3. An "any"-input step (the aux primitives) does NOT add any
 *      `dragging-*` class — `aux-xor` / `aux-copy` / `aux-load` can
 *      legitimately land anywhere.
 *   4. Ending the drag (`dragend`) clears the class so the next gesture
 *      starts clean.
 *   5. Drop anchors inside the rendered SVG carry a `data-state-shape`
 *      attribute matching `inferShapesAtAnchors` — the CSS rules in
 *      app.css read this to decide which anchors to dim.
 *
 * We don't visually verify opacity (jsdom doesn't run CSS); the dimming
 * is a CSS consequence of the class + attribute, and the smoke test for
 * actual visual styling lives in the Playwright pass.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    portedDispatchEnabled: true,
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

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

/**
 * Fire a synthetic `dragstart` on a palette entry. The handler reads
 * `e.dataTransfer` (we attach a mock) and writes to the module-level
 * signal that GraphView observes — no real browser drag is needed.
 */
const fireDragStart = (entry: Element): void => {
  const event = new Event("dragstart", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: {
      setData: () => {},
      effectAllowed: "" as DataTransfer["effectAllowed"],
    },
  });
  entry.dispatchEvent(event);
};

const fireDragEnd = (entry: Element): void => {
  const event = new Event("dragend", { bubbles: true, cancelable: true });
  entry.dispatchEvent(event);
};

describe("GraphView — drop-anchor greying class on .graph-view", () => {
  beforeEach(() => {
    resetAll();
    seedAes128Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("starting a drag of a bytes-input step flips dragging-bytes on .graph-view", () => {
    const { container } = render(() => <GraphView />);
    const view = container.querySelector(".graph-view");
    expect(view).not.toBeNull();
    if (!view) throw new Error("unreachable");
    // Baseline: no dragging class.
    expect(view.classList.contains("dragging-bytes")).toBe(false);
    expect(view.classList.contains("dragging-matrix")).toBe(false);

    // Pick a bytes-input step's palette entry (Serpent SubBytes —
    // `shapeContract.input === "bytes"`). The matrix `generic.compute-block-
    // count@1` example retired in Phase 5 Slice 5.1 with the MatrixState shape.
    const bytesEntry = container.querySelector('[data-step-type="serpent.sub-bytes@1"]');
    expect(bytesEntry).not.toBeNull();
    if (!bytesEntry) throw new Error("unreachable");
    fireDragStart(bytesEntry);

    expect(view.classList.contains("dragging-bytes")).toBe(true);
    expect(view.classList.contains("dragging-matrix")).toBe(false);
  });

  // The "matrix-input step flips dragging-matrix" test was retired in Phase 5
  // Slice 5.1 (2026-05-30): with the MatrixState shape gone, no step declares
  // `shapeContract.input === "matrix4x4-bytes"`, so the `dragging-matrix`
  // class can never fire. (The GraphView classList entry is now dead.)

  it("starting a drag of an any-input step adds no dragging class", () => {
    // The aux primitives + key expansions are "any" — they can land
    // anywhere, so no greying applies.
    const { container } = render(() => <GraphView />);
    const view = container.querySelector(".graph-view");
    expect(view).not.toBeNull();
    if (!view) throw new Error("unreachable");

    const anyEntry = container.querySelector('[data-step-type="generic.aux-xor@1"]');
    expect(anyEntry).not.toBeNull();
    if (!anyEntry) throw new Error("unreachable");
    fireDragStart(anyEntry);

    expect(view.classList.contains("dragging-bytes")).toBe(false);
    expect(view.classList.contains("dragging-matrix")).toBe(false);
  });

  it("dragend clears the dragging class so the next drag starts clean", () => {
    const { container } = render(() => <GraphView />);
    const view = container.querySelector(".graph-view");
    if (!view) throw new Error("unreachable");
    const bytesEntry = container.querySelector('[data-step-type="serpent.sub-bytes@1"]');
    if (!bytesEntry) throw new Error("unreachable");

    fireDragStart(bytesEntry);
    expect(view.classList.contains("dragging-bytes")).toBe(true);
    fireDragEnd(bytesEntry);
    expect(view.classList.contains("dragging-bytes")).toBe(false);
  });

  it("renders data-state-shape on each leaf's drop anchor", () => {
    // Smoke: SVG drop anchors carry the inferred state shape so CSS
    // (`.dragging-bytes [data-state-shape]:not([data-state-shape="bytes"])`)
    // has a value to read.
    const { container } = render(() => <GraphView />);
    const anchors = container.querySelectorAll("[data-drop-anchor][data-state-shape]");
    expect(anchors.length).toBeGreaterThan(0);
    // Byte-native AES-128 (Slice B1): every round leaf is a port-native
    // primitive whose input port is `layout:"raw"`, so the inferred drop-anchor
    // state shape is `bytes` throughout (the matrix form carried
    // `matrix4x4-bytes`). At least one leaf anchor should carry `bytes`.
    let bytesAnchors = 0;
    for (const a of anchors) {
      if (a.getAttribute("data-state-shape") === "bytes") bytesAnchors++;
    }
    expect(bytesAnchors).toBeGreaterThan(0);
  });
});

/**
 * Synthesize a dragover/dragleave/drop event with a step-type-MIME-carrying
 * `dataTransfer` so `isStepTypeDrag` in GraphView's handler returns true.
 * jsdom's DragEvent constructor doesn't accept a `dataTransfer` init, so
 * we forge one via `Object.defineProperty` after construction.
 */
const fireGraphEvent = (target: Element, type: "dragover" | "dragleave" | "drop"): void => {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: {
      types: ["application/x-cryptographer-step-type", "text/plain"],
      // `dropEffect` setter is touched by handleDragOver — allow assignment.
      dropEffect: "none" as DataTransfer["dropEffect"],
      getData: () => "",
      setData: () => {},
    },
    writable: false,
  });
  target.dispatchEvent(event);
};

/**
 * Drop-anchor highlight preview during a palette drag. Until this shipped,
 * compatible anchors had no positive "drop here will land at X" hint —
 * only shape-incompatible ones dimmed via the greying pass. Users had to
 * drop blind, especially in canvas gaps where the closest() walk
 * fell back to root-append far from where they meant to drop.
 *
 * These tests assert that `dragover` resolves the same anchor the drop
 * handler would use and toggles `.graph-drop-target-active` on the
 * matching `<g>`. Moving the cursor to a new anchor swaps the highlight.
 * `dragleave` clears it.
 */
describe("GraphView — drop-anchor highlight during palette drag", () => {
  beforeEach(() => {
    resetAll();
    seedAes128Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("dragover on a leaf adds .graph-drop-target-active to that leaf", () => {
    const { container } = render(() => <GraphView />);
    // Restrict to LEAF anchors. After the 2026-05-15 rescope,
    // `data-drop-anchor` also lives on container header `<rect>`
    // elements (drop-on-header = enter container's body), but the
    // highlight class for header drops attaches to the parent
    // `<g class="graph-container">`, not the header rect itself —
    // a leaf-only selector keeps the assertion direct.
    const anchors = container.querySelectorAll("g.graph-leaf[data-drop-anchor]");
    expect(anchors.length).toBeGreaterThan(0);
    const leaf = anchors[0] as Element;
    expect(leaf.classList.contains("graph-drop-target-active")).toBe(false);
    fireGraphEvent(leaf, "dragover");
    expect(leaf.classList.contains("graph-drop-target-active")).toBe(true);
  });

  it("moving the dragover to a different anchor moves the highlight with it", () => {
    const { container } = render(() => <GraphView />);
    const anchors = Array.from(container.querySelectorAll("g.graph-leaf[data-drop-anchor]"));
    expect(anchors.length).toBeGreaterThan(1);
    const first = anchors[0] as Element;
    const second = anchors[1] as Element;
    fireGraphEvent(first, "dragover");
    expect(first.classList.contains("graph-drop-target-active")).toBe(true);
    fireGraphEvent(second, "dragover");
    // Solid's reactive update of the per-leaf classList flips the
    // first one off because dragOverAnchorId() === clickTargetId no
    // longer holds for it.
    expect(first.classList.contains("graph-drop-target-active")).toBe(false);
    expect(second.classList.contains("graph-drop-target-active")).toBe(true);
  });

  it("dragleave (off the canvas) clears the highlight", () => {
    const { container } = render(() => <GraphView />);
    const leaf = container.querySelector("g.graph-leaf[data-drop-anchor]") as Element;
    fireGraphEvent(leaf, "dragover");
    expect(leaf.classList.contains("graph-drop-target-active")).toBe(true);
    // Dragleave bubbles up to the .graph-view wrapper; that's where
    // handleDragLeave is attached. Fire it on the wrapper so the
    // relatedTarget check fires correctly (no related target → cleared).
    const view = container.querySelector(".graph-view") as Element;
    fireGraphEvent(view, "dragleave");
    expect(leaf.classList.contains("graph-drop-target-active")).toBe(false);
  });
});
