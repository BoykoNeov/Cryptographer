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
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
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
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
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

    // Pick a bytes-input step's palette entry.
    const bytesEntry = container.querySelector('[data-step-type="generic.compute-block-count@1"]');
    expect(bytesEntry).not.toBeNull();
    if (!bytesEntry) throw new Error("unreachable");
    fireDragStart(bytesEntry);

    expect(view.classList.contains("dragging-bytes")).toBe(true);
    expect(view.classList.contains("dragging-matrix")).toBe(false);
  });

  it("starting a drag of a matrix-input step flips dragging-matrix", () => {
    const { container } = render(() => <GraphView />);
    const view = container.querySelector(".graph-view");
    expect(view).not.toBeNull();
    if (!view) throw new Error("unreachable");

    // An AES round step expects matrix4x4-bytes.
    const matrixEntry = container.querySelector('[data-step-type="generic.byte-substitution@1"]');
    expect(matrixEntry).not.toBeNull();
    if (!matrixEntry) throw new Error("unreachable");
    fireDragStart(matrixEntry);

    expect(view.classList.contains("dragging-matrix")).toBe(true);
    expect(view.classList.contains("dragging-bytes")).toBe(false);
  });

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
    const bytesEntry = container.querySelector('[data-step-type="generic.compute-block-count@1"]');
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
    // For the AES-128 single-block spec (state is matrix4x4-bytes throughout),
    // every leaf-level anchor should carry matrix4x4-bytes.
    let matrixAnchors = 0;
    for (const a of anchors) {
      if (a.getAttribute("data-state-shape") === "matrix4x4-bytes") matrixAnchors++;
    }
    expect(matrixAnchors).toBeGreaterThan(0);
  });
});
