// @vitest-environment jsdom

/**
 * jsdom integration tests for the Slice 6 drag + collapse layer of GraphView.
 *
 * Two surfaces:
 *   1. Drag — pointerdown on a container header, pointermove on window,
 *      pointerup on window. The store should receive position updates with
 *      the expected SVG-unit delta. A small move (< threshold) should not
 *      register a position write.
 *   2. Collapse — clicking the chevron toggles `collapsedGroups`; the
 *      container's children disappear from the rendered SVG; clicking
 *      again restores them.
 *
 * Both surfaces exercise per-spec.id partitioning indirectly: the store
 * receives the current spec().id (AES-128) and writes against that key.
 *
 * jsdom quirks we accommodate:
 *   - `setPointerCapture` is a no-op in some jsdom versions; the
 *     drag handler tolerates that (window-level listeners still fire).
 *   - `PointerEvent` doesn't accept all the same init options as the
 *     browser; we synthesize via `new MouseEvent` with the
 *     `pointermove`/`pointerup` types and let the handlers cast — the
 *     handler only reads `clientX`/`clientY`, which MouseEvent carries.
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
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  setNodePosition,
  toggleCollapse,
} from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, getTrace, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
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
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

/**
 * Build a pointer-shaped event that hits the same code paths as a real
 * PointerEvent. jsdom exposes `PointerEvent` as a subclass of MouseEvent
 * in current versions; we use MouseEvent directly so the test compiles
 * cleanly across jsdom versions. Handlers read only `clientX`/`clientY`
 * and `currentTarget`, both of which a MouseEvent carries.
 */
const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  // Stamp pointerId so the handler's setPointerCapture call (if it fires)
  // doesn't throw when reading the field. jsdom tolerates the extra prop.
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

// ─── Drag ──────────────────────────────────────────────────────────────────

describe("GraphView — container drag (Slice 6)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("updates the layout store with the new container position after pointerdown → move → up", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    // Find the header drag handle for round.5 — the data-testid attribute
    // we baked into the component is the stable selector.
    const header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    expect(header).not.toBeNull();

    // Initial position: read from the layout store BEFORE drag — none yet.
    const specId = useSpec()().id;
    expect(getLayoutForSpec(specId)).toBeNull();

    // pointerdown on the header at (100, 100); move to (200, 150) on
    // window; release at (200, 150) on window.
    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 200, 150));
    window.dispatchEvent(pointerEvt("pointerup", 200, 150));

    // Store should have a pin at the container's startBox + delta.
    // We don't know the auto-laid-out startBox precisely (it's computed),
    // but we know the WRITTEN position equals startBoxX + 100, startBoxY + 50.
    const layout = getLayoutForSpec(specId);
    expect(layout).not.toBeNull();
    expect(layout?.positions["round.5"]).toBeDefined();
    const p = layout?.positions["round.5"];
    if (p) {
      // Delta is the only thing we control; sanity-check it landed.
      // startBoxX was something positive; delta x = 100 → new x ≥ 100.
      expect(p.x).toBeGreaterThan(99);
      expect(p.y).toBeGreaterThan(0);
    }
  });

  it("does NOT pin a position when the pointer barely moves (sub-threshold = click, not drag)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    expect(header).not.toBeNull();

    const specId = useSpec()().id;
    expect(getLayoutForSpec(specId)).toBeNull();

    // pointerdown then move 2px (below the 4px threshold) then up.
    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 102, 100));
    window.dispatchEvent(pointerEvt("pointerup", 102, 100));

    // No pinned position should land — the threshold gates the write.
    expect(getLayoutForSpec(specId)).toBeNull();
  });

  // Regression: this is the bug that wasn't caught by the store-only
  // assertion above. Dragging an expanded container DID update the store
  // but the rendered <rect> kept its old x/y because the row callback
  // captured `layout().boxes.get(id)` once at row-init time. The render
  // path now wraps the lookup in `createMemo` so the JSX binding tracks
  // layout changes — this test pins that contract.
  it("moves the rendered container rect's x/y attributes after a drag (not just the store)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    expect(header).not.toBeNull();

    // Read the container rect's PRE-drag attributes. The data-testid header
    // is a sibling of the <rect class="graph-container-rect"> inside the
    // same <g class="graph-container">, so we walk up + find.
    const containerGroup = header.parentElement as Element;
    const rect = containerGroup.querySelector(".graph-container-rect") as SVGRectElement;
    expect(rect).not.toBeNull();
    const beforeX = Number(rect.getAttribute("x"));
    const beforeY = Number(rect.getAttribute("y"));

    // Drag down + right by (100, 80) — well above the 4px threshold.
    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 200, 180));
    window.dispatchEvent(pointerEvt("pointerup", 200, 180));

    // POST-drag the rendered rect's x/y must reflect the new position.
    // We don't pin the exact pixel because startBox is auto-laid-out,
    // but the delta should appear.
    const afterX = Number(rect.getAttribute("x"));
    const afterY = Number(rect.getAttribute("y"));
    expect(afterX - beforeX).toBeCloseTo(100, 0);
    expect(afterY - beforeY).toBeCloseTo(80, 0);
  });

  it("removes window listeners after pointerup so a stray pointermove doesn't keep updating", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;

    const specId = useSpec()().id;

    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 200, 150));
    window.dispatchEvent(pointerEvt("pointerup", 200, 150));
    const afterUp = getLayoutForSpec(specId)?.positions["round.5"];

    // A pointermove after release should not change the stored position.
    window.dispatchEvent(pointerEvt("pointermove", 500, 500));
    const afterStray = getLayoutForSpec(specId)?.positions["round.5"];
    expect(afterStray).toEqual(afterUp);
  });
});

// ─── Collapse ──────────────────────────────────────────────────────────────

describe("GraphView — container collapse (Slice 6)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders all child leaves of a round group when not collapsed", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // round.5 has 4 leaves (sub-bytes, shift-rows, mix-columns, add-round-key).
    // We can't easily count "round.5's children" from the rendered SVG
    // alone, but total leaf count across the whole AES-128 graph is 41.
    expect(container.querySelectorAll(".graph-leaf-rect").length).toBe(41);
  });

  it("clicking the chevron collapses the container; child leaves disappear from the SVG", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    // Collapse round.5 by clicking its chevron.
    const chevron = container.querySelector(
      '[data-testid="graph-container-chevron-round.5"]',
    ) as Element;
    expect(chevron).not.toBeNull();
    fireEvent.click(chevron);

    // Post-collapse: total leaves dropped by 4 (round.5's 4 children).
    expect(container.querySelectorAll(".graph-leaf-rect").length).toBe(37);

    // The container itself is still present as a chip.
    const collapsedRect = container.querySelector(".graph-container-rect-collapsed");
    expect(collapsedRect).not.toBeNull();
  });

  it("clicking the chevron again expands the container (toggle semantics)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    // Re-query between clicks: Solid may swap the chevron's DOM node when
    // its glyph text content changes (▾ → ▸), leaving the captured ref
    // detached. Re-finding by data-testid is the resilient pattern.
    const findChevron = (): Element => {
      const el = container.querySelector('[data-testid="graph-container-chevron-round.5"]');
      if (!el) throw new Error("chevron not found");
      return el;
    };

    fireEvent.click(findChevron()); // collapse
    expect(container.querySelectorAll(".graph-leaf-rect").length).toBe(37);
    fireEvent.click(findChevron()); // expand
    expect(container.querySelectorAll(".graph-leaf-rect").length).toBe(41);
    expect(container.querySelector(".graph-container-rect-collapsed")).toBeNull();
  });
});

// ─── Layout store writes do NOT touch the trace signal ───────────────────
// Advisor constraint: dragging a container shouldn't re-run the cipher.
// The drag handler ultimately funnels into setNodePosition + toggleCollapse,
// so the invariant we verify is "those store writes are isolated from the
// trace signal." We don't drive the full pointer sequence here (that's
// already exercised by the earlier drag tests); we exercise the same write
// path the pointer plumbing terminates at, which is the load-bearing
// constraint. If a future refactor introduces a spec mutation inside the
// drag handler (e.g. accidentally calling updateStepParams), that's a
// different invariant — add a separate test then.

describe("GraphView — layout store writes don't touch the trace signal", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("setNodePosition + toggleCollapse leave getTrace() ref unchanged", () => {
    seedAes128Trace();
    render(() => <GraphView />);
    // Capture trace ref before and after a programmatic store mutation
    // (drag handler ultimately calls setNodePosition; we cut out the
    // pointer plumbing and exercise the same write path).
    const traceBefore = getTrace();
    const specId = useSpec()().id;
    setNodePosition(specId, "round.5", 500, 500);
    toggleCollapse(specId, "round.7");
    const traceAfter = getTrace();
    expect(traceAfter).toBe(traceBefore);
  });
});
