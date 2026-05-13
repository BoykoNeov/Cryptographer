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

  it("clamps drag to non-negative SVG coordinates (block can't be lost behind the sticky header)", () => {
    // Regression: the sticky toolbar/replication-overrides header has
    // z-index: 1 over the SVG. A block dragged to negative SVG y is
    // clipped (outside the SVG viewBox) AND unclickable; the bad
    // position persists in localStorage so the block stays lost across
    // reloads. The drag handler clamps newX/newY to >= 0 so a block
    // can never land outside the SVG's drawn area.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    // Seed round.5 at a starting position close to the top, then drag UP
    // far enough that the natural newY would go negative.
    setNodePosition(specId, "round.5", 50, 30);
    const header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    expect(header).not.toBeNull();

    // pointerdown at (100, 100); move UP/LEFT by (-200, -200). Natural
    // newX = 50 - 200 = -150; natural newY = 30 - 200 = -170. Both
    // negative — the clamp must bring them to 0.
    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", -100, -100));
    window.dispatchEvent(pointerEvt("pointerup", -100, -100));

    const p = getLayoutForSpec(specId)?.positions["round.5"];
    expect(p).toBeDefined();
    expect(p?.x).toBeGreaterThanOrEqual(0);
    expect(p?.y).toBeGreaterThanOrEqual(0);
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

  // Regression: dragged container's arrows didn't follow because EdgePath
  // captured `d = M ... C ...` as a const at component-init time. Now `d`
  // is wrapped in createMemo so the path attribute updates reactively.
  // Pre-fix this only worked after a collapse toggle (which forces a
  // re-mount of EdgePath via re-keyed <For>). This test reproduces the
  // expanded-only case the user reported.
  it("arrows follow dragged containers even when nothing is collapsed", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    // Snapshot the first edge's `d` BEFORE the drag.
    const firstEdge = container.querySelector(".graph-edge") as SVGPathElement;
    expect(firstEdge).not.toBeNull();
    const beforeD = firstEdge.getAttribute("d");
    expect(beforeD).not.toBeNull();

    // Drag round.5 substantially. round.5 is the consumer (target) of at
    // least one key-expansion edge (roundKey.5), so the `d` attribute of
    // that edge must change once round.5's position changes.
    const r5Header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    r5Header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 300, 350));
    window.dispatchEvent(pointerEvt("pointerup", 300, 350));

    // At least ONE edge's `d` must differ from its pre-drag value. We
    // walk all edges so the test stays robust to edge ordering — the
    // round-key edge to round.5 is the easy candidate, but other edges
    // that touch round.5 also count.
    const edges = Array.from(container.querySelectorAll(".graph-edge"));
    const anyChanged = edges.some((p) => {
      const dAttr = p.getAttribute("d");
      return dAttr !== null && dAttr !== beforeD;
    });
    expect(anyChanged).toBe(true);
  });

  // Specifically pin the final round (round.10) — the user reported it
  // wasn't draggable. If this test passes programmatically, the issue is
  // environmental (CSS overflow scroll position, browser quirk). If it
  // fails, we have a reproducible bug.
  it("the final round (round.10) is draggable like every other root container", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    const r10Header = container.querySelector(
      '[data-testid="graph-container-header-round.10"]',
    ) as Element | null;
    expect(r10Header).not.toBeNull();

    const group = (r10Header as Element).parentElement as Element;
    const rect = group.querySelector(".graph-container-rect") as SVGRectElement;
    const beforeX = Number(rect.getAttribute("x"));

    (r10Header as Element).dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 150, 200));
    window.dispatchEvent(pointerEvt("pointerup", 150, 200));

    expect(getLayoutForSpec(specId)?.positions["round.10"]).toBeDefined();
    const afterX = Number(rect.getAttribute("x"));
    expect(afterX - beforeX).toBeCloseTo(50, 0);
  });

  // Regression: pinning round.5 used to leave its slot vacant, causing
  // round.6 to slide leftward into it (and round.7 into round.6's slot,
  // etc.). The user reported this in feedback. Fix: layoutRoot always
  // advances the cursor by the natural width, even when an entity is
  // pinned. This test asserts un-pinned siblings keep their original
  // X coordinates after a sibling is dragged.
  it("pinning a root container does not shift the rendered X of subsequent siblings", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    // Snapshot pre-drag X coordinates of round.6 and round.7.
    const getX = (id: string): number => {
      const headerSibling = container.querySelector(
        `[data-testid="graph-container-header-${id}"]`,
      ) as Element;
      const group = headerSibling.parentElement as Element;
      const rect = group.querySelector(".graph-container-rect") as SVGRectElement;
      return Number(rect.getAttribute("x"));
    };
    const beforeR6X = getX("round.6");
    const beforeR7X = getX("round.7");

    // Drag round.5 well off its natural slot.
    const r5Header = container.querySelector(
      '[data-testid="graph-container-header-round.5"]',
    ) as Element;
    r5Header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 200, 250));
    window.dispatchEvent(pointerEvt("pointerup", 200, 250));

    // Round.5 should be pinned.
    expect(getLayoutForSpec(specId)?.positions["round.5"]).toBeDefined();

    // Round.6 and round.7's X must NOT have moved — they're still in
    // their auto-flow positions, NOT collapsed into round.5's old slot.
    expect(getX("round.6")).toBe(beforeR6X);
    expect(getX("round.7")).toBe(beforeR7X);
  });
});

// ─── Root-level leaf drag ─────────────────────────────────────────────────
// Root-level leaves like AES-128's `key-expansion` and
// `initial.add-round-key` are now draggable (sibling of the container
// drag). Nested leaves like `round.5.sub-bytes` keep their click-only
// behavior so users can't accidentally pull a single step out of its
// parent round.

describe("GraphView — root-level leaf drag", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("dragging a root-level leaf (key-expansion) pins its position AND moves the rendered rect", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    // Find the root-level key-expansion <g class="graph-leaf"> by walking
    // titles. Its title prefix is the stepId.
    const leafGs = Array.from(container.querySelectorAll("g.graph-leaf"));
    const target = leafGs.find((g) =>
      g.querySelector("title")?.textContent?.startsWith("key-expansion ("),
    ) as Element | undefined;
    if (!target) throw new Error("key-expansion leaf not found");

    // It should advertise itself as draggable via the class hook.
    expect(target.classList.contains("graph-leaf-draggable")).toBe(true);

    const rect = target.querySelector(".graph-leaf-rect") as SVGRectElement;
    const beforeX = Number(rect.getAttribute("x"));
    const beforeY = Number(rect.getAttribute("y"));

    // Drag down + right.
    target.dispatchEvent(pointerEvt("pointerdown", 50, 50));
    window.dispatchEvent(pointerEvt("pointermove", 200, 180));
    window.dispatchEvent(pointerEvt("pointerup", 200, 180));

    // Store has the pin.
    const pin = getLayoutForSpec(specId)?.positions["key-expansion"];
    expect(pin).toBeDefined();

    // Rendered rect's x/y reflect the delta (150, 130).
    const afterX = Number(rect.getAttribute("x"));
    const afterY = Number(rect.getAttribute("y"));
    expect(afterX - beforeX).toBeCloseTo(150, 0);
    expect(afterY - beforeY).toBeCloseTo(130, 0);
  });

  it("nested leaves (e.g. round.5.sub-bytes) are NOT draggable", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    const leafGs = Array.from(container.querySelectorAll("g.graph-leaf"));
    const nested = leafGs.find((g) =>
      g.querySelector("title")?.textContent?.startsWith("round.5.sub-bytes ("),
    ) as Element | undefined;
    if (!nested) throw new Error("round.5.sub-bytes leaf not found");

    // No draggable class.
    expect(nested.classList.contains("graph-leaf-draggable")).toBe(false);

    // pointerdown + move should not write any leaf pin to the store
    // (because the onPointerDown handler isn't wired).
    nested.dispatchEvent(pointerEvt("pointerdown", 50, 50));
    window.dispatchEvent(pointerEvt("pointermove", 200, 180));
    window.dispatchEvent(pointerEvt("pointerup", 200, 180));
    expect(getLayoutForSpec(specId)?.positions["round.5.sub-bytes"]).toBeUndefined();
  });

  it("sub-threshold click on a draggable leaf still scrubs the trace", async () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Use the trace store's setFrame import indirectly: pre-park the
    // scrubber on frame 0, then click key-expansion → its frame index.
    const { setFrame, useFrameIndex } = await import("@/ui/stores/trace");
    setFrame(0);
    expect(useFrameIndex()()).toBe(0);

    const leafGs = Array.from(container.querySelectorAll("g.graph-leaf"));
    const target = leafGs.find((g) =>
      g.querySelector("title")?.textContent?.startsWith("key-expansion ("),
    ) as Element | undefined;
    if (!target) throw new Error("key-expansion leaf not found");

    // Sub-threshold drag (2px) acts as a click — the drag handler's
    // onClickFallback should fire handleLeafClick → setFrame.
    target.dispatchEvent(pointerEvt("pointerdown", 50, 50));
    window.dispatchEvent(pointerEvt("pointermove", 51, 50));
    window.dispatchEvent(pointerEvt("pointerup", 51, 50));

    const trace = getTrace();
    if (!trace) throw new Error("trace was lost");
    const expected = trace.frames.findIndex((f) => f.stepId === "key-expansion");
    expect(useFrameIndex()()).toBe(expected);
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
