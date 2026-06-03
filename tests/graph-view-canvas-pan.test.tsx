// @vitest-environment jsdom

/**
 * Regression tests for drag-to-pan on the graph canvas (2026-05-30).
 *
 * The bug: the pan handler lived on the `<svg>`, which is sized to its
 * content (`height = canvasH * zoom`). The scroll wrapper `.graph-view`
 * has `min-height: 560px`, so a short spec leaves a DEAD ZONE below the
 * SVG that belongs to the wrapper, not the SVG. A pointerdown there never
 * started a pan — the reported symptom was "panning works at the top
 * (over the SVG) but not at the bottom, until a tall container is
 * expanded and the SVG grows to cover the band." The fix moves the
 * handler to the scroll wrapper and guards on "background-ness"
 * (`ev.target === wrapper || ev.target instanceof SVGSVGElement`).
 *
 * These tests dispatch on the SAME element a real click hits — the
 * wrapper for the dead zone, the SVG root for the canvas background, a
 * leaf rect for a node — so the guard is exercised honestly rather than
 * vacuously (see the [[feedback_visual_smoke_vs_property_tests]] trap:
 * dispatching on the wrong element would pass while the browser bug
 * survives).
 *
 * jsdom has no layout, so `scrollWidth`/`clientWidth`/… all read 0 and
 * the handler's overflow guard would always bail. We mock those dims, and
 * back `scrollLeft`/`scrollTop` with real storage (jsdom's defaults
 * ignore writes) so the pan-move assertion is observable.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  // Keep replication OFF so the canvas geometry stays simple and the leaf
  // selector below is deterministic (parity with graph-view-drag.test).
  setReplicationEnabled(false);
};

const resetAll = (): void => {
  __resetReplicationForTests();
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

/** A bubbling pointer-shaped event (button 0). Handlers read clientX/Y,
 *  button and pointerId — all carried by MouseEvent. bubbles:true so
 *  Solid's delegated `onPointerDown` at the document catches it. */
const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, button: 0, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

/**
 * Give an element real scroll storage + a chosen overflow state. jsdom
 * reports 0 for every layout dim and silently drops scroll writes, so
 * without this the overflow guard always bails and scroll moves are
 * invisible.
 */
const mockScrollableWrapper = (
  el: Element,
  opts: { overflow: boolean; left?: number; top?: number },
): { scroll: { left: number; top: number } } => {
  const scroll = { left: opts.left ?? 0, top: opts.top ?? 0 };
  const dim = opts.overflow
    ? { scrollWidth: 2000, clientWidth: 500, scrollHeight: 2000, clientHeight: 500 }
    : { scrollWidth: 500, clientWidth: 500, scrollHeight: 500, clientHeight: 500 };
  for (const [key, value] of Object.entries(dim)) {
    Object.defineProperty(el, key, { configurable: true, value });
  }
  Object.defineProperty(el, "scrollLeft", {
    configurable: true,
    get: () => scroll.left,
    set: (v: number) => {
      scroll.left = v;
    },
  });
  Object.defineProperty(el, "scrollTop", {
    configurable: true,
    get: () => scroll.top,
    set: (v: number) => {
      scroll.top = v;
    },
  });
  return { scroll };
};

describe("GraphView — drag-to-pan on the scroll wrapper", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("starts a pan from the wrapper's own background — the dead zone below a short SVG", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const wrapper = container.querySelector(".graph-view") as HTMLElement;
    expect(wrapper).not.toBeNull();
    const { scroll } = mockScrollableWrapper(wrapper, { overflow: true, left: 100, top: 100 });

    // Pointerdown ON the wrapper (target === wrapper) — exactly the dead
    // zone the old SVG-bound handler couldn't see.
    wrapper.dispatchEvent(pointerEvt("pointerdown", 300, 300));
    expect(wrapper.classList.contains("panning")).toBe(true);

    // Drag up-left: the canvas should scroll opposite the pointer.
    wrapper.dispatchEvent(pointerEvt("pointermove", 270, 260));
    expect(scroll.left).toBe(130); // 100 − (270 − 300)
    expect(scroll.top).toBe(140); // 100 − (260 − 300)

    wrapper.dispatchEvent(pointerEvt("pointerup", 270, 260));
    expect(wrapper.classList.contains("panning")).toBe(false);
  });

  it("starts a pan from the SVG root background too", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const wrapper = container.querySelector(".graph-view") as HTMLElement;
    mockScrollableWrapper(wrapper, { overflow: true });
    const svg = container.querySelector("svg.graph-view-svg") as SVGSVGElement;
    expect(svg).not.toBeNull();

    // target === svg root (an SVGSVGElement) — the canvas background.
    svg.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    expect(wrapper.classList.contains("panning")).toBe(true);

    wrapper.dispatchEvent(pointerEvt("pointerup", 200, 200));
    expect(wrapper.classList.contains("panning")).toBe(false);
  });

  it("starts a pan from a container BODY rect — drag inside an expanded round moves the view", () => {
    // Regression for "I can't drag inside an expanded DES round to move the
    // view" (2026-06-03). A populated container's interior is fully covered by
    // its own `graph-container-rect`, which paints above the SVG root — so a
    // pointerdown there hits the rect, not the SVG background. Before the fix
    // the pan guard only accepted the wrapper / SVG root, so the gesture
    // bailed and nothing scrolled. The body rect owns no click/drag gesture of
    // its own (the header band is a separate rect with its own pointerdown),
    // so treating it as a pan surface is safe.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const wrapper = container.querySelector(".graph-view") as HTMLElement;
    const { scroll } = mockScrollableWrapper(wrapper, { overflow: true, left: 100, top: 100 });
    const containerRect = container.querySelector(".graph-container-rect") as SVGRectElement;
    expect(containerRect).not.toBeNull();

    // target === a container body rect — the surface inside an expanded round.
    containerRect.dispatchEvent(pointerEvt("pointerdown", 300, 300));
    expect(wrapper.classList.contains("panning")).toBe(true);

    // Drag down-right: the canvas scrolls opposite the pointer.
    wrapper.dispatchEvent(pointerEvt("pointermove", 340, 360));
    expect(scroll.left).toBe(60); // 100 − (340 − 300)
    expect(scroll.top).toBe(40); // 100 − (360 − 300)

    wrapper.dispatchEvent(pointerEvt("pointerup", 340, 360));
    expect(wrapper.classList.contains("panning")).toBe(false);
  });

  it("does NOT pan when the pointerdown lands on a node (a leaf rect)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const wrapper = container.querySelector(".graph-view") as HTMLElement;
    mockScrollableWrapper(wrapper, { overflow: true });
    const leafRect = container.querySelector(".graph-leaf-rect") as SVGRectElement;
    expect(leafRect).not.toBeNull();

    // A child rect is a node the user means to scrub/drag — the guard
    // (and the leaf's own stopPropagation) must keep pan from firing.
    leafRect.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    expect(wrapper.classList.contains("panning")).toBe(false);
  });

  it("is a no-op when nothing overflows — there is nothing to pan", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const wrapper = container.querySelector(".graph-view") as HTMLElement;
    mockScrollableWrapper(wrapper, { overflow: false, left: 100, top: 100 });

    wrapper.dispatchEvent(pointerEvt("pointerdown", 300, 300));
    expect(wrapper.classList.contains("panning")).toBe(false);
  });
});
