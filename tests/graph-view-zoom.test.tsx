// @vitest-environment jsdom

/**
 * Component tests for the graph view's zoom toolbar (Slice 3 of the
 * graph-narrative-and-zoom plan). Asserts the visible UI contract:
 *
 *   1. The readout starts at 100% on a fresh spec.
 *   2. [+] and [−] step the readout up / down by VIEW_ZOOM_BUTTON_STEP.
 *   3. [reset] returns to 100%.
 *   4. [+] is disabled at max, [−] is disabled at min, [reset] is disabled
 *      at default — so the button states actually reflect zoom limits.
 *   5. The SVG's rendered `width` attribute scales with zoom while the
 *      `viewBox` stays at the logical canvas dimensions (the core
 *      invariant that lets pin coordinates stay in viewBox units).
 *
 * Wheel handling is deliberately NOT tested here — the wheel listener
 * depends on layout dimensions jsdom doesn't compute, and the plan
 * explicitly defers wheel verification to a manual browser pass.
 *
 * AES-128 is the fixture so the graph has meaningful canvas dimensions
 * to scale.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import {
  VIEW_ZOOM_DEFAULT,
  VIEW_ZOOM_MAX,
  VIEW_ZOOM_MIN,
  __resetViewZoomForTests,
  setViewZoom,
} from "@/ui/stores/view-zoom";
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
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
  __resetViewZoomForTests();
};

const findZoomReadout = (container: ParentNode): HTMLElement | null =>
  container.querySelector('[data-testid="graph-view-zoom-readout"]') as HTMLElement | null;

const findZoomButtons = (
  container: ParentNode,
): { minus: HTMLButtonElement; plus: HTMLButtonElement; reset: HTMLButtonElement } => {
  const minus = container.querySelector(
    'button[aria-label="Zoom out"]',
  ) as HTMLButtonElement | null;
  const plus = container.querySelector('button[aria-label="Zoom in"]') as HTMLButtonElement | null;
  const reset = container.querySelector(
    'button[aria-label="Reset zoom"]',
  ) as HTMLButtonElement | null;
  if (!minus || !plus || !reset) {
    throw new Error(`Zoom buttons missing: minus=${!!minus} plus=${!!plus} reset=${!!reset}`);
  }
  return { minus, plus, reset };
};

describe("GraphView — zoom toolbar (Slice 3)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("readout starts at 100% on a fresh spec", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    expect(findZoomReadout(container)?.textContent?.trim()).toBe("100%");
  });

  it("clicking [+] increases zoom by one button step", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const { plus } = findZoomButtons(container);
    plus.click();
    expect(findZoomReadout(container)?.textContent?.trim()).toBe("110%");
  });

  it("clicking [−] decreases zoom by one button step", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const { minus } = findZoomButtons(container);
    minus.click();
    expect(findZoomReadout(container)?.textContent?.trim()).toBe("90%");
  });

  it("[reset] returns the readout to 100%", () => {
    seedAes128Trace();
    setViewZoom(aes128Spec.id, 1.5);
    const { container } = render(() => <GraphView />);
    expect(findZoomReadout(container)?.textContent?.trim()).toBe("150%");
    findZoomButtons(container).reset.click();
    expect(findZoomReadout(container)?.textContent?.trim()).toBe("100%");
  });

  it("[+] is disabled at VIEW_ZOOM_MAX; [−] is enabled there", () => {
    seedAes128Trace();
    setViewZoom(aes128Spec.id, VIEW_ZOOM_MAX);
    const { container } = render(() => <GraphView />);
    const { minus, plus } = findZoomButtons(container);
    expect(plus.disabled).toBe(true);
    expect(minus.disabled).toBe(false);
  });

  it("[−] is disabled at VIEW_ZOOM_MIN; [+] is enabled there", () => {
    seedAes128Trace();
    setViewZoom(aes128Spec.id, VIEW_ZOOM_MIN);
    const { container } = render(() => <GraphView />);
    const { minus, plus } = findZoomButtons(container);
    expect(minus.disabled).toBe(true);
    expect(plus.disabled).toBe(false);
  });

  it("[reset] is disabled at VIEW_ZOOM_DEFAULT (no-op state)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const { reset } = findZoomButtons(container);
    expect(reset.disabled).toBe(true);
    // After a non-default zoom, reset becomes enabled.
    setViewZoom(aes128Spec.id, 1.3);
    expect(reset.disabled).toBe(false);
  });

  it("SVG `width` scales with zoom while `viewBox` stays at logical canvas dims", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const svg = container.querySelector("svg.graph-view-svg") as SVGSVGElement | null;
    expect(svg).not.toBeNull();
    if (!svg) return;

    const viewBoxAtDefault = svg.getAttribute("viewBox") ?? "";
    const widthAtDefault = Number(svg.getAttribute("width"));
    expect(widthAtDefault).toBeGreaterThan(0);

    // Zoom in 2× — rendered width should double (within the rounding the
    // browser does on width attributes), viewBox should NOT change.
    setViewZoom(aes128Spec.id, 2.0);
    const widthAt2x = Number(svg.getAttribute("width"));
    expect(widthAt2x).toBe(widthAtDefault * 2);
    expect(svg.getAttribute("viewBox")).toBe(viewBoxAtDefault);

    // Zoom out 0.5× — rendered width halves, viewBox still unchanged.
    setViewZoom(aes128Spec.id, 0.5);
    const widthAtHalf = Number(svg.getAttribute("width"));
    expect(widthAtHalf).toBe(widthAtDefault * 0.5);
    expect(svg.getAttribute("viewBox")).toBe(viewBoxAtDefault);
  });

  it("button labels include the percentage in the title attribute (hover hint)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const { minus, plus, reset } = findZoomButtons(container);
    // The labels mention the percentage so a hover hints the boundary.
    expect(minus.title).toContain(`${Math.round(VIEW_ZOOM_MIN * 100)}%`);
    expect(plus.title).toContain(`${Math.round(VIEW_ZOOM_MAX * 100)}%`);
    expect(reset.title).toContain(`${Math.round(VIEW_ZOOM_DEFAULT * 100)}%`);
  });
});
