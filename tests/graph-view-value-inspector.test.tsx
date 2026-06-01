// @vitest-environment jsdom

/**
 * Component test for the value-inspector panel.
 *
 * The pure-function lookups are covered by `edge-value-lookup.test.ts`
 * (edges) and `node-value-lookup.test.ts` (nodes) — this file pins the
 * UI plumbing across edges + leaves + endpoint pills:
 *
 *   1. Collapsed-by-default header is mounted in the toolbar band.
 *   2. CLICKING an edge selects it (panel auto-opens; the visible path
 *      gets `.graph-edge-selected`); body shows from → to identity +
 *      kind badge + value row.
 *   3. CLICKING a leaf selects it for the inspector AND scrubs the
 *      trace (additive behavior); the visible leaf gets
 *      `.graph-leaf-selected`; body shows the leaf id, kind badge, and
 *      the leaf's state value (state-after at the leaf's own frame).
 *   4. CLICKING an endpoint pill selects it; the pill gets
 *      `.graph-endpoint-selected`; body shows the "input pill" / "output
 *      pill" descriptive label.
 *   5. Re-clicking the same target clears the inspector (toggle).
 *   6. Clicking a DIFFERENT target replaces the selection (mixing kinds
 *      — leaf then edge then pill — confirms the single-target model).
 *   7. Swapping the cipher spec clears the selection so a stale target
 *      from a prior spec doesn't render "missing" against stale ids.
 *
 * No hover tests: click-only is part of the contract.
 *
 * Byte-native AES-128 (Slice B1; AddRoundKey merged to one `xor-with-aux@1`
 * leaf in Finding F3) is the fixture — well-known stable id set: the
 * `key-schedule → initial.add-round-key` aux edge carries `roundKey.0`, which
 * the merged AddRoundKey leaf reads internally (so it IS the round-key fan-out
 * consumer now).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { CIPHER_OUTPUT_ID } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { INPUT_SOURCE_ID } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import {
  __resetValueInspectorForTests,
  setInspectorPanelOpen,
  useSelectedTarget,
} from "@/ui/stores/view-value-inspector";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  // Byte-native AES-128 (Slice B1) auto-ON's replication via GraphView's
  // `effectiveReplicate` (ported spec). Force it OFF — simulating an explicit
  // user toggle — so `key-schedule`'s 11 round-key edges stay un-replicated
  // and the edge-key selectors below remain stable.
  setReplicationEnabled(false);
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

/**
 * Synthetic pointer event. jsdom lacks a real `PointerEvent`, so we build a
 * `MouseEvent` and graft a `pointerId` — the same shim the drag tests use.
 */
const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

/**
 * Click a leaf the way a real browser does. Post-Finding 4 every AES leaf is
 * draggable, so the `<g>` carries `onPointerDown` instead of `onClick` — a
 * click is a pointerdown + sub-threshold (no-move) pointerup, after which the
 * drag handler's `onClickFallback` runs the same scrub + inspector-select the
 * old `onClick` did. `fireEvent.click` does NOT traverse that path, so leaf
 * selections must be driven through here. (Edges + endpoint pills keep their
 * direct `onClick`, so those still use `fireEvent.click`.)
 */
const clickLeaf = (leaf: SVGGElement): void => {
  leaf.dispatchEvent(pointerEvt("pointerdown", 100, 100));
  window.dispatchEvent(pointerEvt("pointerup", 100, 100));
};

const findEdgePathByEndpoints = (
  container: HTMLElement,
  fromId: string,
  toId: string,
  auxKey: string,
): SVGPathElement | null => {
  // The hit-path carries `data-edge-key` (it sits on top of the visible
  // `.graph-edge` and catches click). Querying `[data-edge-key]` is the
  // stable selector since the visible path doesn't carry it.
  const paths = container.querySelectorAll<SVGPathElement>("path[data-edge-key]");
  for (const p of paths) {
    const key = p.getAttribute("data-edge-key");
    if (key === null) continue;
    if (key === `${fromId}|${toId}|${auxKey}|aux`) return p;
    if (key === `${fromId}|${toId}|${auxKey}|state`) return p;
  }
  return null;
};

/**
 * Locate a leaf's wrapping <g> by its full stepId. Matches the existing
 * `clicking a leaf node moves the trace scrubber` test's selector: we
 * walk every `.graph-leaf` and check its `<title>` text. This is the
 * stable way to find a NESTED leaf — `data-drop-anchor` matches too but
 * the title query disambiguates leaves that share an anchor with their
 * source (replicas / chips).
 *
 * Note: post-Finding 4 EVERY AES leaf is draggable (root-level, iteration-
 * body, and now `group`-nested round-body leaves alike), so `onClick` is
 * wired to `undefined` on the <g> and `fireEvent.click` doesn't reach the
 * handler — clicks flow through a pointerdown + sub-threshold-release path
 * that fireEvent doesn't simulate. Leaf clicks in this file therefore go
 * through the `clickLeaf` helper above; this lookup just resolves the <g>.
 */
const findLeafByStepId = (container: HTMLElement, stepId: string): SVGGElement | null => {
  const leaves = container.querySelectorAll<SVGGElement>("g.graph-leaf");
  for (const g of Array.from(leaves)) {
    const title = g.querySelector("title")?.textContent ?? "";
    if (title.startsWith(`${stepId} `) || title === stepId) return g;
  }
  return null;
};

/** Locate an endpoint pill by side — the pill's class encodes "input" or "output". */
const findEndpointPill = (container: HTMLElement, side: "input" | "output"): SVGGElement | null => {
  return container.querySelector<SVGGElement>(`g.graph-endpoint-${side}`);
};

describe("GraphView — value-inspector panel (click-only, edges + nodes)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the inspector panel header (collapsed by default)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector('[data-testid="value-inspector-panel-toggle"]');
    expect(toggle).not.toBeNull();
    expect(container.querySelector('[data-testid="value-inspector-body"]')).toBeNull();
  });

  it("opens the body when the header is clicked", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector('[data-testid="value-inspector-panel-toggle"]');
    fireEvent.click(toggle as Element);
    expect(container.querySelector('[data-testid="value-inspector-body"]')).not.toBeNull();
  });

  it("clicking an aux edge selects it, auto-opens the panel, and populates the body", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-schedule",
      "initial.add-round-key",
      "roundKey.0",
    );
    expect(path).not.toBeNull();
    fireEvent.click(path as SVGPathElement);
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body).not.toBeNull();
    // Halo on the VISIBLE `.graph-edge` sibling.
    const visibleEdge = path?.parentElement?.querySelector(".graph-edge");
    expect(visibleEdge?.classList.contains("graph-edge-selected")).toBe(true);
    expect(body?.textContent).toContain("key-schedule");
    expect(body?.textContent).toContain("initial.add-round-key");
    // First 4 bytes of the input key as a fingerprint for round key 0.
    expect(body?.textContent).toContain("00010203");
    const target = useSelectedTarget()();
    expect(target).toEqual({
      kind: "edge",
      key: "key-schedule|initial.add-round-key|roundKey.0|aux",
    });
  });

  it("clicking a leaf selects it AND scrubs the trace (scrub-plus-inspect)", () => {
    seedAes128Trace();
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    // Nested group leaf (inside round.5) — draggable post-Finding 4, so the
    // click is driven through the pointer path (`clickLeaf`), which fires the
    // drag handler's sub-threshold `onClickFallback`.
    const leaf = findLeafByStepId(container as HTMLElement, "round.5.mix-columns");
    expect(leaf).not.toBeNull();
    clickLeaf(leaf as SVGGElement);
    // Halo on the wrapping <g>.
    expect(leaf?.classList.contains("graph-leaf-selected")).toBe(true);
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body).not.toBeNull();
    // Identity row mentions the leaf id (single span, no arrow).
    expect(body?.textContent).toContain("round.5.mix-columns");
    // Kind badge shows "state" (the leaf produces a state value at its frame).
    expect(body?.textContent).toMatch(/state/);
    const target = useSelectedTarget()();
    expect(target).toEqual({ kind: "node", id: "round.5.mix-columns" });
  });

  it("clicking an endpoint pill selects it and shows the plaintext bytes in the inspector", () => {
    seedAes128Trace();
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    const pill = findEndpointPill(container as HTMLElement, "input");
    expect(pill).not.toBeNull();
    fireEvent.click(pill as SVGGElement);
    expect(pill?.classList.contains("graph-endpoint-selected")).toBe(true);
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body?.textContent).toContain(INPUT_SOURCE_ID);
    // Endpoint pill kind badge says "input pill"; value row shows the
    // cipher's plaintext bytes (formatted with the active ByteFormat).
    // The AES-128 fixture uses the FIPS-197 Appendix B plaintext
    // `00112233445566778899aabbccddeeff`.
    expect(body?.textContent).toMatch(/input pill/);
    expect(body?.textContent).toMatch(/00112233445566778899aabbccddeeff/);
    expect(useSelectedTarget()()).toEqual({ kind: "node", id: INPUT_SOURCE_ID });
  });

  it("clicking the output pill selects it (verifies side discrimination)", () => {
    seedAes128Trace();
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    const pill = findEndpointPill(container as HTMLElement, "output");
    expect(pill).not.toBeNull();
    fireEvent.click(pill as SVGGElement);
    expect(useSelectedTarget()()).toEqual({ kind: "node", id: CIPHER_OUTPUT_ID });
  });

  it("clicking the same edge twice un-selects it", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-schedule",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedTarget()()).not.toBeNull();
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedTarget()()).toBeNull();
  });

  it("clicking the same leaf twice un-selects it", () => {
    seedAes128Trace();
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    const leaf = findLeafByStepId(container as HTMLElement, "round.5.mix-columns");
    clickLeaf(leaf as SVGGElement);
    expect(useSelectedTarget()()).not.toBeNull();
    clickLeaf(leaf as SVGGElement);
    expect(useSelectedTarget()()).toBeNull();
  });

  it("clicking a different element replaces the selection (leaf → edge → pill)", () => {
    seedAes128Trace();
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    // Start with a nested group leaf (draggable post-Finding 4 → pointer path).
    const leaf = findLeafByStepId(container as HTMLElement, "round.5.mix-columns");
    clickLeaf(leaf as SVGGElement);
    expect(useSelectedTarget()()).toEqual({ kind: "node", id: "round.5.mix-columns" });
    // Switch to an edge.
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-schedule",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedTarget()()).toEqual({
      kind: "edge",
      key: "key-schedule|initial.add-round-key|roundKey.0|aux",
    });
    // Switch to the input pill.
    const pill = findEndpointPill(container as HTMLElement, "input");
    fireEvent.click(pill as SVGGElement);
    expect(useSelectedTarget()()).toEqual({ kind: "node", id: INPUT_SOURCE_ID });
  });

  it("renders the no-trace hint when the user hasn't run yet (trace null)", () => {
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-schedule",
      "initial.add-round-key",
      "roundKey.0",
    );
    if (path === null) {
      const body = container.querySelector('[data-testid="value-inspector-body"]');
      expect(body?.textContent).toMatch(/Click an edge|Run the cipher/);
      return;
    }
    fireEvent.click(path);
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body?.textContent).toMatch(/Run the cipher/);
  });

  it("swapping the spec clears the selection (no stale identity)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-schedule",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedTarget()()).not.toBeNull();
    setCipherMode("ecb");
    expect(useSelectedTarget()()).toBeNull();
  });

  // Block-chip click coverage is handled by the pure-function lookup
  // tests in `node-value-lookup.test.ts` — driving the iterate-collapse
  // chevron in jsdom is brittle.
});
