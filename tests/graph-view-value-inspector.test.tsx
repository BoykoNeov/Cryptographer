// @vitest-environment jsdom

/**
 * Component test for the value-inspector panel (formerly "edge
 * inspector" — renamed when the click model dropped hover and the
 * panel's domain expanded beyond edges).
 *
 * The pure-function lookup is covered by `edge-value-lookup.test.ts` —
 * this file pins the UI plumbing:
 *
 *   1. The collapsed-by-default panel is mounted in the toolbar band.
 *   2. CLICKING an edge selects it (panel auto-opens, the visible path
 *      gets the `.graph-edge-selected` halo class) and populates the
 *      body with the resolved value (kind badge + value row).
 *   3. Clicking the SAME edge un-selects it (toggle behavior).
 *   4. Clicking a DIFFERENT edge replaces the selection.
 *   5. Swapping the cipher spec clears the selection so a stale edge
 *      from a prior spec doesn't render "missing" against stale
 *      identity.
 *   6. With no trace yet (user hasn't run), clicking an edge — if any
 *      are drawn — produces the no-trace hint copy.
 *
 * No hover tests: click-only is part of the contract.
 *
 * AES-128 is the fixture — a spec with a stable, well-known set of
 * edges (`key-expansion → initial.add-round-key` carrying
 * `roundKey.0`).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import {
  __resetValueInspectorForTests,
  setInspectorPanelOpen,
  useSelectedEdgeKey,
} from "@/ui/stores/view-value-inspector";
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
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
  __resetValueInspectorForTests();
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
    // Two valid kinds; either matches if the from/to/auxKey triple does.
    if (key === `${fromId}|${toId}|${auxKey}|aux`) return p;
    if (key === `${fromId}|${toId}|${auxKey}|state`) return p;
  }
  return null;
};

describe("GraphView — value-inspector panel (click-only)", () => {
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
    // Body is hidden when closed.
    expect(container.querySelector('[data-testid="value-inspector-body"]')).toBeNull();
  });

  it("opens the body when the header is clicked", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector('[data-testid="value-inspector-panel-toggle"]');
    expect(toggle).not.toBeNull();
    fireEvent.click(toggle as Element);
    expect(container.querySelector('[data-testid="value-inspector-body"]')).not.toBeNull();
  });

  it("clicking an aux edge selects it, auto-opens the panel, and populates the body", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-expansion",
      "initial.add-round-key",
      "roundKey.0",
    );
    expect(path).not.toBeNull();
    fireEvent.click(path as SVGPathElement);
    // Panel auto-opens on click.
    const body = container.querySelector('[data-testid="value-inspector-body"]');
    expect(body).not.toBeNull();
    // Halo class is on the VISIBLE `.graph-edge` sibling, not the hit-
    // path (the hit path is invisible so the halo would render nothing).
    const visibleEdge = path?.parentElement?.querySelector(".graph-edge");
    expect(visibleEdge?.classList.contains("graph-edge-selected")).toBe(true);
    // Identity row mentions both endpoints.
    expect(body?.textContent).toContain("key-expansion");
    expect(body?.textContent).toContain("initial.add-round-key");
    // Value row shows hex of the round key (16 bytes = 32 hex chars).
    // The AES-128 round key 0 is the input key itself; first 4 bytes
    // `00010203` is enough of a fingerprint.
    expect(body?.textContent).toContain("00010203");
    // Store reflects the selection.
    expect(useSelectedEdgeKey()()).toBe("key-expansion|initial.add-round-key|roundKey.0|aux");
  });

  it("clicking the same edge twice un-selects it", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-expansion",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedEdgeKey()()).not.toBeNull();
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedEdgeKey()()).toBeNull();
  });

  it("clicking a DIFFERENT edge replaces the selection", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const first = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-expansion",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(first as SVGPathElement);
    const initialSel = useSelectedEdgeKey()();
    expect(initialSel).not.toBeNull();
    // Pick a different edge from key-expansion (round 1 key).
    const second = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-expansion",
      "round.1.add-round-key",
      "roundKey.1",
    );
    expect(second).not.toBeNull();
    fireEvent.click(second as SVGPathElement);
    expect(useSelectedEdgeKey()()).not.toBe(initialSel);
    expect(useSelectedEdgeKey()()).toBe("key-expansion|round.1.add-round-key|roundKey.1|aux");
  });

  it("renders the no-trace hint when the user hasn't run yet (trace null)", () => {
    // aes128Spec is set by default, but no trace is seeded.
    setInspectorPanelOpen(true);
    const { container } = render(() => <GraphView />);
    const path = findEdgePathByEndpoints(
      container as HTMLElement,
      "key-expansion",
      "initial.add-round-key",
      "roundKey.0",
    );
    // No edges drawn if no trace; bail without failing — the panel just
    // shows the empty hint message.
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
      "key-expansion",
      "initial.add-round-key",
      "roundKey.0",
    );
    fireEvent.click(path as SVGPathElement);
    expect(useSelectedEdgeKey()()).not.toBeNull();
    // Swap to ECB mode — the watcher effect should clear the selection
    // when the spec.id changes. aes128 single-block → aes128-ecb has a
    // different spec.id, satisfying the createEffect dep.
    setCipherMode("ecb");
    // The clear runs in a createEffect; Solid flushes effects
    // synchronously for signals set imperatively (no batch), so the
    // signal reflects the change immediately.
    expect(useSelectedEdgeKey()()).toBeNull();
  });

  // Note: end-to-end block-chip-click wiring is intentionally NOT
  // covered by a component test — driving the iterate's collapse
  // chevron in jsdom is brittle on this layout, and the lookup
  // branches (block-chip incoming / outgoing / blocksFromAux /
  // outBlocksAux) are already pinned by `edge-value-lookup.test.ts`.
  // If a future regression makes the chip-edge keys differ from the
  // pure-function expectation, the pure test will fail first.
});
