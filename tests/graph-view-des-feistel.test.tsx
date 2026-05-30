// @vitest-environment jsdom

/**
 * GraphView rendering of `feistel-round` containers — retargeted to the
 * synthetic Feistel fixture in B4 (universal-port Phase 4d). After the DES
 * rebuild no shipped cipher uses `feistel-round`, but GraphView's
 * `kind === "feistel"` container layout (round containers, L/R passthrough
 * chips, rejoin chip, collapse) is a SURVIVING render path (Phase-5-doomed,
 * pending the obligatory port-native Feistel-diagram rebuild). It is the only
 * coverage of that render path, so it is exercised here against
 * `buildSyntheticFeistelSpec(16)` — shaped exactly like the old DES (16
 * feistel-rounds, 4-leaf R tracks `expand-R/xor-K/s-boxes/p-permute`, empty
 * L tracks, round 16 = no-swap), injected via `__setSpecForTests`.
 *
 * The DES-only "key-schedule replicas in the feistel right gutter" test was
 * dropped: it needs a RUNNABLE feistel spec with an aux fan-out (16 round
 * keys), which no construct provides post-B4 (the toy F uses a param, the
 * synthetic uses inert leaves). The generic replica-placement mechanism is
 * covered by `replicate-fanout` tests; the feistel right-gutter placement is
 * Phase-5-doomed and will be re-covered by the diagram rebuild.
 */

import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, __setSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSyntheticFeistelSpec } from "./fixtures/synthetic-feistel-rounds";

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

describe("GraphView — feistel-round rendering (synthetic spec)", () => {
  beforeEach(() => {
    resetAll();
    // feistel-round is not a selector cipher; inject the synthetic Feistel
    // fixture (shaped like the old DES) so GraphView's feistel layout renders.
    __setSpecForTests(buildSyntheticFeistelSpec(16));
  });

  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("does not throw when rendering the full feistel spec", () => {
    expect(() => render(() => <GraphView />)).not.toThrow();
  });

  it("renders 16 round containers (one per feistel-round)", () => {
    const { container } = render(() => <GraphView />);
    const feistelContainers = container.querySelectorAll(".graph-container-feistel");
    expect(feistelContainers.length).toBe(16);
  });

  it("renders the 4 R-track leaves inside each round", () => {
    const { container } = render(() => <GraphView />);
    // Spot-check round.1 — every R-track leaf resolves to a LeafRect.
    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.1.${leafSuffix}"]`);
      expect(node, `round.1.${leafSuffix} should render as a leaf`).not.toBeNull();
    }
    // And round.16 (no-swap) to confirm the combineKind variant doesn't
    // change the per-track leaf rendering.
    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.16.${leafSuffix}"]`);
      expect(node, `round.16.${leafSuffix} should render as a leaf`).not.toBeNull();
    }
  });

  it("renders a rejoin chip for each round at its direction-aware position", () => {
    const { container } = render(() => <GraphView />);
    for (const r of [1, 8, 16]) {
      const rejoin = container.querySelector(`[data-testid="graph-rejoin-round.${r}:rejoin"]`);
      expect(rejoin, `round.${r}:rejoin chip should render`).not.toBeNull();
    }
    // The chip is rendered via RejoinChip, not LeafRect — no leaf testid.
    const asLeaf = container.querySelector('[data-testid="graph-leaf-round.1:rejoin"]');
    expect(asLeaf).toBeNull();
  });

  it("renders a passthrough chip in each round's empty L track", () => {
    const { container } = render(() => <GraphView />);
    for (const r of [1, 8, 16]) {
      const pt = container.querySelector(
        `[data-testid="graph-passthrough-round.${r}:passthrough-0"]`,
      );
      expect(pt, `round.${r}:passthrough-0 chip should render`).not.toBeNull();
    }
  });

  it('passthrough chip label uses the track name ("L passthrough")', () => {
    const { container } = render(() => <GraphView />);
    const pt = container.querySelector('[data-testid="graph-passthrough-round.1:passthrough-0"]');
    expect(pt?.textContent).toContain("L passthrough");
  });

  it("places the rejoin chip BELOW the round's track columns (vertical-flow parent)", () => {
    const { container } = render(() => <GraphView />);
    // The "rounds" group is `kind: "group"` (vertical-flow), so the rejoin
    // chip sits BELOW the columns. Compare the rejoin chip's y to a body
    // leaf's y: rejoin > leaf. SVG positions live on the inner <rect>.
    const rejoinRect = container.querySelector(
      '[data-testid="graph-rejoin-round.1:rejoin"] rect',
    ) as SVGRectElement | null;
    const bodyLeafRect = container.querySelector(
      '[data-testid="graph-leaf-round.1.p-permute"] rect',
    ) as SVGRectElement | null;
    expect(rejoinRect, "rejoin chip should render").not.toBeNull();
    expect(bodyLeafRect, "round.1.p-permute (R track tail) should render").not.toBeNull();
    if (rejoinRect && bodyLeafRect) {
      const rejoinY = Number(rejoinRect.getAttribute("y"));
      const bodyY = Number(bodyLeafRect.getAttribute("y"));
      expect(rejoinY, "rejoin chip should sit BELOW the R track tail").toBeGreaterThan(bodyY);
    }
  });

  // Collapse — generic `collapseGraph` clears `childIds: []` on a collapsed
  // feistel-round, triggering GraphView's `childIds.length === 0`
  // short-circuit so the round renders as a single chip. No feistel-specific
  // layout code needed (proved by feistel-collapse-generic.test.ts).
  it("collapsing a round renders it as a single chip; R-track leaves disappear", () => {
    const { container } = render(() => <GraphView />);
    expect(container.querySelector('[data-testid="graph-leaf-round.1.expand-R"]')).not.toBeNull();

    const specId = useSpec()().id;
    toggleCollapse(specId, "round.1", false);

    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.1.${leafSuffix}"]`);
      expect(node, `round.1.${leafSuffix} should be hidden when round.1 is collapsed`).toBeNull();
    }
    const collapsedRound = container.querySelector(
      '[data-testid="graph-container-header-round.1"]',
    );
    expect(collapsedRound, "collapsed round.1 container should still render").not.toBeNull();
  });
});
