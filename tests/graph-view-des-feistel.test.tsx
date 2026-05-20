// @vitest-environment jsdom

/**
 * Phase 6a of the DES + branching primitive plan
 * (`docs/plans/des-feistel.md`).
 *
 * Pins that GraphView renders without throwing for a DES spec — the
 * minimum bar for the new `kind === "feistel"` container layout
 * branch — and that the per-track children of each round get a layout
 * box (so they're visible chips inside the round, not collapsed into
 * a single horizontal row alongside the rejoin synthetic id).
 *
 * What this test does NOT check (deferred to Phase 6b / 6c / 6e):
 *
 *   - Rejoin chip rendering at the container right edge (Phase 6b).
 *   - Single-chip collapse of a feistel-round (Phase 6c — generic
 *     `collapseGraph` likely covers it; experiment pending).
 *   - Vertical stacking layout (L track above R track) — geometric
 *     assertions belong in the linear/component-test pair once the
 *     visual is settled in Phase 6b. Phase 6a's bar is "doesn't crash."
 *
 * Per `[[feedback-jsdom-pointer-events-gap]]` the smoke pass at the
 * end of Phase 6 is the discriminating check for SVG hit-testing
 * regressions; this jsdom test pins the DOM shape only.
 */

import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

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

describe("GraphView — DES feistel-round rendering (Phase 6a)", () => {
  beforeEach(() => {
    resetAll();
    // Use the spec-store setter so both encrypt/decrypt slots get rebuilt
    // via buildCanonicalPair — per [[feedback-setcipher-test-import]].
    setCipher("des");
  });

  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("does not throw when rendering the full DES spec", () => {
    expect(() => render(() => <GraphView />)).not.toThrow();
  });

  it("renders 16 round containers (one per feistel-round)", () => {
    const { container } = render(() => <GraphView />);
    // Container rects carry class `graph-container-feistel`.
    const feistelContainers = container.querySelectorAll(".graph-container-feistel");
    expect(feistelContainers.length).toBe(16);
  });

  it("renders the 4 R-track leaves inside each round (64 leaves total across rounds)", () => {
    const { container } = render(() => <GraphView />);
    // Spot-check round.1 — every R-track leaf should resolve to a LeafRect
    // with the matching data-testid.
    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.1.${leafSuffix}"]`);
      expect(node, `round.1.${leafSuffix} should render as a leaf`).not.toBeNull();
    }
    // And round.16, the no-swap round, to confirm the combineKind variant
    // doesn't change the per-track leaf rendering.
    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.16.${leafSuffix}"]`);
      expect(node, `round.16.${leafSuffix} should render as a leaf`).not.toBeNull();
    }
  });

  it("does NOT render a leaf rectangle for the rejoin synthetic id (Phase 6a — chip lands in Phase 6b)", () => {
    const { container } = render(() => <GraphView />);
    // Rejoin synthetic ids are in `graph.nodes` but the Phase 6a feistel
    // layout branch doesn't place them in `layout.boxes`. The render
    // pass's `<Show when={box()}>` therefore omits them from the DOM.
    // Phase 6b will add explicit placement at the container right edge;
    // when that lands this assertion flips to `not.toBeNull()` (or moves
    // to a new test file).
    const rejoin = container.querySelector('[data-testid="graph-leaf-round.1:rejoin"]');
    expect(rejoin).toBeNull();
  });

  // ─── Phase 6c — collapse to single round chip ──────────────────────
  //
  // The plan §Phase 2 proposed a dedicated `collapseFeistelRoundEdges`
  // transform; tests/feistel-collapse-generic.test.ts proved generic
  // `collapseGraph` is sufficient (it clears `childIds: []` on collapsed
  // entries). That triggers the existing `childIds.length === 0`
  // short-circuit at GraphView.tsx ~line 969 — collapsed feistel
  // containers render as leaf-sized chips BEFORE my Phase 6a `kind ===
  // "feistel"` branch is reached. So Phase 6c needs no new layout code;
  // these tests pin that behavior.

  it("collapsing a round renders it as a single chip; R-track leaves disappear", () => {
    const { container } = render(() => <GraphView />);
    // Sanity: round.1 leaves present before collapse.
    expect(container.querySelector('[data-testid="graph-leaf-round.1.expand-R"]')).not.toBeNull();

    const specId = useSpec()().id;
    toggleCollapse(specId, "round.1");

    // After collapse, the round container itself still renders (chevron + label
    // chip), but its R-track leaves are gone from the DOM.
    for (const leafSuffix of ["expand-R", "xor-K", "s-boxes", "p-permute"]) {
      const node = container.querySelector(`[data-testid="graph-leaf-round.1.${leafSuffix}"]`);
      expect(node, `round.1.${leafSuffix} should be hidden when round.1 is collapsed`).toBeNull();
    }
    // The collapsed container itself stays in the DOM.
    const collapsedRound = container.querySelector(
      '[data-testid="graph-container-header-round.1"]',
    );
    expect(collapsedRound, "collapsed round.1 container should still render").not.toBeNull();
  });
});
