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

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, setReplicationMode, toggleCollapse } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// FIPS 46-3 Appendix B test vector — used to seed an actual DES trace
// so the rendered graph has aux edges (and therefore replicate-able sources).
const seedDesTrace = (): void => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: { shape: "bytes" as const, bytes: bytesFromHex("0123456789abcdef") },
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
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

  it("renders a rejoin chip for each round at its direction-aware position (Phase 6b)", () => {
    const { container } = render(() => <GraphView />);
    // Phase 6b — rejoin synthetic now has a layout box (bottom edge
    // for DES's vertical-flow "rounds" group parent). The chip uses
    // a distinct testid `graph-rejoin-*` so a stray query for
    // `graph-leaf-*` doesn't pick it up — the rejoin isn't a leaf
    // and isn't a drop target.
    for (const r of [1, 8, 16]) {
      const rejoin = container.querySelector(`[data-testid="graph-rejoin-round.${r}:rejoin"]`);
      expect(rejoin, `round.${r}:rejoin chip should render`).not.toBeNull();
    }
    // Old leaf-* testid should remain absent — the chip is rendered
    // via `RejoinChip`, not `LeafRect`, so it has no drop anchor and
    // is exempt from leaf-style affordances.
    const asLeaf = container.querySelector('[data-testid="graph-leaf-round.1:rejoin"]');
    expect(asLeaf).toBeNull();
  });

  it("renders a passthrough chip in each round's empty L track (Phase 6b-ii)", () => {
    const { container } = render(() => <GraphView />);
    // Phase 6b-ii — the empty L track now carries a synthetic
    // passthrough chip (`{roundId}:passthrough-{trackIdx}`). Distinct
    // testid `graph-passthrough-*` so a stray query for `graph-leaf-*`
    // doesn't pick it up — the chip isn't a leaf and isn't a drop
    // target (drop gutters land in Phase 6d via dedicated gutter strips).
    for (const r of [1, 8, 16]) {
      const pt = container.querySelector(
        `[data-testid="graph-passthrough-round.${r}:passthrough-0"]`,
      );
      expect(pt, `round.${r}:passthrough-0 chip should render`).not.toBeNull();
    }
  });

  it('passthrough chip label uses the track name ("L passthrough" for DES)', () => {
    const { container } = render(() => <GraphView />);
    const pt = container.querySelector('[data-testid="graph-passthrough-round.1:passthrough-0"]');
    expect(pt?.textContent).toContain("L passthrough");
  });

  it("places the rejoin chip BELOW the round's track columns (vertical-flow parent)", () => {
    const { container } = render(() => <GraphView />);
    // The "rounds" group is `kind: "group"` (vertical-flow), so the
    // rejoin chip sits BELOW the columns rather than to their right.
    // Compare the rejoin chip's `y` to a body leaf's `y`: rejoin > leaf.
    // SVG positions live on the inner <rect>, not on the <g> wrapper.
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

  // ─── Regression — replicas in feistel right gutter ─────────────────
  //
  // Phase 6a-revision (commit 12b88e0) introduced a layout that iterates
  // `container.feistelTracks` only. Replica synthetic ids (e.g.
  // `key-schedule@->round.1.xor-K`) live in flat `childIds` but NOT in
  // any `feistelTracks` entry, so they were initially skipped — their
  // box stayed unset and `<Show when={box()}>` omitted them from the
  // DOM, making the source vanish in fully-replicated mode. The second
  // pass in the kind === "feistel" branch places them in the right
  // gutter; this test guards that fix.

  it("places key-schedule replicas in the right gutter when replication is enabled", () => {
    // DES key-schedule has 16 aux edges → exceeds default threshold of 6
    // → auto-replicates with just master switch ON (no per-source override
    // needed). Per [[feedback-jsdom-replication-off-default]]
    // setReplicationEnabled must be called explicitly before render —
    // localStorage default returns false in jsdom.
    // Replication needs aux edges → needs a real trace.
    seedDesTrace();
    const specId = useSpec()().id;
    setReplicationEnabled(true);
    setReplicationMode(specId, "key-schedule", "always");

    const { container } = render(() => <GraphView />);

    // Replicas land in two distinct buckets by design:
    //   - 15 aux-fan-out replicas, one per round.2..round.16's xor-K,
    //     placed inside each round's RIGHT GUTTER by the new feistel
    //     layout pass.
    //   - 1 spine-replica for round.1.xor-K, laid out at the SOURCE'S
    //     old root slot (where `key-schedule` used to render). Requires
    //     the splice-anchor fix in `replicateHighFanoutSources` (same
    //     day): the anchor for spine-replicas had to switch from
    //     `edge.to` (consumer's id) to `edge.from` (source's id) so
    //     it lands correctly when source's parent differs from
    //     consumer's parent. DES is the first cipher with that
    //     mismatch — `key-schedule` at root vs `round.1.xor-K` inside
    //     `round.1` inside the "rounds" group. The code comment at
    //     graph.ts:1786 originally flagged this as "defer until
    //     something demands it"; DES demanded it.
    //
    // Spot-check round-internal replicas (right-gutter pass).
    for (const roundIdx of [2, 8, 16]) {
      const replica = container.querySelector(
        `[data-testid="graph-leaf-key-schedule@->round.${roundIdx}.xor-K"]`,
      );
      expect(
        replica,
        `key-schedule replica for round.${roundIdx}.xor-K should render`,
      ).not.toBeNull();
    }

    // The round.1 spine-replica is rendered at root in key-schedule's
    // old slot. Pin explicitly so a regression in the splice-anchor
    // fix surfaces here instead of as a silent count mismatch.
    const round1Replica = container.querySelector(
      '[data-testid="graph-leaf-key-schedule@->round.1.xor-K"]',
    );
    expect(
      round1Replica,
      "round.1.xor-K spine-replica should render after splice anchor fix",
    ).not.toBeNull();

    // 16 total replicas rendered = 15 aux-fan-out (rounds 2-16) +
    // 1 spine-replica (round.1).
    const allReplicas = container.querySelectorAll(
      '[data-testid^="graph-leaf-key-schedule@->round."]',
    );
    expect(allReplicas.length).toBe(16);
  });
});
