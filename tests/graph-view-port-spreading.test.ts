// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure helper exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `buildReplicaPlacement` + `replicaTargetXOffset`.

/**
 * Port-spreading at consumer head (follow-up to Slice 7c, 2026-05-16).
 *
 * Slice 7c stacked replicas vertically above each consumer by globally-
 * stable source rows. The remaining UX gap: every replica's outgoing
 * arrow lands at the SAME point on the consumer's top edge (midpoint),
 * so 3+ stacked replicas produce a fan-IN funnel — the arrows visually
 * overlap at the convergence point and the 12 px `.graph-edge-hit`
 * stroke's hit zones collapse onto each other near the consumer head.
 *
 * Cure: `replicaTargetXOffset(edge, placement, portGap)` returns a per-
 * edge x-shift applied at the consumer's top edge. Globally-stable rows
 * → consistent per-source landing across the canvas (source A always at
 * row-0 offset, source B at row-1, etc.), mirroring Slice 7c's y-row
 * philosophy. `total === 1` short-circuits to 0 so single-source ciphers
 * (every aux-only baseline today) are byte-identical to pre-port-
 * spreading.
 *
 * Properties this file pins:
 *
 *   1. **Non-replica edge** — `edge.from` not in `sourceOf` → offset 0
 *      regardless of `portGap` (regular long-range aux / state spine
 *      edges don't fan in; they take a single direct path to their
 *      consumer).
 *   2. **Single-source no-op** — `rowOfSource.size === 1` → offset 0 for
 *      every edge from that source's replicas. Preserves the canonical
 *      AES + key-expansion-only-source visual.
 *   3. **Multi-source spread** — 2 sources at PORT_GAP=10 → offsets
 *      −5, +5 (centered around midpoint). 3 sources → −10, 0, +10. 4
 *      sources → −15, −5, +5, +15. Formula:
 *      `(row - (total - 1) / 2) * portGap`.
 *   4. **Kind-agnostic** — placement is built from `replicaOf` only
 *      (never edge.kind), so a state-kind edge from a replica gets the
 *      same offset as an aux-kind edge from the same row. Pre-verifies
 *      Slice 7b's `kind === "aux"` filter drop won't surprise port-
 *      spreading.
 *   5. **Composition with placement** — `buildReplicaPlacement` from a
 *      real `CipherGraph` literal feeds the helper without any glue.
 *      End-to-end smoke for the same data path the renderer uses.
 */

import type { CipherGraph, GraphEdge, GraphNode } from "@/core/graph";
import { buildReplicaPlacement, replicaTargetXOffset } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Helpers (same shape as graph-view-replica-placement.test.ts) ─────────

/** Make a leaf consumer node at root level. */
const consumerNode = (id: string): GraphNode => ({
  stepId: id,
  stepType: "test.consumer",
  label: id,
  containerPath: [],
});

/** Make a replica node pointing at `sourceId`. */
const replicaNode = (id: string, sourceId: string): GraphNode => ({
  stepId: id,
  stepType: "test.source",
  label: id,
  containerPath: [],
  replicaOf: sourceId,
});

/** Make an aux edge from replica → consumer. */
const auxEdge = (from: string, to: string): GraphEdge => ({
  from,
  to,
  auxKey: "test-key",
  kind: "aux",
});

const buildSyntheticGraph = (parts: {
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];
  readonly rootIds: readonly string[];
}): CipherGraph => ({
  nodes: parts.nodes,
  containers: [],
  edges: parts.edges,
  rootIds: parts.rootIds,
});

// ─── Test 1: Non-replica edge ─────────────────────────────────────────────

describe("port-spreading — non-replica edge", () => {
  it("returns 0 for an edge whose source is not in `sourceOf` (regular long-range edge)", () => {
    // Graph with a single replica from source A, plus an unrelated direct
    // edge `c1 → c2` (no replica involved). The helper should return 0
    // for the direct edge even though placement has a non-empty source
    // map — the offset only applies to replica-sourced edges.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), consumerNode("c2"), replicaNode("A->c1", "A")],
      edges: [auxEdge("A->c1", "c1"), auxEdge("c1", "c2")],
      rootIds: ["A->c1", "c1", "c2"],
    });
    const placement = buildReplicaPlacement(g);
    const directEdge = g.edges[1];
    if (!directEdge) throw new Error("missing direct edge");
    expect(replicaTargetXOffset(directEdge, placement, 13)).toBe(0);
  });
});

// ─── Test 2: Single-source no-op ──────────────────────────────────────────

describe("port-spreading — single-source no-op", () => {
  it("returns 0 for every replica edge when `rowOfSource.size === 1`", () => {
    // Canonical AES baseline: one source (`key-expansion` analogue),
    // multiple consumers fanned from it. Pre-port-spreading visual must
    // be byte-identical to post-port-spreading on this shape.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        consumerNode("c2"),
        consumerNode("c3"),
        replicaNode("src->c1", "src"),
        replicaNode("src->c2", "src"),
        replicaNode("src->c3", "src"),
      ],
      edges: [auxEdge("src->c1", "c1"), auxEdge("src->c2", "c2"), auxEdge("src->c3", "c3")],
      rootIds: ["src->c1", "c1", "src->c2", "c2", "src->c3", "c3"],
    });
    const placement = buildReplicaPlacement(g);
    // Confirm the placement is genuinely single-source — guards against
    // accidental test rot if `replicaOf` semantics shift.
    expect(placement.rowOfSource.size).toBe(1);
    for (const edge of g.edges) {
      expect(replicaTargetXOffset(edge, placement, 13)).toBe(0);
    }
  });
});

// ─── Test 3: Multi-source spread ──────────────────────────────────────────

describe("port-spreading — multi-source spread", () => {
  it("two sources at PORT_GAP=10 → offsets centered at -5 and +5", () => {
    // Two sources A, B both fanning to consumer c1. Row 0 = A, row 1 = B
    // (encounter order over graph.nodes). With PORT_GAP=10:
    //   - row 0 → (0 - 0.5) * 10 = -5
    //   - row 1 → (1 - 0.5) * 10 = +5
    // Spread is centered around the consumer-top midpoint.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), replicaNode("A->c1", "A"), replicaNode("B->c1", "B")],
      edges: [auxEdge("A->c1", "c1"), auxEdge("B->c1", "c1")],
      rootIds: ["A->c1", "B->c1", "c1"],
    });
    const placement = buildReplicaPlacement(g);
    const eA = g.edges[0];
    const eB = g.edges[1];
    if (!eA || !eB) throw new Error("missing edges");
    expect(replicaTargetXOffset(eA, placement, 10)).toBe(-5);
    expect(replicaTargetXOffset(eB, placement, 10)).toBe(+5);
  });

  it("three sources at PORT_GAP=10 → offsets at -10, 0, +10", () => {
    // Three sources A, B, C all fanning to consumer c1. Row assignment is
    // first-seen-wins over graph.nodes — match the rootIds splice
    // convention so the order is unambiguous. With PORT_GAP=10:
    //   - row 0 → (0 - 1) * 10 = -10
    //   - row 1 → (1 - 1) * 10 = 0  (middle row lands at midpoint)
    //   - row 2 → (2 - 1) * 10 = +10
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        replicaNode("A->c1", "A"),
        replicaNode("B->c1", "B"),
        replicaNode("C->c1", "C"),
      ],
      edges: [auxEdge("A->c1", "c1"), auxEdge("B->c1", "c1"), auxEdge("C->c1", "c1")],
      rootIds: ["A->c1", "B->c1", "C->c1", "c1"],
    });
    const placement = buildReplicaPlacement(g);
    expect(placement.rowOfSource.size).toBe(3);
    const [eA, eB, eC] = g.edges;
    if (!eA || !eB || !eC) throw new Error("missing edges");
    expect(replicaTargetXOffset(eA, placement, 10)).toBe(-10);
    expect(replicaTargetXOffset(eB, placement, 10)).toBe(0);
    expect(replicaTargetXOffset(eC, placement, 10)).toBe(+10);
  });

  it("four sources at PORT_GAP=10 → offsets at -15, -5, +5, +15 (even count straddles the midpoint)", () => {
    // Even-count case: the middle straddles the midpoint with no row
    // landing exactly at 0. Important to keep the formula symmetric for
    // any count, not just odd ones.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        replicaNode("A->c1", "A"),
        replicaNode("B->c1", "B"),
        replicaNode("C->c1", "C"),
        replicaNode("D->c1", "D"),
      ],
      edges: [
        auxEdge("A->c1", "c1"),
        auxEdge("B->c1", "c1"),
        auxEdge("C->c1", "c1"),
        auxEdge("D->c1", "c1"),
      ],
      rootIds: ["A->c1", "B->c1", "C->c1", "D->c1", "c1"],
    });
    const placement = buildReplicaPlacement(g);
    expect(placement.rowOfSource.size).toBe(4);
    const offsets = g.edges.map((e) => replicaTargetXOffset(e, placement, 10));
    expect(offsets).toEqual([-15, -5, +5, +15]);
  });

  it("scales linearly with PORT_GAP — 3 sources at PORT_GAP=20 → offsets at -20, 0, +20", () => {
    // Density scaling sanity: PORT_GAP=20 doubles the offsets. Locks in
    // that the helper is a pure multiplication, not a magnitude-clamped
    // computation that would saturate at large gaps.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        replicaNode("A->c1", "A"),
        replicaNode("B->c1", "B"),
        replicaNode("C->c1", "C"),
      ],
      edges: [auxEdge("A->c1", "c1"), auxEdge("B->c1", "c1"), auxEdge("C->c1", "c1")],
      rootIds: ["A->c1", "B->c1", "C->c1", "c1"],
    });
    const placement = buildReplicaPlacement(g);
    const offsets = g.edges.map((e) => replicaTargetXOffset(e, placement, 20));
    expect(offsets).toEqual([-20, 0, +20]);
  });
});

// ─── Test 4: Kind-agnostic (Slice 7b prep) ────────────────────────────────

describe("port-spreading — kind-agnostic placement (Slice 7b prep)", () => {
  it("a state-kind replica edge gets the same offset as an aux-kind edge at the same row", () => {
    // Slice 7b will drop the `kind === "aux"` filter at
    // `replicateHighFanoutSources` and produce state-kind replicas. Pre-
    // verify they slot into port-spreading the same way: placement keys
    // off `replicaOf` only, never edge.kind, so the offset is identical.
    //
    // Two-source graph with one aux edge from source A and one state
    // edge from source B (both replicas, both fan to c1). Offsets should
    // mirror the all-aux case.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), replicaNode("A->c1", "A"), replicaNode("B->c1", "B")],
      edges: [
        { from: "A->c1", to: "c1", auxKey: "aux-key", kind: "aux" },
        { from: "B->c1", to: "c1", auxKey: "state", kind: "state" },
      ],
      rootIds: ["A->c1", "B->c1", "c1"],
    });
    const placement = buildReplicaPlacement(g);
    const [auxE, stateE] = g.edges;
    if (!auxE || !stateE) throw new Error("missing edges");
    // A at row 0 → -5, B at row 1 → +5. Kind doesn't factor in.
    expect(replicaTargetXOffset(auxE, placement, 10)).toBe(-5);
    expect(replicaTargetXOffset(stateE, placement, 10)).toBe(+5);
  });
});

// ─── Test 5: Composition — same data path as the renderer ─────────────────

describe("port-spreading — composes with `buildReplicaPlacement` on real-shape graphs", () => {
  it("globally-stable rows give the same offset at every consumer source A reaches", () => {
    // The headline visual invariant: source A always lands at the SAME
    // x-offset across the canvas, no matter which consumer it targets.
    // This is what makes the canvas eye-trackable per the Slice 7c
    // philosophy — "every chip at this offset is from source A."
    //
    // Two sources A, B fanning to c1 + c2. Both consumers see the same
    // offset values: A at row 0, B at row 1.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        consumerNode("c2"),
        replicaNode("A->c1", "A"),
        replicaNode("B->c1", "B"),
        replicaNode("A->c2", "A"),
        replicaNode("B->c2", "B"),
      ],
      edges: [
        auxEdge("A->c1", "c1"),
        auxEdge("B->c1", "c1"),
        auxEdge("A->c2", "c2"),
        auxEdge("B->c2", "c2"),
      ],
      rootIds: ["A->c1", "B->c1", "c1", "A->c2", "B->c2", "c2"],
    });
    const placement = buildReplicaPlacement(g);

    // Source A → row 0 → offset -5 at every consumer.
    const aOffsetAtC1 = replicaTargetXOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[0]!,
      placement,
      10,
    );
    const aOffsetAtC2 = replicaTargetXOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[2]!,
      placement,
      10,
    );
    expect(aOffsetAtC1).toBe(-5);
    expect(aOffsetAtC2).toBe(-5);

    // Source B → row 1 → offset +5 at every consumer.
    const bOffsetAtC1 = replicaTargetXOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[1]!,
      placement,
      10,
    );
    const bOffsetAtC2 = replicaTargetXOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[3]!,
      placement,
      10,
    );
    expect(bOffsetAtC1).toBe(+5);
    expect(bOffsetAtC2).toBe(+5);
  });
});

// ─── REPRO: chip-head heterogeneous fan-in (port-spreading-consumer-head) ──
//
// Slice 7c manual smoke surfaced fan-IN ambiguity at a collapsed-iterate
// chip head receiving heterogeneous incoming edges (mix of a non-replica
// state edge from the previous spine leaf + aux replicas from multiple
// distinct sources). The advisor (2026-05-16) flagged three plausible
// mechanisms and asked: construct a failing test before fleshing the plan.
// If we can't write the assertion, we don't know the bug.
//
// These two `it.fails` tests pin the two mechanisms that are testable at
// the helper level (the third, off-chip clamping against chip-vs-leaf
// width, lives in the EdgePath render site and needs an integration test).
// Each asserts the desired POST-fix behavior; both currently fail under
// the global-rows formula. When the fix lands, drop `.fails` and they
// become regression guards.
//
//   - Mechanism 1 (collision-at-zero): a non-replica edge returns 0, AND
//     the source mapped to the middle global row (`(row - (total-1)/2)
//     = 0`) also returns 0. Two distinct logical incoming edges land at
//     the same x on the consumer top — visual collision.
//   - Mechanism 2 (skipped-global-rows): a consumer's local fan-in only
//     hits a subset of the global rows; adjacent local edges land more
//     than one `portGap` apart because the global formula counts skipped
//     rows. Spread spans further than the local fan-in needs and reads
//     visually uneven against the consumer width.
//
// **Fix-direction note:** Test B's assertion (`|offsetA - offsetB| ===
// portGap`) is opinionated about a per-consumer fan-in fix. If we instead
// keep global rows and only retune chip-width handling, Test B's shape
// would change. Run as DIAGNOSTIC: a failure tells us "skipped-row
// spread happens"; the fix-direction call is the plan-flesh-out decision.

describe("port-spreading — chip-head heterogeneous fan-in (REPRO — bug)", () => {
  it.fails(
    "mechanism 1: a non-replica edge and a middle-row replica edge to the same consumer produce DISTINCT offsets",
    () => {
      // Three global sources A (row 0), B (row 1, middle), C (row 2).
      // Consumer c1 receives:
      //   - one non-replica state edge from `prev` → offset 0 (no row).
      //   - one aux replica edge from source B (middle row) → offset 0
      //     under `(row - (total-1)/2) * portGap` = (1 - 1) * 10 = 0.
      // Both arrows arrive at the same x on c1's top edge.
      const g = buildSyntheticGraph({
        nodes: [
          consumerNode("prev"),
          consumerNode("c1"),
          consumerNode("c2"),
          consumerNode("c3"),
          replicaNode("A->c2", "A"),
          replicaNode("B->c1", "B"),
          replicaNode("C->c3", "C"),
        ],
        edges: [
          // Non-replica spine edge prev → c1.
          { from: "prev", to: "c1", auxKey: "state", kind: "state" },
          // Aux replica edges (B lands on c1; A and C land elsewhere so
          // the placement registers 3 distinct global sources).
          auxEdge("A->c2", "c2"),
          auxEdge("B->c1", "c1"),
          auxEdge("C->c3", "c3"),
        ],
        rootIds: ["prev", "A->c2", "B->c1", "C->c3", "c1", "c2", "c3"],
      });
      const placement = buildReplicaPlacement(g);
      expect(placement.rowOfSource.size).toBe(3);

      const spineEdge = g.edges[0];
      const bToC1 = g.edges[2];
      if (!spineEdge || !bToC1) throw new Error("missing edges");
      const portGap = 10;

      const spineOffset = replicaTargetXOffset(spineEdge, placement, portGap);
      const bMiddleOffset = replicaTargetXOffset(bToC1, placement, portGap);

      // Both edges target c1. Distinct logical sources MUST get distinct
      // offsets — otherwise the arrows visually collide at the chip head.
      // Currently FAILS: spineOffset === 0 (non-replica), bMiddleOffset
      // === 0 (middle global row). Same value → collision.
      expect(spineOffset).not.toBe(bMiddleOffset);
    },
  );

  it.fails(
    "mechanism 2: adjacent local edges at one consumer land exactly `portGap` apart (per-consumer fan-in spacing)",
    () => {
      // Three global sources A (row 0), B (row 1), C (row 2). Consumer
      // c1 sees only A and C (B's replica goes to a different consumer).
      // Under per-consumer fan-in: A and C are c1's only two incoming
      // edges → spacing portGap. Under global rows: A at -1*portGap,
      // C at +1*portGap → spacing 2*portGap because the skipped row B
      // counts toward the spread.
      const g = buildSyntheticGraph({
        nodes: [
          consumerNode("c1"),
          consumerNode("c-other"),
          replicaNode("A->c1", "A"),
          replicaNode("B->c-other", "B"),
          replicaNode("C->c1", "C"),
        ],
        edges: [auxEdge("A->c1", "c1"), auxEdge("B->c-other", "c-other"), auxEdge("C->c1", "c1")],
        rootIds: ["A->c1", "B->c-other", "C->c1", "c1", "c-other"],
      });
      const placement = buildReplicaPlacement(g);
      expect(placement.rowOfSource.size).toBe(3);

      const aToC1 = g.edges[0];
      const cToC1 = g.edges[2];
      if (!aToC1 || !cToC1) throw new Error("missing edges");
      const portGap = 10;

      const aOffset = replicaTargetXOffset(aToC1, placement, portGap);
      const cOffset = replicaTargetXOffset(cToC1, placement, portGap);

      // Per-consumer spacing: |offsetA - offsetC| === portGap. Currently
      // FAILS: spacing is 2 * portGap because B's skipped global row
      // inflates the spread without contributing a visible edge.
      expect(Math.abs(aOffset - cOffset)).toBe(portGap);
    },
  );
});
