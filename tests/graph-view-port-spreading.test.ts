// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure helper exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `buildReplicaPlacement` + `buildConsumerPortAssignment`
// + `consumerPortOffset`.

/**
 * Port-spreading at consumer head — per-consumer slot semantics
 * (port-spreading-consumer-head plan, 2026-05-16). Slice 7c stacked
 * replicas vertically above each consumer by globally-stable source
 * rows; the consumer-side x-offset originally distributed by GLOBAL
 * row index. The 7c manual smoke pass surfaced two distinct chip-head
 * ambiguity mechanisms with that approach (see `it.fails` migration
 * note below). The fix swaps the global-row formula for a PER-CONSUMER
 * slot assignment via `buildConsumerPortAssignment` →
 * `consumerPortOffset`. Slot ordering at each consumer inherits the
 * global row ordering (so source-side and target-side spreads stay
 * aligned and arrows don't cross), but the spread itself is computed
 * against the consumer's LOCAL fan-in count, with non-replicas
 * sorted last (Infinity row).
 *
 * Properties this file pins:
 *
 *   1. **Single-incoming no-op** — a consumer with one incoming edge
 *      gets `slotOf.get(edge) === undefined` → offset 0 regardless of
 *      `portGap`. Subsumes the prior "non-replica edge returns 0" and
 *      "single-source returns 0" properties.
 *   2. **Multi-incoming spread** — N incoming edges at one consumer →
 *      offsets `(i - (N-1)/2) * portGap` for i ∈ 0..N-1, centered
 *      around the consumer's top-edge midpoint. Formula tested at
 *      N = 2, 3, 4 and at two PORT_GAP scales.
 *   3. **Kind-agnostic** — comparator never reads `edge.kind`; state-
 *      kind and aux-kind edges sort identically when their other
 *      fields tie. Pre-verifies Slice 7b's `kind === "aux"` filter
 *      drop won't surprise port-spreading.
 *   4. **Composition with placement** — `buildConsumerPortAssignment`
 *      takes a `ReplicaPlacement` to inherit row ordering. End-to-end
 *      smoke for the same data path the renderer uses.
 *   5. **No chip-head collision** — non-replica edges and middle-row
 *      replica edges at one consumer get DISTINCT offsets (Mechanism 1
 *      fix); local fan-in determines spacing, not global row gaps
 *      (Mechanism 2 fix). These pin the two diagnostic tests that
 *      shipped as `it.fails` in commit `97e098f`; they are plain
 *      `it` now.
 */

import type { CipherGraph, GraphEdge, GraphNode } from "@/core/graph";
import {
  buildConsumerPortAssignment,
  buildReplicaPlacement,
  consumerPortOffset,
} from "@/ui/components/GraphView";
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

// ─── Test 1: Single-incoming no-op ────────────────────────────────────────

describe("port-spreading — single-incoming no-op (subsumes prior 'non-replica edge')", () => {
  it("returns 0 for an edge at a consumer with no other incoming edges", () => {
    // Graph with a single replica from source A → c1, plus an unrelated
    // direct edge `c1 → c2`. c2 sees only the direct edge (localCount=1
    // → no slot entry → consumerPortOffset returns 0). Pins the
    // single-incoming property — replaces the prior "non-replica edge"
    // framing, which was a side effect of the old global-row formula.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), consumerNode("c2"), replicaNode("A->c1", "A")],
      edges: [auxEdge("A->c1", "c1"), auxEdge("c1", "c2")],
      rootIds: ["A->c1", "c1", "c2"],
    });
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    const directEdge = g.edges[1];
    if (!directEdge) throw new Error("missing direct edge");
    expect(consumerPortOffset(directEdge, ports, 13)).toBe(0);
  });
});

// ─── Test 2: Canonical single-source baseline ─────────────────────────────

describe("port-spreading — canonical single-source baseline", () => {
  it("returns 0 for every replica edge when each consumer has localCount === 1", () => {
    // Canonical AES baseline: one source (`key-expansion` analogue),
    // multiple consumers each fanned to by a separate replica. Each
    // consumer sees exactly one incoming edge → localCount=1 → offset
    // 0. Pre-port-spreading visual stays byte-identical on this shape.
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    // Sanity guards against test rot if `replicaOf` semantics shift.
    expect(replicas.rowOfSource.size).toBe(1);
    expect(ports.localCountOf.get("c1")).toBe(1);
    expect(ports.localCountOf.get("c2")).toBe(1);
    expect(ports.localCountOf.get("c3")).toBe(1);
    for (const edge of g.edges) {
      expect(consumerPortOffset(edge, ports, 13)).toBe(0);
    }
  });
});

// ─── Test 3: Multi-incoming spread at one consumer ────────────────────────

describe("port-spreading — multi-incoming spread at one consumer", () => {
  it("two incoming edges at PORT_GAP=10 → offsets centered at -5 and +5", () => {
    // Two sources A, B both fanning to consumer c1. Slot assignment at
    // c1 inherits row ordering from ReplicaPlacement (A=row 0, B=row 1):
    //   - slot 0 (A) → (0 - 0.5) * 10 = -5
    //   - slot 1 (B) → (1 - 0.5) * 10 = +5
    // Centered around the consumer-top midpoint.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), replicaNode("A->c1", "A"), replicaNode("B->c1", "B")],
      edges: [auxEdge("A->c1", "c1"), auxEdge("B->c1", "c1")],
      rootIds: ["A->c1", "B->c1", "c1"],
    });
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    const eA = g.edges[0];
    const eB = g.edges[1];
    if (!eA || !eB) throw new Error("missing edges");
    expect(consumerPortOffset(eA, ports, 10)).toBe(-5);
    expect(consumerPortOffset(eB, ports, 10)).toBe(+5);
  });

  it("three incoming edges at PORT_GAP=10 → offsets at -10, 0, +10", () => {
    // Three sources A, B, C all fanning to c1. Row order = encounter
    // order over graph.nodes (A=0, B=1, C=2). Slots at c1 follow row:
    //   - slot 0 (A) → -10
    //   - slot 1 (B) → 0 (middle slot lands at midpoint)
    //   - slot 2 (C) → +10
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    expect(ports.localCountOf.get("c1")).toBe(3);
    const [eA, eB, eC] = g.edges;
    if (!eA || !eB || !eC) throw new Error("missing edges");
    expect(consumerPortOffset(eA, ports, 10)).toBe(-10);
    expect(consumerPortOffset(eB, ports, 10)).toBe(0);
    expect(consumerPortOffset(eC, ports, 10)).toBe(+10);
  });

  it("four incoming edges at PORT_GAP=10 → offsets at -15, -5, +5, +15 (even count straddles the midpoint)", () => {
    // Even-count case: the middle straddles the midpoint with no slot
    // landing exactly at 0. The formula stays symmetric for any count.
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    expect(ports.localCountOf.get("c1")).toBe(4);
    const offsets = g.edges.map((e) => consumerPortOffset(e, ports, 10));
    expect(offsets).toEqual([-15, -5, +5, +15]);
  });

  it("scales linearly with PORT_GAP — 3 incoming at PORT_GAP=20 → offsets at -20, 0, +20", () => {
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    const offsets = g.edges.map((e) => consumerPortOffset(e, ports, 20));
    expect(offsets).toEqual([-20, 0, +20]);
  });
});

// ─── Test 4: Kind-agnostic (Slice 7b prep) ────────────────────────────────

describe("port-spreading — kind-agnostic comparator (Slice 7b prep)", () => {
  it("a state-kind replica edge gets the same slot ordering as an aux-kind edge at the same row", () => {
    // Slice 7b will drop the `kind === "aux"` filter at
    // `replicateHighFanoutSources` and produce state-kind replicas. The
    // per-consumer slot comparator's primary key is row order, never
    // edge.kind — so state-kind and aux-kind replicas at the same
    // consumer interleave by row, identical to today's all-aux case.
    //
    // Two-source graph: one aux edge from source A (row 0) and one
    // state edge from source B (row 1), both fanning to c1.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("c1"), replicaNode("A->c1", "A"), replicaNode("B->c1", "B")],
      edges: [
        { from: "A->c1", to: "c1", auxKey: "aux-key", kind: "aux" },
        { from: "B->c1", to: "c1", auxKey: "state", kind: "state" },
      ],
      rootIds: ["A->c1", "B->c1", "c1"],
    });
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    const [auxE, stateE] = g.edges;
    if (!auxE || !stateE) throw new Error("missing edges");
    // A at row 0 → slot 0 → -5; B at row 1 → slot 1 → +5. Kind doesn't
    // factor in.
    expect(consumerPortOffset(auxE, ports, 10)).toBe(-5);
    expect(consumerPortOffset(stateE, ports, 10)).toBe(+5);
  });
});

// ─── Test 5: Symmetric topology — slots align across consumers ────────────

describe("port-spreading — symmetric topology gives aligned slots across consumers", () => {
  it("when two consumers see the same set of sources, each source lands at the same slot at both", () => {
    // Two sources A, B fanning to BOTH c1 AND c2 (symmetric topology).
    // Per-consumer slot ordering inherits row order from
    // ReplicaPlacement: at every consumer A is row 0 (slot 0), B is row
    // 1 (slot 1). Result: A's offset at c1 === A's offset at c2 (-5);
    // B's offset at c1 === B's offset at c2 (+5). Note: this is the
    // SYMMETRIC case. Cross-canvas stability only survives when
    // consumers see identical incoming-source sets — see the
    // "per-consumer locality" test below for the asymmetric tradeoff.
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);

    // Source A at every consumer it touches → slot 0 → offset -5.
    const aOffsetAtC1 = consumerPortOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[0]!,
      ports,
      10,
    );
    const aOffsetAtC2 = consumerPortOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[2]!,
      ports,
      10,
    );
    expect(aOffsetAtC1).toBe(-5);
    expect(aOffsetAtC2).toBe(-5);

    // Source B at every consumer → slot 1 → offset +5.
    const bOffsetAtC1 = consumerPortOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[1]!,
      ports,
      10,
    );
    const bOffsetAtC2 = consumerPortOffset(
      // biome-ignore lint/style/noNonNullAssertion: literal index
      g.edges[3]!,
      ports,
      10,
    );
    expect(bOffsetAtC1).toBe(+5);
    expect(bOffsetAtC2).toBe(+5);
  });
});

// ─── Test 5b: Per-consumer locality (asymmetric tradeoff) ─────────────────

describe("port-spreading — per-consumer locality in asymmetric topology", () => {
  it("the same source lands at DIFFERENT offsets at consumers with different fan-in", () => {
    // The trade vs the old global-row formula: a source's absolute
    // x-offset is no longer stable across consumers when those consumers
    // have different fan-in counts. This test pins that property
    // explicitly so a future "restore global stability" attempt has
    // to surface the regression.
    //
    // Source A fans to c1 (where c1's only incoming is A) AND to c2
    // (where c2 also has incoming B). c1's localCount=1 → A's offset
    // at c1 is 0. c2's localCount=2 → A (row 0) at slot 0 → -5.
    // Under the OLD formula, A would have landed at -5 at BOTH
    // consumers (because total=2 globally, A's row=0 → -5 everywhere).
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        consumerNode("c2"),
        replicaNode("A->c1", "A"),
        replicaNode("A->c2", "A"),
        replicaNode("B->c2", "B"),
      ],
      edges: [auxEdge("A->c1", "c1"), auxEdge("A->c2", "c2"), auxEdge("B->c2", "c2")],
      rootIds: ["A->c1", "A->c2", "B->c2", "c1", "c2"],
    });
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    expect(ports.localCountOf.get("c1")).toBe(1);
    expect(ports.localCountOf.get("c2")).toBe(2);
    const [aToC1, aToC2] = g.edges;
    if (!aToC1 || !aToC2) throw new Error("missing edges");
    // c1 single-incoming → 0. c2 multi-incoming → A at slot 0 → -5.
    expect(consumerPortOffset(aToC1, ports, 10)).toBe(0);
    expect(consumerPortOffset(aToC2, ports, 10)).toBe(-5);
  });
});

// ─── Regression: chip-head heterogeneous fan-in (was REPRO, now FIX) ──────
//
// Slice 7c manual smoke surfaced fan-IN ambiguity at a collapsed-iterate
// chip head receiving heterogeneous incoming edges (mix of a non-replica
// state edge from the previous spine leaf + aux replicas from multiple
// distinct sources). The advisor (2026-05-16) flagged three plausible
// mechanisms and asked: construct a failing test before fleshing the plan.
// Two mechanisms shipped as `it.fails` in commit `97e098f`; both are now
// plain `it` (regression guards) after the per-consumer slot fix lands.
//
//   - Mechanism 1 (collision-at-zero): under the old global-row formula,
//     a non-replica edge returned 0 AND the source mapped to the middle
//     global row (`(row - (total-1)/2) = 0`) also returned 0. Fixed by
//     the per-consumer slot ordering: non-replicas sort last (Infinity
//     row), so they get the rightmost slot regardless of how the
//     replicas sit. The two edges now occupy distinct slots.
//   - Mechanism 2 (skipped-global-rows): a consumer whose local fan-in
//     hit a sparse subset of global rows had adjacent local edges land
//     more than one `portGap` apart because the global formula counted
//     skipped rows. Fixed: local fan-in count is the denominator, so
//     adjacent local slots always sit exactly `portGap` apart.
//   - Mechanism 3 (off-chip clamp) — render-site, not helper-level.
//     Deferred to the implementation slice's manual smoke; see
//     `docs/plans/port-spreading-consumer-head.md` for the fallback
//     plan if visual smoke still shows clamping issues.

describe("port-spreading — chip-head heterogeneous fan-in (regression guards)", () => {
  it("mechanism 1: a non-replica edge and a middle-row replica edge to the same consumer produce DISTINCT offsets", () => {
    // Three global sources A (row 0), B (row 1, was middle), C (row 2).
    // Consumer c1 receives:
    //   - one non-replica state edge from `prev` (Infinity row).
    //   - one aux replica edge from source B (row 1).
    // Under the new per-consumer logic at c1: localCount=2, slots sorted
    // by row ascending → slot 0=B (row 1), slot 1=prev (row Infinity).
    // Offsets: B=-5, prev=+5. Distinct values → no collision.
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    expect(replicas.rowOfSource.size).toBe(3);
    expect(ports.localCountOf.get("c1")).toBe(2);

    const spineEdge = g.edges[0];
    const bToC1 = g.edges[2];
    if (!spineEdge || !bToC1) throw new Error("missing edges");
    const portGap = 10;

    const spineOffset = consumerPortOffset(spineEdge, ports, portGap);
    const bMiddleOffset = consumerPortOffset(bToC1, ports, portGap);

    // Distinct logical sources MUST get distinct offsets — otherwise
    // the arrows visually collide at the chip head. Post-fix: B at slot 0
    // → -5; prev at slot 1 → +5.
    expect(spineOffset).not.toBe(bMiddleOffset);
    expect(bMiddleOffset).toBe(-5);
    expect(spineOffset).toBe(+5);
  });

  it("mechanism 2: adjacent local edges at one consumer land exactly `portGap` apart (per-consumer fan-in spacing)", () => {
    // Three global sources A (row 0), B (row 1), C (row 2). Consumer c1
    // sees only A and C (B's replica goes to a different consumer).
    // Per-consumer logic at c1: localCount=2, slot 0=A (row 0), slot
    // 1=C (row 2). Offsets: A=-5, C=+5. Spacing = portGap (not 2*portGap
    // as under the old global formula).
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
    const replicas = buildReplicaPlacement(g);
    const ports = buildConsumerPortAssignment(g, replicas);
    expect(replicas.rowOfSource.size).toBe(3);
    expect(ports.localCountOf.get("c1")).toBe(2);

    const aToC1 = g.edges[0];
    const cToC1 = g.edges[2];
    if (!aToC1 || !cToC1) throw new Error("missing edges");
    const portGap = 10;

    const aOffset = consumerPortOffset(aToC1, ports, portGap);
    const cOffset = consumerPortOffset(cToC1, ports, portGap);

    // Adjacent local slots = exactly portGap apart. Post-fix: A at slot
    // 0 → -5; C at slot 1 → +5. |offsetA - offsetC| = 10 = portGap.
    expect(Math.abs(aOffset - cOffset)).toBe(portGap);
    expect(aOffset).toBe(-5);
    expect(cOffset).toBe(+5);
  });
});
