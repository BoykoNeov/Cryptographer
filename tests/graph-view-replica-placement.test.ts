// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`.

/**
 * Slice 7c — by-source-row replica placement.
 *
 * Replaces the encounter-order horizontal scatter (per-consumer x-step
 * counter) with **by-source columns above each consumer**: every replica
 * from source A lives at the SAME row index above every consumer it
 * touches. Source B claims the next row up. Globally stable: across the
 * whole canvas, source A is always at row 0, source B always at row 1,
 * etc., regardless of which consumers each source happens to fan to.
 *
 * Properties this file pins:
 *
 *   1. **Aux-only baseline regression** — single-source AES-128 ECB +
 *      `key-expansion → always` graph: every replica still lands at the
 *      pre-7c position because rowOfSource[key-expansion] = 0. Refactor
 *      should not shift existing layout under no-state-replica conditions.
 *   2. **Multi-source row stability** — synthetic graph with two sources
 *      A, B fanning to common + disjoint consumers. Source A always at
 *      row 0 (its consumers' lifted y); source B always at row 1, even
 *      at the consumer where source A has no replica (that consumer's
 *      row 0 sits empty — vertical gap, source B sits at row 1).
 *   3. **Synthetic state-kind replicas** — `replicateHighFanoutSources`
 *      doesn't produce state-kind replicas today (Slice 7b will drop the
 *      filter). We hand-construct a graph with `replicaOf` on a node that
 *      has only an outgoing STATE edge, and assert placement is identical
 *      to the aux case at the same shape. This converts "kind-agnostic"
 *      from a claim into a fact and means Slice 7b can drop the
 *      `kind === "aux"` filter without surprise placement bugs.
 *   4. **Chip-crowding fixture** — collapsed iterate with 4 block-chips
 *      × 2 always-sources. Each block-chip has exactly 2 replicas above
 *      it, source A on row 0 and source B on row 1, all 4 source-A
 *      replicas share y, all 4 source-B replicas share y. This is the
 *      canonical bad case the user surfaced in the post-CBC manual review.
 */

import type { CipherGraph, ContainerNode, GraphEdge, GraphNode } from "@/core/graph";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Build a synthetic CipherGraph with explicit nodes/edges/containers. Used
 * by the by-source-row tests so we have full control over which sources
 * exist, which consumers they target, and which edges connect them. The
 * real-cipher fixtures (AES, Speck) only ever produce one source
 * (key-expansion) per consumer, so synthetic literals are the only way
 * to exercise the multi-source rows.
 */
const buildSyntheticGraph = (parts: {
  readonly nodes: readonly GraphNode[];
  readonly containers?: readonly ContainerNode[];
  readonly edges: readonly GraphEdge[];
  readonly rootIds: readonly string[];
}): CipherGraph => ({
  nodes: parts.nodes,
  containers: parts.containers ?? [],
  edges: parts.edges,
  rootIds: parts.rootIds,
});

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

// ─── Test 1: Aux-only baseline regression ─────────────────────────────────

describe("Slice 7c — aux-only baseline (single-source) regression", () => {
  it("single-source replicas all land at row 0 (pre-7c position)", () => {
    // One source (`src`), three replicas pointing at three distinct
    // consumers. Pre-7c: every replica at consumer.y - LEAF_H - STACK_GAP.
    // Post-7c: rowOfSource[src] = 0 → every replica at the SAME y offset.
    // The two are identical for a single-source graph — that's the
    // baseline guarantee.
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
      // Replica-then-consumer per the splice convention.
      rootIds: ["src->c1", "c1", "src->c2", "c2", "src->c3", "c3"],
    });
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);

    const expectedReplicaYOffset = consts.LEAF_H + consts.STACK_GAP;
    for (const cid of ["c1", "c2", "c3"]) {
      const c = boxes.get(cid);
      const r = boxes.get(`src->${cid}`);
      if (!c || !r) throw new Error(`missing box for ${cid}`);
      // Replica at consumer.x (column-stacked).
      expect(r.x).toBe(c.x);
      // Replica at exactly row 0: consumer.y - LEAF_H - STACK_GAP.
      expect(r.y).toBe(c.y - expectedReplicaYOffset);
    }
  });
});

// ─── Test 2: Multi-source row stability ───────────────────────────────────

describe("Slice 7c — multi-source row stability (globally-stable rowOfSource)", () => {
  it("source A at row 0 across every consumer; source B at row 1 EVEN at consumers where A has no replica", () => {
    // Two sources A, B. Both fan to 3 common consumers c1/c2/c3; only B
    // also fans to a disjoint c4. The headline test of the by-source-row
    // policy: at c4 (where A has no replica), B's replica is still at
    // row 1, NOT row 0 — c4's row 0 sits empty (vertical gap above c4).
    //
    // Why globally stable beats per-consumer compaction: lets the eye
    // track "every chip on this y is from source X" across the whole
    // canvas. The cost is c4's empty row 0; the payoff is scannability.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("c1"),
        consumerNode("c2"),
        consumerNode("c3"),
        consumerNode("c4"),
        // Order matters for rowOfSource: A's first replica appears first
        // in graph.nodes → A claims row 0; B claims row 1.
        replicaNode("A->c1", "A"),
        replicaNode("B->c1", "B"),
        replicaNode("A->c2", "A"),
        replicaNode("B->c2", "B"),
        replicaNode("A->c3", "A"),
        replicaNode("B->c3", "B"),
        replicaNode("B->c4", "B"),
      ],
      edges: [
        auxEdge("A->c1", "c1"),
        auxEdge("B->c1", "c1"),
        auxEdge("A->c2", "c2"),
        auxEdge("B->c2", "c2"),
        auxEdge("A->c3", "c3"),
        auxEdge("B->c3", "c3"),
        auxEdge("B->c4", "c4"),
      ],
      // Splice convention: replicas-before-consumer.
      rootIds: [
        "A->c1",
        "B->c1",
        "c1",
        "A->c2",
        "B->c2",
        "c2",
        "A->c3",
        "B->c3",
        "c3",
        "B->c4",
        "c4",
      ],
    });
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);

    // Row 0 sits `LEAF_H + STACK_GAP` above the consumer (unchanged from
    // pre-port-spreading). Rows ≥1 stack with `LEAF_H + FLOW_GAP` between
    // them (port-spreading polish, 2026-05-16): wider gap so the arrows
    // from upper rows have visible drawing room and don't squish into a
    // 3-px sliver between chips. Tracks `replicaSlotPosition`'s y formula.
    const row0Lift = consts.LEAF_H + consts.STACK_GAP;
    const rowStep = consts.LEAF_H + consts.FLOW_GAP;

    // All A-replicas across c1/c2/c3 share the same y (row 0 above their
    // respective consumers). They differ in x (above their distinct
    // consumers' columns), but the row index is global.
    const aRepYs: number[] = [];
    for (const cid of ["c1", "c2", "c3"]) {
      const c = boxes.get(cid);
      const a = boxes.get(`A->${cid}`);
      if (!c || !a) throw new Error(`missing A-replica box for ${cid}`);
      // Each A-replica at exactly row 0 above its consumer. Row 0 lives
      // at `consumer.x` with no horizontal shift (port-spreading shifts
      // only rows ≥1).
      expect(a.y).toBe(c.y - row0Lift);
      expect(a.x).toBe(c.x);
      aRepYs.push(a.y);
    }
    // All A-replicas share the same numerical y (consumers are root-level
    // siblings on the same spine row, so c.y is identical).
    expect(new Set(aRepYs).size).toBe(1);

    // All B-replicas across c1/c2/c3/c4 share the same y (row 1 above
    // their consumers — one (LEAF_H + FLOW_GAP)-spaced row above A's
    // row 0). Including c4. With the straight-line + offset-start
    // approach (2026-05-16), REPLICA_ROW_X_STEP === 0 so all rows
    // share the consumer.x column — upper-row arrows ORIGINATE from
    // offset x positions on the column's bottom edges (via
    // `replicaSourceXOffset`) instead of from a diagonally-displaced
    // source. The assertion below tolerates the column-stacked case
    // (x === c.x + 0) identically — placement of the box stays
    // centred regardless.
    const bRepYs: number[] = [];
    for (const cid of ["c1", "c2", "c3", "c4"]) {
      const c = boxes.get(cid);
      const b = boxes.get(`B->${cid}`);
      if (!c || !b) throw new Error(`missing B-replica box for ${cid}`);
      // B at row 1: row 0 lift + one row step.
      expect(b.y).toBe(c.y - row0Lift - rowStep);
      expect(b.x).toBe(c.x + consts.REPLICA_ROW_X_STEP);
      bRepYs.push(b.y);
    }
    expect(new Set(bRepYs).size).toBe(1);

    // The headline cross-source assertion: B's row sits exactly one row
    // step above A's row, at every consumer. (Cheap derivation from above
    // — surface it explicitly so a future regression that breaks the
    // "source X always at row Y" property fails on this line.)
    expect(bRepYs[0]).toBe((aRepYs[0] ?? 0) - rowStep);

    // c4 has no A-replica; its column at row 0 (c4.y - row0Lift) should
    // be empty. Pin via the absence: no node's box is at that position
    // above c4. Search column tolerance: post-port-spreading row 1 is
    // at c.x + REPLICA_ROW_X_STEP, NOT c.x, so an "above c4 = same x"
    // check still distinguishes row 0 from row 1.
    const c4 = boxes.get("c4");
    if (!c4) throw new Error("missing c4");
    const c4Row0Y = c4.y - row0Lift;
    let row0OccupantAtC4: string | null = null;
    for (const [nid, box] of boxes) {
      if (nid === "c4" || nid === "B->c4") continue;
      // "Above c4 at row 0" = same x column as c4, y matching row 0.
      if (box.x === c4.x && box.y === c4Row0Y) {
        row0OccupantAtC4 = nid;
        break;
      }
    }
    expect(row0OccupantAtC4).toBeNull();
  });
});

// ─── Test 3: Synthetic state-kind replicas (Slice 7b prep) ────────────────

describe("Slice 7c — placement is kind-agnostic (Slice 7b prep)", () => {
  it("a state-kind replica places identically to an aux-kind replica at the same shape", () => {
    // Today `replicateHighFanoutSources` only produces aux-kind replicas
    // (it filters `if (e.kind !== "aux") continue;` at graph.ts:967).
    // Slice 7b will drop that filter so state-kind replicas land in the
    // same machinery. This test pre-verifies that buildReplicaPlacement
    // doesn't accidentally key off edge.kind — placement reads only
    // `node.replicaOf` and the consumer-edge target.
    //
    // Build two parallel synthetic graphs: identical shape, only the
    // single edge differs in kind (aux vs state). Run layoutRoot on
    // both; assert the replica's box is byte-identical between them.
    const buildGraphForKind = (kind: "aux" | "state"): CipherGraph =>
      buildSyntheticGraph({
        nodes: [consumerNode("consumer"), replicaNode("src->consumer", "src")],
        edges: [
          {
            from: "src->consumer",
            to: "consumer",
            auxKey: kind === "state" ? "state" : "test-key",
            kind,
          },
        ],
        rootIds: ["src->consumer", "consumer"],
      });

    const consts = layoutConstantsFor("normal");
    const empty = new Map<string, { x: number; y: number }>();

    const auxBoxes = layoutRoot(buildGraphForKind("aux"), empty, consts).boxes;
    const stateBoxes = layoutRoot(buildGraphForKind("state"), empty, consts).boxes;

    const auxReplica = auxBoxes.get("src->consumer");
    const stateReplica = stateBoxes.get("src->consumer");
    if (!auxReplica || !stateReplica) {
      throw new Error("missing replica box in one of the kind variants");
    }
    // Byte-identical placement — kind doesn't enter the layout decision.
    expect(stateReplica.x).toBe(auxReplica.x);
    expect(stateReplica.y).toBe(auxReplica.y);
    expect(stateReplica.w).toBe(auxReplica.w);
    expect(stateReplica.h).toBe(auxReplica.h);
  });
});

// ─── Test 4: Chip-crowding fixture (canonical bad case) ───────────────────

describe("Slice 7c — chip-crowding fixture (canonical bad case)", () => {
  it("4 block-chips × 2 always-sources: each chip has 2 replicas, source A on row 0, source B on row 1", () => {
    // The canonical bad case the user surfaced in the post-CBC manual
    // review: a collapsed iterate produces N block-chips (N = blockSpan,
    // capped at 6). Two `always`-source overrides fan to every chip.
    //
    // We model the post-`expandCollapsedIterates` graph directly: 4
    // chips at root level, 2 sources, 8 replicas total (one per
    // (source, chip) pair). The placement is the same machinery the
    // chips would hit after Slice 6's expansion.
    //
    // Properties: each chip has exactly 2 replicas above it, sharing
    // its column x. All 4 source-A replicas at the same y (row 0). All
    // 4 source-B replicas at the same y (row 1).
    const chipIds = ["chip0", "chip1", "chip2", "chip3"];
    const aReplicaIds = chipIds.map((c) => `A->${c}`);
    const bReplicaIds = chipIds.map((c) => `B->${c}`);

    const nodes: GraphNode[] = [
      ...chipIds.map(consumerNode),
      // Interleave source-A then source-B per chip, matching the order
      // the renderer builds replicas. graph.nodes walk order determines
      // rowOfSource: A first → row 0, B next → row 1.
      ...chipIds.flatMap((cid) => [replicaNode(`A->${cid}`, "A"), replicaNode(`B->${cid}`, "B")]),
    ];
    const edges: GraphEdge[] = [
      ...aReplicaIds.map((rid, i) => auxEdge(rid, chipIds[i] ?? "")),
      ...bReplicaIds.map((rid, i) => auxEdge(rid, chipIds[i] ?? "")),
    ];
    // Splice convention: replicas-before-consumer at root. Per chip:
    // [A->chip, B->chip, chip].
    const rootIds: string[] = chipIds.flatMap((cid) => [`A->${cid}`, `B->${cid}`, cid]);

    const g = buildSyntheticGraph({ nodes, edges, rootIds });
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);

    // Row 0 lift uses STACK_GAP (close to consumer); higher rows step
    // up by LEAF_H + FLOW_GAP (wider — port-spreading polish for visible
    // inter-row arrow gaps). With the straight-line + offset-start
    // approach (2026-05-16), REPLICA_ROW_X_STEP === 0 so row 1 sits at
    // chip.x (same column); its arrow ORIGINATES from an offset point
    // on row 1's bottom edge (via `replicaSourceXOffset`) and a
    // start-dot marks that origin so the eye reads it as distinct
    // from row 0's arrow.
    const row0Lift = consts.LEAF_H + consts.STACK_GAP;
    const rowStep = consts.LEAF_H + consts.FLOW_GAP;

    // For each chip, its 2 replicas sit at row 0 (chip.x) and row 1
    // (chip.x + REPLICA_ROW_X_STEP) — the diagonal stack that bypasses
    // the row-0 chip when the row-1 arrow descends.
    const aYs: number[] = [];
    const bYs: number[] = [];
    for (const cid of chipIds) {
      const chip = boxes.get(cid);
      const aRep = boxes.get(`A->${cid}`);
      const bRep = boxes.get(`B->${cid}`);
      if (!chip || !aRep || !bRep) throw new Error(`missing box for ${cid}`);
      // A on row 0: at chip.x, lifted by row0Lift.
      expect(aRep.x).toBe(chip.x);
      expect(aRep.y).toBe(chip.y - row0Lift);
      // B on row 1: at chip.x + REPLICA_ROW_X_STEP (= chip.x today
      // since the curved-edge prototype zeros that constant), lifted
      // by row0Lift + rowStep (row 0 lift + one inter-row step). The
      // bow on row 1's arrow swings around row 0 horizontally.
      expect(bRep.x).toBe(chip.x + consts.REPLICA_ROW_X_STEP);
      expect(bRep.y).toBe(chip.y - row0Lift - rowStep);
      aYs.push(aRep.y);
      bYs.push(bRep.y);
    }
    // All 4 source-A replicas share y (row 0 is GLOBAL across the canvas).
    expect(new Set(aYs).size).toBe(1);
    // All 4 source-B replicas share y (row 1 is GLOBAL).
    expect(new Set(bYs).size).toBe(1);
    // The two rows are exactly one (LEAF_H + FLOW_GAP) apart.
    expect((aYs[0] ?? 0) - (bYs[0] ?? 0)).toBe(rowStep);
  });
});
