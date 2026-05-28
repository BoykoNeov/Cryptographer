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
import {
  buildConsumerPortAssignment,
  buildReplicaPlacement,
  consumerPortOffset,
  layoutConstantsFor,
  layoutRoot,
} from "@/ui/components/GraphView";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Offset-based layout ships ON by default (2026-05-28), but these are
// baseline replica-placement geometry tests — they pin by-source-row
// placement against the un-offset layout. Their interaction WITH offsets
// is covered by the pending visual smoke, not here. Pin OFF for the file.
beforeEach(() => __setOffsetsEnabledForTest(false));
afterEach(() => __setOffsetsEnabledForTest(null));

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

    const expectedReplicaYOffset = consts.LEAF_H + consts.REPLICA_LIFT_GAP;
    for (const cid of ["c1", "c2", "c3"]) {
      const c = boxes.get(cid);
      const r = boxes.get(`src->${cid}`);
      if (!c || !r) throw new Error(`missing box for ${cid}`);
      // Replica at consumer.x (column-stacked).
      expect(r.x).toBe(c.x);
      // Replica at exactly row 0: consumer.y - LEAF_H - REPLICA_LIFT_GAP.
      // REPLICA_LIFT_GAP (= 20) replaced STACK_GAP (= 6) here so the
      // arrow shaft between dot and arrowhead has visible length after
      // ARROW_INSET subtraction.
      expect(r.y).toBe(c.y - expectedReplicaYOffset);
    }
  });
});

// ─── Test 2: Multi-source row stability ───────────────────────────────────

describe("Slice S2(j2) — per-consumer local row densification (revises Slice 7c global-row policy)", () => {
  it("source A at LOCAL row 0 across every consumer that has it; source B's row depends on whether A is also present", () => {
    // Two sources A, B. Both fan to 3 common consumers c1/c2/c3; only B
    // also fans to a disjoint c4. Slice S2(j2) (2026-05-26) densifies
    // the per-consumer row pool: at c4 (where A has no replica), B's
    // replica is at LOCAL row 0 (not the global row 1 from
    // `rowOfSource`). Pre-S2(j2) this test pinned the opposite
    // ("globally-stable rowOfSource: B at row 1 EVEN at c4 with c4's
    // row 0 sitting empty"); SHA-256's s-stages — which see only
    // split-wv / split-H at global rows 2 / 3 — were paying 252+ px
    // of empty vertical space for unused rows 0/1.
    //
    // Within a consumer that DOES have both sources (c1, c2, c3), the
    // local row order still mirrors the global row order — A first
    // (local row 0), B second (local row 1) — so the within-cluster
    // tracking property the original test cared about is preserved.
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

    // Row 0 sits `LEAF_H + REPLICA_LIFT_GAP` above the consumer
    // (REPLICA_LIFT_GAP = 36, bumped from STACK_GAP=6 on 2026-05-16,
    // then 20 → 36 on 2026-05-17 so the arrow shaft between the
    // start-dot and the arrowhead has visible length).
    // Rows ≥1 stack with `LEAF_H + REPLICA_STACK_GAP` between them
    // (replica-stack-gap polish, 2026-05-17): the ×N bundle pills sit
    // at arrow midpoints, so the inter-row gap was bumped from
    // FLOW_GAP=24 to REPLICA_STACK_GAP=48 to keep adjacent pills from
    // crowding. Tracks `replicaSlotPosition`'s y formula.
    const row0Lift = consts.LEAF_H + consts.REPLICA_LIFT_GAP;
    const rowStep = consts.LEAF_H + consts.REPLICA_STACK_GAP;

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

    // B-replicas at c1/c2/c3 (where A is also present) sit at LOCAL row
    // 1 — row 0 lift + one row step above their consumer. Same as
    // pre-S2(j2) for these consumers because the local row pool (A=0,
    // B=1) matches the global row pool (A=0, B=1) when both sources
    // are present.
    const bRepYsWithA: number[] = [];
    for (const cid of ["c1", "c2", "c3"]) {
      const c = boxes.get(cid);
      const b = boxes.get(`B->${cid}`);
      if (!c || !b) throw new Error(`missing B-replica box for ${cid}`);
      expect(b.y).toBe(c.y - row0Lift - rowStep);
      expect(b.x).toBe(c.x + consts.REPLICA_ROW_X_STEP);
      bRepYsWithA.push(b.y);
    }
    expect(new Set(bRepYsWithA).size).toBe(1);

    // Within-cluster tracking property: at every consumer that has BOTH
    // sources, B sits exactly one row step above A.
    expect(bRepYsWithA[0]).toBe((aRepYs[0] ?? 0) - rowStep);

    // Slice S2(j2) — densification headline: c4 has only B. B at c4
    // takes LOCAL row 0 (no A present locally), so its y equals A's
    // y at c1/c2/c3 (all "row 0 above consumer" positions). Pre-
    // S2(j2) this would have been row 1 with c4's row 0 sitting empty.
    const c4 = boxes.get("c4");
    const bAtC4 = boxes.get("B->c4");
    if (!c4 || !bAtC4) throw new Error("missing c4 / B->c4");
    expect(bAtC4.y).toBe(c4.y - row0Lift);
    // No REPLICA_ROW_X_STEP shift since this replica is at local row 0
    // (the per-row x-shift formula uses local row, and row 0 contributes
    // 0 * step = 0).
    expect(bAtC4.x).toBe(c4.x);
    // Cross-check: at c4 the row above c4 IS occupied (by B itself),
    // unlike pre-S2(j2) where it sat empty.
    let row0OccupantAtC4: string | null = null;
    for (const [nid, box] of boxes) {
      if (nid === "c4") continue;
      if (box.x === c4.x && box.y === c4.y - row0Lift) {
        row0OccupantAtC4 = nid;
        break;
      }
    }
    expect(row0OccupantAtC4).toBe("B->c4");
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

    // Row 0 lift uses REPLICA_LIFT_GAP (= 36 after the 2026-05-17
    // bump from 20, wider than STACK_GAP=6 so the arrow shaft is
    // visible after ARROW_INSET subtraction); higher rows step up by
    // `LEAF_H + REPLICA_STACK_GAP` (REPLICA_STACK_GAP=48, replacing
    // FLOW_GAP=24 on 2026-05-17 so adjacent bundle ×N pills don't
    // crowd each other). With the straight-line + offset-start
    // approach (2026-05-16), REPLICA_ROW_X_STEP === 0 so row 1 sits
    // at chip.x (same column); its arrow ORIGINATES from an offset
    // point on row 1's bottom edge (via `replicaSourceXOffset`) and a
    // start-dot marks that origin so the eye reads it as distinct
    // from row 0's arrow.
    const row0Lift = consts.LEAF_H + consts.REPLICA_LIFT_GAP;
    const rowStep = consts.LEAF_H + consts.REPLICA_STACK_GAP;

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

// ─── Post-Option-C: replicas anchored at iterate center when consumer is
// a collapsed iterate (chip-body) ──────────────────────────────────────────
//
// Under Option C, a collapsed iterate keeps its container box and the
// `childIds` become block-chip ids. The earlier replica-anchor rule
// ("place above the iterate body's first non-replica child") read those
// chips as if they were real body steps — every replica's tip landed
// above block 1, making the user think the aux feeds only block 1.
// Override: when the first non-replica child is a block chip
// (`blockChipOf !== undefined`), anchor the replica at the iterate's
// horizontal center instead. Real body steps (expanded iterate) keep
// the first-child anchor.

describe("Option C — replica anchor for collapsed-iterate consumers", () => {
  it("anchors replicas at iterate-center when the first body child is a block chip", () => {
    const consts = layoutConstantsFor("normal");
    const graph: CipherGraph = {
      nodes: [
        {
          stepId: "key-expansion",
          stepType: "ke",
          label: "key-expansion",
          containerPath: [],
        },
        // Block chips (synthetic, post-expandCollapsedIterates). Use TWO
        // chips so the iterate's box is wider than a single LEAF_W and
        // its center is unambiguously to the right of chip 0's x — the
        // perception-bug we are fixing only manifests when the center
        // diverges from chip 0.
        {
          stepId: "iter@block0",
          stepType: "__block_chip__",
          label: "block 1",
          containerPath: ["iter"],
          blockChipOf: "iter",
        },
        {
          stepId: "iter@block1",
          stepType: "__block_chip__",
          label: "block 2",
          containerPath: ["iter"],
          blockChipOf: "iter",
        },
        // Replica node — `replicateHighFanoutSources` would have created
        // this in real flow with the consumer's containerPath. Here the
        // consumer is the iterate at root, so the replica sits at root.
        {
          stepId: "key-expansion@->iter",
          stepType: "ke",
          label: "key-expansion",
          containerPath: [],
          replicaOf: "key-expansion",
        },
      ],
      containers: [
        {
          kind: "iterate",
          id: "iter",
          label: "iter",
          containerPath: [],
          childIds: ["iter@block0", "iter@block1"],
          blockSpan: 2,
        },
      ],
      edges: [{ from: "key-expansion@->iter", to: "iter", auxKey: "key", kind: "aux" }],
      rootIds: ["key-expansion", "key-expansion@->iter", "iter"],
    };

    const { boxes } = layoutRoot(graph, new Map(), consts);
    const iterBox = boxes.get("iter");
    const replicaBox = boxes.get("key-expansion@->iter");
    const block0Box = boxes.get("iter@block0");

    expect(iterBox).toBeDefined();
    expect(replicaBox).toBeDefined();
    expect(block0Box).toBeDefined();
    if (!iterBox || !replicaBox || !block0Box) return;

    // Expected anchor: iterate-center adjusted so the chip is column-
    // centered on the iterate's midline.
    const expectedAnchorX = iterBox.x + (iterBox.w - consts.LEAF_W) / 2;
    expect(replicaBox.x).toBe(expectedAnchorX);

    // The replica is NOT anchored over block 1's column — that was the
    // perception-bug we are fixing.
    expect(replicaBox.x).not.toBe(block0Box.x);
  });
});

// ─── Single-replica vertical arrow (2026-05-17 polish) ──────────────────
//
// When a consumer has exactly ONE incoming replica chip but the consumer-
// port-spread gives that chip's bundle a non-center slot (other non-
// replica bundles also feed the consumer), `layoutRoot` shifts the
// chip's x by `consumerPortOffset(...)`. Result: chip.x + LEAF_W/2 =
// arrow target x at the consumer's top edge → vertical arrow. Multi-
// replica consumers skip the shift to preserve the column-stacked
// visual the user finds acceptable.

describe("single-replica vertical-arrow shift (2026-05-17 polish)", () => {
  it("shifts a sole replica chip's x by its bundle's port-slot offset, producing a vertical arrow", () => {
    // Synthetic: one consumer with three incoming aux bundles. Only ONE
    // of the producers is a replica chip; the other two are plain leaves.
    // The port-spread orders bundles by (row asc, from asc, auxKey asc,
    // kind asc) and centers them around the consumer-top midline; with
    // 3 bundles, the replica's bundle gets a non-center slot. Pre-fix:
    // the chip sat at consumer.x → arrow diagonal. Post-fix: chip.x =
    // consumer.x + slotOffset → arrow vertical.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("consumer"),
        consumerNode("plainA"),
        consumerNode("plainB"),
        replicaNode("replica->consumer", "replica"),
      ],
      edges: [
        // Replica's bundle: one aux edge from the chip.
        { from: "replica->consumer", to: "consumer", auxKey: "rk", kind: "aux" },
        // Two non-replica bundles from other root leaves.
        { from: "plainA", to: "consumer", auxKey: "blockCount", kind: "aux" },
        { from: "plainB", to: "consumer", auxKey: "input-blocks", kind: "aux" },
      ],
      // Splice replica before its consumer; plain leaves earlier so they
      // own their slots in the rootIds order (rendering invariant only).
      rootIds: ["plainA", "plainB", "replica->consumer", "consumer"],
    });
    const consts = layoutConstantsFor("normal");
    // Build the port assignment the layout pass needs. For this test
    // every bundle is a singleton, so the synth graph IS its own bundle
    // representative — we can pass the graph directly.
    const ports = buildConsumerPortAssignment(g, buildReplicaPlacement(g));
    const portGap = Math.max(6, Math.round(consts.LEAF_W / 10));

    // First: confirm the consumer-port assignment gave the replica's
    // bundle a non-center slot. If it didn't, the test wouldn't be
    // exercising the new path (consumerPortOffset would return 0 for
    // every edge and the shift wouldn't matter).
    const replicaEdge = g.edges.find((e) => e.from === "replica->consumer");
    if (!replicaEdge) throw new Error("missing replica edge");
    const expectedSlotOffset = consumerPortOffset(replicaEdge, ports, portGap);
    expect(expectedSlotOffset).not.toBe(0);

    // Now run the layout WITH the port assignment.
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      consts,
      new Set(),
      ports,
    );

    const consumer = boxes.get("consumer");
    const chip = boxes.get("replica->consumer");
    if (!consumer || !chip) throw new Error("missing layout box");

    // The headline assertion: chip.x is shifted by the slot offset, so
    // chip.center.x === consumer.center.x + slotOffset === arrow target x.
    // The arrow drawn from chip-bottom-center to (consumer.x + slotOffset,
    // consumer.y) is therefore vertical.
    expect(chip.x).toBe(consumer.x + expectedSlotOffset);
  });

  it("does NOT shift when there are multiple replica chips feeding the same consumer (preserves the column-stacked visual)", () => {
    // Two replicas (A + B) feeding the same consumer alongside a plain
    // leaf. Without the shift, chips stack at consumer.x with column-
    // diagonal arrows; user said "if we have 2 or 3 replicates it look
    // good." Confirm the shift is suppressed in this multi-chip case.
    const g = buildSyntheticGraph({
      nodes: [
        consumerNode("consumer"),
        consumerNode("plain"),
        replicaNode("A->consumer", "A"),
        replicaNode("B->consumer", "B"),
      ],
      edges: [
        { from: "A->consumer", to: "consumer", auxKey: "akey", kind: "aux" },
        { from: "B->consumer", to: "consumer", auxKey: "bkey", kind: "aux" },
        { from: "plain", to: "consumer", auxKey: "plainkey", kind: "aux" },
      ],
      rootIds: ["plain", "A->consumer", "B->consumer", "consumer"],
    });
    const consts = layoutConstantsFor("normal");
    const ports = buildConsumerPortAssignment(g, buildReplicaPlacement(g));

    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      consts,
      new Set(),
      ports,
    );

    const consumer = boxes.get("consumer");
    const a = boxes.get("A->consumer");
    const b = boxes.get("B->consumer");
    if (!consumer || !a || !b) throw new Error("missing layout box");

    // Both replicas still sit at consumer.x (no slot shift). Stacked
    // vertically in y by REPLICA_STACK_GAP.
    expect(a.x).toBe(consumer.x);
    expect(b.x).toBe(consumer.x);
  });

  it("no shift when portAssignment is undefined (test backward-compat — layoutRoot's old signature)", () => {
    // Existing callers that don't pass the new port-assignment parameter
    // must see byte-identical placement. This catches a regression where
    // the new code path leaks into the no-port-assignment branch.
    const g = buildSyntheticGraph({
      nodes: [consumerNode("consumer"), consumerNode("plain"), replicaNode("R->consumer", "R")],
      edges: [
        { from: "R->consumer", to: "consumer", auxKey: "rkey", kind: "aux" },
        { from: "plain", to: "consumer", auxKey: "pkey", kind: "aux" },
      ],
      rootIds: ["plain", "R->consumer", "consumer"],
    });
    const consts = layoutConstantsFor("normal");

    // No portAssignment argument — old four-arg signature.
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);

    const consumer = boxes.get("consumer");
    const chip = boxes.get("R->consumer");
    if (!consumer || !chip) throw new Error("missing layout box");
    // Chip at consumer.x exactly (no shift).
    expect(chip.x).toBe(consumer.x);
  });
});
