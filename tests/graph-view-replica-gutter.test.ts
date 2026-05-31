// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`.

/**
 * Tests for the replica side-gutter layout (placement of high-fanout
 * replicas inside vertical-stack groups).
 *
 * The bug this prevents: `replicateHighFanoutSources` splices a replica
 * into the consumer's parent `childIds` immediately BEFORE the consumer.
 * Inside a vertical-stack group (every AES round), that lands the replica
 * in the same column as state-spine-consecutive leaves (mix-columns →
 * add-round-key). The replica's box sits BETWEEN them and visually
 * obscures the state edge running through the column — the user can't
 * tell whether mix-columns feeds add-round-key or the replica does.
 *
 * The fix: in `kind === "group"` (vertical stack), partition childIds —
 * non-replicas keep the column, replicas land in a LEFT GUTTER at their
 * consumer's y. The state-spine column is unobstructed; the aux arrow
 * from replica → consumer is a short horizontal segment.
 *
 * Properties this test pins:
 *
 *   1. Replica.x < consumer.x (replica is in the left gutter).
 *   2. Replica.y is centered against consumer.y (visually adjacent).
 *   3. The group's box widens by approximately LEAF_W + FLOW_GAP to make
 *      room for the gutter (only when a replica is present).
 *   4. Non-replicated rounds (none today in default AES-128 since EVERY
 *      round consumes a round key, but iterated against the principle)
 *      keep their original width.
 *
 * Note: AES-128 has 10 round groups + initial.add-round-key at root. All
 * 11 add-round-key consumers receive a replica when replication is on.
 * `initial.add-round-key` is at ROOT level (horizontal flow), so its
 * replica lands via the existing splice-before-consumer mechanic — no
 * gutter logic involved at root. We verify the round-group cases here.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import {
  type CipherGraph,
  type ContainerNode,
  type GraphEdge,
  type GraphNode,
  deriveAuxGraph,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { layoutConstantsFor, layoutRoot, visualEdgeTargetId } from "@/ui/components/GraphView";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Offset-based layout ships ON by default (2026-05-28), but these are
// baseline replica/gutter geometry tests — they pin the spine/gutter
// invariants against the un-offset layout. Their interaction WITH offsets
// is covered by the pending visual smoke, not here. Pin OFF for the file.
beforeEach(() => __setOffsetsEnabledForTest(false));
afterEach(() => __setOffsetsEnabledForTest(null));

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const aes128Graph = (): CipherGraph => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  return deriveAuxGraph(trace, aes128Spec);
};

const aes128ReplicatedGraph = (): CipherGraph => replicateHighFanoutSources(aes128Graph(), 6);

// AES-128-ECB exercises the iterate-body branch: `initial.add-round-key` is
// inside the iterate body, so its `key-expansion@->...` replica lands at
// iterate-body level (horizontal flow), not at root. Same orthogonal-axis
// principle as root must apply, otherwise the body-level spine arrow
// `initial.add-round-key → round.1.sub-bytes` would pass through the replica.
const ECB_PT_1_BLOCK = "6bc1bee22e409f96e93d7e117393172a";
const ECB_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const aes128EcbReplicatedGraph = (): CipherGraph => {
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PT_1_BLOCK)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(ECB_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
  });
  return replicateHighFanoutSources(deriveAuxGraph(trace, aes128EcbSpec), 6);
};

// Serpent exercises the FIRST-CHILD branch: every round group's `add-round-key`
// is the FIRST step (Serpent's per-round order is add-round-key → sub-bytes
// → linear-transform, opposite of AES). The inter-round state spine enters
// each round from the LEFT at `add-round-key`'s y. A LEFT-gutter replica at
// that same y would obscure the incoming arrow, so the layout LIFTS the
// column instead — placing the replica directly ABOVE `add-round-key` in
// the lifted top of the round box. AES vs Serpent both consume from
// `key-expansion`, but only Serpent triggers the lift branch.
const SERPENT128_PT = "00112233445566778899aabbccddeeff";
const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const serpent128ReplicatedGraph = (): CipherGraph => {
  const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
    // Serpent's round body is port-native since B3 → ported dispatch required.
  });
  return replicateHighFanoutSources(deriveAuxGraph(trace, serpent128Spec), 6);
};

// Synthetic spine-replica graph — scaffolding-suppression Slice B1.
//
// Byte-native AES-128 (the former matrix fixture for the two spine-replica
// tests below) has NO state spine: the working state carries port-to-port, so
// `inferStateEdges` emits nothing and the spine-replica
// `key-expansion@->initial.add-round-key` no longer exists. No other shipped
// cipher exercises this exact branch either — Serpent uses the lift branch
// (consumer-is-first-child), DES is Feistel, and aes-192/256 go byte-native in
// B1.3. Per the Bucket-C policy ("keep state-spine machinery covered until
// Phase C"), drive `layoutRoot`'s spine-replica path with a hand-built graph —
// the same pattern `makeMultiReplicaGraph` (below) uses for aux replicas.
//
// The mechanism under test: `buildReplicaPlacement` EXCLUDES `isSpineReplica`
// nodes from `isReplica` (GraphView.tsx ~937), so the spine-replica flows as a
// REGULAR leaf at the source's old root slot — on the spine row, no lift.
// Retire alongside `inferStateEdges` in Phase C.
const SPINE_CONSUMER_ID = "initial.add-round-key";
const SPINE_REPLICA_ID = `key-expansion@->${SPINE_CONSUMER_ID}`;
const syntheticSpineReplicaGraph = (): CipherGraph => ({
  nodes: [
    {
      stepId: SPINE_CONSUMER_ID,
      stepType: "test.consumer",
      label: SPINE_CONSUMER_ID,
      containerPath: [],
    },
    {
      stepId: SPINE_REPLICA_ID,
      stepType: "test.source",
      label: SPINE_REPLICA_ID,
      containerPath: [],
      replicaOf: "key-expansion",
      isSpineReplica: true,
    },
  ],
  containers: [],
  // The spine edge the replica carries into its consumer (state-kind; for
  // `kind: "state"` the auxKey sentinel is "state").
  edges: [{ from: SPINE_REPLICA_ID, to: SPINE_CONSUMER_ID, auxKey: "state", kind: "state" }],
  // Source's old slot first — Slice 7b removed the original `key-expansion`.
  rootIds: [SPINE_REPLICA_ID, SPINE_CONSUMER_ID],
});

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("GraphView — replica side-gutter inside vertical-stack groups", () => {
  it("places each round.N replica to the LEFT of its consumer (replica.x < consumer.x)", () => {
    const g = aes128ReplicatedGraph();
    const empty = new Map<string, { x: number; y: number }>();
    const { boxes } = layoutRoot(g, empty, layoutConstantsFor("normal"));

    // Sample a handful of rounds — the property holds for every round in
    // byte-native AES-128 because every round.N.add-round-key pulls a round key
    // from the high-fanout key-expansion source.
    for (const n of [1, 5, 10]) {
      const consumerId = `round.${n}.add-round-key`;
      const replicaId = `key-expansion@->${consumerId}`;
      const consumerBox = boxes.get(consumerId);
      const replicaBox = boxes.get(replicaId);
      if (!consumerBox || !replicaBox) {
        throw new Error(
          `missing box for round.${n}: consumer=${!!consumerBox} replica=${!!replicaBox}`,
        );
      }
      // The whole point: replica sits to the left of the consumer, not
      // stacked in the same column above it.
      expect(replicaBox.x).toBeLessThan(consumerBox.x);
    }
  });

  it("vertically centers the replica against its consumer (replica.y ≈ consumer.y)", () => {
    const g = aes128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerId = "round.5.add-round-key";
    const replicaId = `key-expansion@->${consumerId}`;
    const c = boxes.get(consumerId);
    const r = boxes.get(replicaId);
    if (!c || !r) throw new Error("missing box");
    // Center-y match (replica.h === consumer.h === LEAF_H, so the y
    // offsets are equal after centering). Allow 1px slack for rounding.
    const cMidY = c.y + c.h / 2;
    const rMidY = r.y + r.h / 2;
    expect(Math.abs(cMidY - rMidY)).toBeLessThanOrEqual(1);
  });

  it("widens the round group's bounding box to make room for the gutter", () => {
    const without = aes128Graph();
    const with_ = aes128ReplicatedGraph();
    const empty = new Map<string, { x: number; y: number }>();
    const consts = layoutConstantsFor("normal");
    const a = layoutRoot(without, empty, consts).boxes;
    const b = layoutRoot(with_, empty, consts).boxes;

    const r5_no = a.get("round.5");
    const r5_yes = b.get("round.5");
    if (!r5_no || !r5_yes) throw new Error("missing round.5 box");

    // The gutter adds approximately LEAF_W + FLOW_GAP to the group width.
    // Use a lower bound (≥ LEAF_W) so the test is robust against future
    // gutter-padding tweaks; just confirm the box widened MEANINGFULLY.
    expect(r5_yes.w).toBeGreaterThan(r5_no.w);
    expect(r5_yes.w - r5_no.w).toBeGreaterThanOrEqual(consts.LEAF_W);
  });

  it("the in-column children (sub-bytes / shift-rows / mix-columns / add-round-key) stay vertically aligned with each other", () => {
    // The pedagogical headline: the working state flows through one clean
    // column. After the gutter fix, the non-replica children of each round
    // should share an x-coordinate (or share width and start) — same column.
    // Byte-native round.5 has four children (Finding F3 merged the round-key
    // fetch into the single `xor-with-aux@1` AddRoundKey); all live in the
    // column, the key-expansion replica in the gutter.
    const g = aes128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const ids = [
      "round.5.sub-bytes",
      "round.5.shift-rows",
      "round.5.mix-columns",
      "round.5.add-round-key",
    ];
    const xs = ids.map((id) => boxes.get(id)?.x);
    // All x-coordinates are the same number (they share the column).
    expect(new Set(xs).size).toBe(1);
    // And the replica's x is strictly less than that shared column x.
    const replicaX = boxes.get("key-expansion@->round.5.add-round-key")?.x;
    expect(replicaX).toBeDefined();
    expect(replicaX).toBeLessThan(xs[0] ?? Number.POSITIVE_INFINITY);
  });

  it("the spine-replica flows on the spine row at the source's old slot (narrow scope-aware fix, 2026-05-17)", () => {
    // The replica `key-expansion@->initial.add-round-key` is the SPINE
    // replica for AES-128 — `initial.add-round-key` is the spineSuccessor
    // (first state-target of key-expansion). The replica takes over the
    // removed source's position on the canvas main row.
    //
    // **Pre-fix behavior (asserted by the old version of this test):**
    // ALL replicas of a single source — including the spine-replica —
    // lifted above their consumer at the same x. With key-expansion=
    // always + collapsed iterate, all replicas piled into a single
    // column at the canvas top, which the user read as "one replica
    // column" even though spine and aux are different dataflows.
    //
    // **Post-fix behavior:** the spine-replica flows on the spine row
    // (same y as its consumer) at the source's old slot. Aux fan-out
    // replicas (for OTHER consumers) keep stacking above their
    // consumer — that part of the layout is unchanged. See
    // `tests/replicate-fanout.test.ts` for the structural assertions
    // and `GraphView.tsx::buildReplicaPlacement` for the `isReplica`
    // exclusion that drives this layout difference.
    //
    // Synthetic fixture (Slice B1): byte-native AES has no state spine, so this
    // branch is driven by a hand-built graph — see `syntheticSpineReplicaGraph`.
    const g = syntheticSpineReplicaGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerBox = boxes.get(SPINE_CONSUMER_ID);
    const replicaBox = boxes.get(SPINE_REPLICA_ID);
    if (!consumerBox || !replicaBox) throw new Error("missing root box");
    // Spine-replica flows at the spine row (same y as consumer).
    expect(replicaBox.y).toBe(consumerBox.y);
    // Spine-replica sits at SOURCE's old slot — strictly left of the
    // consumer, where `key-expansion` was before Slice 7b removal.
    expect(replicaBox.x).toBeLessThan(consumerBox.x);
    // Slice 7b: original is gone from the graph — no overlap to worry about.
    expect(boxes.get("key-expansion")).toBeUndefined();
  });

  it("when no replicas are present, root row stays at CANVAS_MARGIN (no spurious lift)", () => {
    const g = aes128Graph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    // CANVAS_MARGIN = 60 (module-internal constant, bumped 24 → 44 → 60
    // across two 2026-05-17 polish rounds); pin via the observed top y
    // of the leftmost root child instead of importing it.
    const keyExp = boxes.get("key-expansion");
    if (!keyExp) throw new Error("missing key-expansion");
    // Without replicas, the row should sit flush against the top margin
    // — no extra LEAF_H + REPLICA_LIFT_GAP shift.
    expect(keyExp.y).toBe(60);
  });

  it("inside an iterate body (AES-128-ECB), replicas also lift above their consumer", () => {
    // Symmetric to the root-level test: the iterate body is also a
    // horizontal flow, so its spliced-before-consumer replicas need the
    // same orthogonal lift. Byte-native ECB (B1.4): key-expansion's per-round
    // consumers are the `*.add-round-key` (`aux-load-bytes@1`) leaves inside the
    // iterate; the first is `initial.add-round-key`, so the replica is
    // `key-expansion@->initial.add-round-key` and it lifts above that consumer.
    const g = aes128EcbReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerBox = boxes.get("initial.add-round-key");
    const replicaBox = boxes.get("key-expansion@->initial.add-round-key");
    if (!consumerBox || !replicaBox) {
      throw new Error("missing iterate-body box (consumer or replica)");
    }
    expect(replicaBox.y).toBeLessThan(consumerBox.y);
    expect(replicaBox.x).toBe(consumerBox.x);
  });

  it("Serpent (consumer-is-first-child): replica is LIFTED above the column, not in LEFT gutter", () => {
    // Serpent's per-round order is add-round-key → sub-bytes → linear-transform,
    // so the consumer (add-round-key) is the FIRST non-replica child. A
    // LEFT-gutter replica at consumer.y would obscure the incoming
    // inter-round spine arrow. The dual-strategy fix places the replica
    // ABOVE the consumer at the column's x instead — directly visible as
    // the replica's x matching add-round-key's x, and y strictly less.
    const g = serpent128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    // Pick any Serpent round (they're all identically structured).
    const consumerId = "round.5.add-round-key";
    const replicaId = `key-expansion@->${consumerId}`;
    const consumerBox = boxes.get(consumerId);
    const replicaBox = boxes.get(replicaId);
    if (!consumerBox || !replicaBox) {
      throw new Error("missing Serpent box (consumer or replica)");
    }
    // Lift: replica sits above consumer at the SAME x (column).
    expect(replicaBox.x).toBe(consumerBox.x);
    expect(replicaBox.y).toBeLessThan(consumerBox.y);
    // And the replica is NOT in a left gutter — its x is the column x,
    // not less than the column x. (LEFT-gutter replicas would have
    // replicaBox.x < consumerBox.x; the lift branch avoids that.)
  });

  it("Serpent: the lifted replica's y-range does not overlap any in-column child", () => {
    // The whole point: the lifted replica must NOT sit at the same y as
    // any of add-round-key / sub-bytes / linear-transform, otherwise the
    // incoming inter-round arrow at add-round-key's y could still be
    // obscured.
    const g = serpent128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const replicaBox = boxes.get("key-expansion@->round.5.add-round-key");
    if (!replicaBox) throw new Error("missing replica");
    const replicaBottom = replicaBox.y + replicaBox.h;
    for (const child of [
      "round.5.add-round-key",
      "round.5.sub-bytes",
      "round.5.linear-transform",
    ]) {
      const cBox = boxes.get(child);
      if (!cBox) throw new Error(`missing ${child}`);
      const cTop = cBox.y;
      const cBottom = cBox.y + cBox.h;
      const noOverlap = replicaBottom <= cTop || replicaBox.y >= cBottom;
      expect(noOverlap).toBe(true);
    }
  });

  it("Serpent: round groups grow TALLER (not wider) because the lift, not the gutter, is active", () => {
    // AES exercises the gutter branch → group WIDENS. Serpent exercises
    // the lift branch → group HEIGHTENS. Pin both behaviors so a future
    // refactor that accidentally collapses the dual strategy fails fast.
    const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      // Serpent's round body is port-native since B3 → ported dispatch required.
    });
    const noRep = deriveAuxGraph(trace, serpent128Spec);
    const withRep = replicateHighFanoutSources(noRep, 6);
    const empty = new Map<string, { x: number; y: number }>();
    const consts = layoutConstantsFor("normal");
    const a = layoutRoot(noRep, empty, consts).boxes;
    const b = layoutRoot(withRep, empty, consts).boxes;
    const r5a = a.get("round.5");
    const r5b = b.get("round.5");
    if (!r5a || !r5b) throw new Error("missing round.5");
    // Width unchanged (no left gutter in Serpent's case).
    expect(r5b.w).toBe(r5a.w);
    // Height increased by LEAF_H + REPLICA_LIFT_GAP exactly (the lift
    // amount — REPLICA_LIFT_GAP = 20 replaced STACK_GAP = 6 in the
    // replica path on 2026-05-16 to give the arrow shaft visible
    // length after ARROW_INSET subtraction).
    expect(r5b.h - r5a.h).toBe(consts.LEAF_H + consts.REPLICA_LIFT_GAP);
  });

  it("when no replicas are present, round groups keep their original (pre-gutter) width", () => {
    // Drive `layoutRoot` against the un-replicated graph — every round
    // should be sized as if the gutter logic didn't exist (the gutter
    // only opens when at least one replica child is present).
    const g = aes128Graph();
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const r5 = boxes.get("round.5");
    if (!r5) throw new Error("missing round.5 box");
    // Round groups in AES-128 stack 4 leaves; their natural width is
    // LEAF_W + 2*CONTAINER_PAD (the children dominate the formula). Pin
    // that exact value as a regression anchor — if the gutter
    // accidentally fires when no replicas exist, this fails.
    expect(r5.w).toBe(consts.LEAF_W + 2 * consts.CONTAINER_PAD);
  });
});

/**
 * Multiple-source-per-consumer replica stacking (Slice 7c).
 *
 * The bug this prevents: when the user sets MORE than one source's
 * replication override to "always" (e.g. both `compute-block-count` AND
 * `split-blocks` for the same iterate consumer), every replica targeting
 * the same consumer used to land at exactly `(consumer.x, consumer.y -
 * LEAF_H - STACK_GAP)`. Two replicas → same box → only the last-drawn one
 * is visible, clicks land on whichever ended up on top.
 *
 * **Slice 7c policy** (replaces the original per-consumer-x-step counter):
 * by-source rows. Each source claims a globally-stable row index in
 * `rowOfSource` (insertion order over `graph.nodes`). All replicas of
 * source A live at row 0 above their consumer; all replicas of source B
 * live at row 1; etc. Multiple sources targeting the SAME consumer stack
 * VERTICALLY — `replicaA.x === replicaB.x === consumer.x`,
 * `replicaB.y === replicaA.y - (LEAF_H + FLOW_GAP)`. Three layout
 * passes (root, group lift, iterate body) all read the same global
 * `rowOfSource` map, so source A always sits at row 0 across the whole
 * canvas — eye-trackable.
 *
 * The "don't overlap" guarantee from the original fix still holds (a
 * fixed two replicas no longer occupy the same box). It just rotates
 * 90° from horizontal tiling to vertical stacking. This is the first
 * brick in the cross-consumer scannability story (Slice 7b will then
 * fan state edges through the same row machinery).
 */
describe("GraphView — multiple sources targeting same consumer don't overlap", () => {
  // Helper: builds a minimal CipherGraph with N replica nodes all pointing
  // at one consumer. `consumerContainerPath` controls where the consumer
  // sits — `[]` for root, `["body"]` for inside an iterate body, etc.
  // Each replica gets its own aux edge so `buildReplicaPlacement` registers
  // it via `consumerOf`.
  const makeMultiReplicaGraph = (
    consumerId: string,
    replicaIds: readonly string[],
    extras: {
      readonly containers?: readonly ContainerNode[];
      readonly extraRootIds?: readonly string[];
      readonly consumerContainerPath?: readonly string[];
    } = {},
  ): CipherGraph => {
    const consumerContainerPath = extras.consumerContainerPath ?? [];
    const nodes: GraphNode[] = [
      {
        stepId: consumerId,
        stepType: "test.consumer",
        label: consumerId,
        containerPath: consumerContainerPath,
      },
      ...replicaIds.map(
        (rid): GraphNode => ({
          stepId: rid,
          stepType: "test.source",
          label: rid,
          containerPath: consumerContainerPath,
          // The marker that promotes this node into `isReplica`.
          replicaOf: rid.split("->")[0] ?? "src",
        }),
      ),
    ];
    const edges: GraphEdge[] = replicaIds.map((rid) => ({
      from: rid,
      to: consumerId,
      auxKey: "test-key",
      kind: "aux",
    }));
    // For root placement, rootIds includes both consumer and replicas (in
    // any order — buildReplicaPlacement reads them all). For nested cases,
    // the caller passes `extraRootIds` (e.g. the iterate container) and the
    // replicas/consumer live inside `extras.containers` via their childIds.
    const rootIds =
      consumerContainerPath.length === 0
        ? [...replicaIds, consumerId]
        : (extras.extraRootIds ?? []);
    return {
      nodes,
      containers: extras.containers ?? [],
      edges,
      rootIds,
    };
  };

  it("root: two replicas → same consumer stack VERTICALLY at consumer.x (Slice 7c)", () => {
    // Two synthetic replicas, both at root level, both pointing at one
    // consumer via aux edges. Pre-7c both would land at the same box;
    // the V1 fix tiled them rightward; Slice 7c stacks them vertically
    // by source row. Source A (encountered first via graph.nodes walk)
    // claims row 0; source B claims row 1.
    const g = makeMultiReplicaGraph("consumer", ["src-a->consumer", "src-b->consumer"]);
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const a = boxes.get("src-a->consumer");
    const b = boxes.get("src-b->consumer");
    const c = boxes.get("consumer");
    if (!a || !b || !c) throw new Error("missing synthetic box");
    // Row 0 at consumer.x; row 1 at consumer.x + REPLICA_ROW_X_STEP —
    // which equals consumer.x today (straight-line + offset-start
    // approach zeros the constant; upper-row arrows originate from
    // offset x positions on the column's bottom edges via
    // `replicaSourceXOffset` + start-dots).
    expect(a.x).toBe(c.x);
    expect(b.x).toBe(c.x + consts.REPLICA_ROW_X_STEP);
    // Vertical separation: source A on row 0 (close to consumer at
    // STACK_GAP), source B on row 1 (one LEAF_H + FLOW_GAP step higher
    // — wider gap so the arrow has visible drawing room).
    expect(a.y).toBeLessThan(c.y);
    expect(b.y).toBe(a.y - consts.LEAF_H - consts.REPLICA_STACK_GAP);
  });

  it("root: three replicas → same consumer stack VERTICALLY without overlap (Slice 7c)", () => {
    // Stress to N=3 — confirms each new source claims the next row.
    // Sources A/B/C → rows 0/1/2 respectively; all share consumer.x.
    const g = makeMultiReplicaGraph("consumer", [
      "src-a->consumer",
      "src-b->consumer",
      "src-c->consumer",
    ]);
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const a = boxes.get("src-a->consumer");
    const b = boxes.get("src-b->consumer");
    const c = boxes.get("src-c->consumer");
    const cons = boxes.get("consumer");
    if (!a || !b || !c || !cons) throw new Error("missing synthetic box");
    // Column x stack: row 0 at consumer.x; rows 1+ at the same x
    // (REPLICA_ROW_X_STEP === 0); the straight-line + offset-start
    // approach uses `replicaSourceXOffset` (signed shift of the
    // arrow's START point on the replica's bottom edge) + visible
    // start-dot rather than diagonal source displacement.
    expect(a.x).toBe(cons.x);
    expect(b.x).toBe(cons.x + consts.REPLICA_ROW_X_STEP);
    expect(c.x).toBe(cons.x + 2 * consts.REPLICA_ROW_X_STEP);
    // Strictly DECREASING y: row 0 at REPLICA_LIFT_GAP above consumer;
    // rows 1+ step up by `LEAF_H + REPLICA_STACK_GAP` (REPLICA_STACK_GAP
    // bumped from FLOW_GAP=24 to 48 on 2026-05-17 so the bundle ×N
    // pills sitting at arrow midpoints don't crowd adjacent rows).
    const rowStep = consts.LEAF_H + consts.REPLICA_STACK_GAP;
    expect(b.y).toBe(a.y - rowStep);
    expect(c.y).toBe(b.y - rowStep);
    // All three distinct ys (no overlap).
    expect(new Set([a.y, b.y, c.y]).size).toBe(3);
  });

  it("iterate body: two replicas → same consumer stack VERTICALLY (Slice 7c)", () => {
    // Build an iterate container whose body contains: replica-A, replica-B,
    // consumer. The iterate's layoutNode pass (horizontal-flow branch)
    // owns the placement loop; same by-source-row policy applies.
    const replicaA = "src-a->consumer";
    const replicaB = "src-b->consumer";
    const consumerId = "consumer";
    const iterateId = "iterate";
    const containers: ContainerNode[] = [
      {
        kind: "iterate",
        id: iterateId,
        label: "iterate",
        containerPath: [],
        // Order matters for placement: replicas first (the splice-before-
        // consumer convention), then the consumer.
        childIds: [replicaA, replicaB, consumerId],
        blockSpan: 2,
      },
    ];
    const g = makeMultiReplicaGraph(consumerId, [replicaA, replicaB], {
      containers,
      extraRootIds: [iterateId],
      consumerContainerPath: [iterateId],
    });
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const a = boxes.get(replicaA);
    const b = boxes.get(replicaB);
    const c = boxes.get(consumerId);
    if (!a || !b || !c) throw new Error("missing iterate-body synthetic box");
    // Row 0 at consumer.x; row 1 at consumer.x + REPLICA_ROW_X_STEP
    // (= consumer.x today since the curved-edge prototype zeros the
    // step — the bow on the row-1 edge handles the visual splay).
    expect(a.x).toBe(c.x);
    expect(b.x).toBe(c.x + consts.REPLICA_ROW_X_STEP);
    // Source A at row 0 (STACK_GAP above), source B at row 1
    // (LEAF_H + FLOW_GAP higher than row 0).
    expect(a.y).toBeLessThan(c.y);
    expect(b.y).toBe(a.y - consts.LEAF_H - consts.REPLICA_STACK_GAP);
  });

  it("group (lift branch): two replicas → first-child consumer stack VERTICALLY (Slice 7c)", () => {
    // Mirror of the iterate test, but for the vertical-stack group's LIFT
    // branch (consumer IS the first non-replica child). Same by-source
    // row policy applies — both replicas at consumer.x, separated in y.
    const replicaA = "src-a->consumer";
    const replicaB = "src-b->consumer";
    const consumerId = "consumer";
    const groupId = "group";
    const containers: ContainerNode[] = [
      {
        kind: "group",
        id: groupId,
        label: "group",
        containerPath: [],
        // Consumer is FIRST non-replica child → triggers lift branch (not
        // left-gutter). Both replicas point at this first child.
        childIds: [replicaA, replicaB, consumerId],
      },
    ];
    const g = makeMultiReplicaGraph(consumerId, [replicaA, replicaB], {
      containers,
      extraRootIds: [groupId],
      consumerContainerPath: [groupId],
    });
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const a = boxes.get(replicaA);
    const b = boxes.get(replicaB);
    const c = boxes.get(consumerId);
    if (!a || !b || !c) throw new Error("missing group-lift synthetic box");
    // Row 0 at consumer.x; row 1 at consumer.x + REPLICA_ROW_X_STEP
    // (= consumer.x today — curved-edge prototype zeros the step).
    expect(a.x).toBe(c.x);
    expect(b.x).toBe(c.x + consts.REPLICA_ROW_X_STEP);
    // Source A at row 0 (STACK_GAP above consumer), source B at row 1
    // (one LEAF_H + FLOW_GAP step higher — wider gap for arrow drawing
    // room per port-spreading polish, 2026-05-16).
    expect(a.y).toBeLessThan(c.y);
    expect(b.y).toBe(a.y - consts.LEAF_H - consts.REPLICA_STACK_GAP);
  });
});

/**
 * Aux-only root-leaf lift (Slice 1 visual companion — Section 5.15 of
 * the graph-narrative plan, surfaced during browser verification).
 *
 * The bug it prevents: post-Slice-1, the synthetic plaintext pill at
 * canvas left points (via the renderer's anchor heuristic) at the FIRST
 * state-consumer leaf — for AES single-block that's `initial.add-round-key`.
 * Geometrically the arrow runs from far left to past `key-expansion`'s
 * x-slot, and without a Y offset on `key-expansion`, that arrow passes
 * directly through `key-expansion`'s rectangle. Visually it reads as
 * "plaintext flows through key-expansion" which is wrong: key-expansion
 * is aux-only (state passes through identity).
 *
 * The fix: any root-level leaf whose `shapeContract.input === "any"`
 * is lifted to the same `CANVAS_MARGIN` row that root replicas occupy,
 * mirroring the existing visual language "above the spine = supporting
 * computation; on the spine = state flow."
 */
describe("GraphView — aux-only root leaves are lifted above the spine row", () => {
  it("places `key-expansion` at CANVAS_MARGIN and the spine row below it", () => {
    // No replicas — pure aux-only-lift behavior, isolated.
    const g = aes128Graph();
    const consts = layoutConstantsFor("normal");
    const empty = new Map<string, { x: number; y: number }>();
    const auxOnlyRootIds = new Set<string>(["key-expansion"]);
    const { boxes } = layoutRoot(g, empty, consts, auxOnlyRootIds);

    const ke = boxes.get("key-expansion");
    const initial = boxes.get("initial.add-round-key");
    if (!ke || !initial) throw new Error("missing key boxes");

    // key-expansion sits at the lifted row (CANVAS_MARGIN = 60).
    expect(ke.y).toBe(60);
    // The spine row sits one LEAF_H + REPLICA_LIFT_GAP below it (so
    // the arrow from a left-side endpoint pill clears the key-expansion
    // chip with a visible shaft — REPLICA_LIFT_GAP = 36 replaced
    // STACK_GAP = 6 on 2026-05-16).
    expect(initial.y).toBe(60 + consts.LEAF_H + consts.REPLICA_LIFT_GAP);
    // Both still flow left-to-right horizontally: key-expansion's x
    // is to the left of initial.add-round-key's.
    expect(ke.x).toBeLessThan(initial.x);
  });

  it("when no aux-only root leaves are present, spine stays at CANVAS_MARGIN", () => {
    // Empty auxOnlyRootIds → no lift → spine row is the top row.
    // Backward-compat: callers that pass nothing get the old behavior.
    const g = aes128Graph();
    const consts = layoutConstantsFor("normal");
    const empty = new Map<string, { x: number; y: number }>();
    const { boxes } = layoutRoot(g, empty, consts);

    const ke = boxes.get("key-expansion");
    const initial = boxes.get("initial.add-round-key");
    if (!ke || !initial) throw new Error("missing key boxes");

    // No lift: both sit at CANVAS_MARGIN = 60.
    expect(ke.y).toBe(60);
    expect(initial.y).toBe(60);
  });

  it("spine-replica + its consumer both flow on the spine row at CANVAS_MARGIN (no lift)", () => {
    // Replica-scope-aware fix (2026-05-17, narrow): the spine-replica
    // `key-expansion@->initial.add-round-key` takes over the removed
    // source's spec slot. It flows AS A REGULAR LEAF on the spine row
    // at source's old position, instead of being lifted above its
    // consumer like an aux-fan-out replica.
    //
    // Pre-fix behavior (pinned by the previous version of this test):
    // the spine-replica was at CANVAS_MARGIN (lifted row), the consumer
    // a LEAF_H + REPLICA_LIFT_GAP below. That two-row layout no longer
    // applies for single-source fixtures whose only replica IS the
    // spine-replica — both sit on the same row now.
    //
    // For a fixture that ALSO has aux-fan-out replicas (none at the
    // root level in AES-128 single-block — they live inside round
    // groups), the two-row layout still applies for those — see
    // `tests/graph-view-replica-placement.test.ts` for that case.
    // Synthetic fixture (Slice B1): byte-native AES has no state spine, so this
    // branch is driven by a hand-built graph — see `syntheticSpineReplicaGraph`.
    const g = syntheticSpineReplicaGraph();
    const consts = layoutConstantsFor("normal");
    const empty = new Map<string, { x: number; y: number }>();
    const { boxes } = layoutRoot(g, empty, consts);

    const replica = boxes.get(SPINE_REPLICA_ID);
    const initial = boxes.get(SPINE_CONSUMER_ID);
    if (!replica || !initial) throw new Error("missing key boxes");
    // Spine-replica flows at CANVAS_MARGIN — the spine row, no lift.
    expect(replica.y).toBe(60);
    // Consumer also sits at the spine row — both at the same y.
    expect(initial.y).toBe(60);
    // Spine-replica sits LEFT of consumer at source's old slot — the
    // splice-before-spineSuccessor logic puts it where key-expansion
    // used to be in rootIds, so layout flows source's-old-slot →
    // consumer left-to-right.
    expect(replica.x).toBeLessThan(initial.x);
    // Strictly: separated by at least one column-width + FLOW_GAP
    // (no overlap), so the spine arrow has visible length.
    expect(initial.x - replica.x).toBeGreaterThanOrEqual(consts.LEAF_W);
    // Original key-expansion is gone (Slice 7b removal).
    expect(boxes.get("key-expansion")).toBeUndefined();
  });
});

/**
 * Slice-2 root-replica anchor for iterate consumers.
 *
 * The bug it prevents: prior to Slice 2, a root-level replica whose
 * consumer is a wide iterate (e.g. AES-128 ECB's `ecb-blocks` at ~1500px)
 * was placed at `consumer.x` — above the iterate's LEFT edge. The
 * EdgePath then routed the aux arrow from the replica's center down to
 * the iterate's center-top, sweeping ~750px horizontally on a real ECB
 * trace. The pedagogical reading was wrong too: the iterate's
 * `countFromAux` / `blocksFromAux` are consumed at iteration entry, which
 * is conceptually "at the start of the body," not "at the iterate
 * container's left edge."
 *
 * The fix: in `layoutRoot`'s root-replica placement loop, when the
 * consumer container is an `iterate`, anchor the replica above the
 * iterate body's FIRST child (`childIds[0]`) instead of the iterate's
 * own x. The arrow drops into "the start of the body where the aux is
 * read," matching the runtime's read order.
 */
describe("GraphView — root replica with iterate consumer anchors above first body child", () => {
  // [DELETED B1.4a] The AES-128-ECB integration test that force-replicated
  // `compute-block-count` (an aux-mode multi-block plumbing leaf) and asserted
  // the matrix spine-replica-to-iterate placement / `visualEdgeTargetId`
  // retarget is gone: byte-native ECB (port-mode iterate) has no
  // compute-block-count / split-blocks and produces no replica edge pointing
  // AT the iterate (key-expansion replicates to the in-body `*.add-round-key`
  // leaves instead). The underlying layout machinery stays covered by the
  // SYNTHETIC fixtures in this file (sibling tests below). Per the sweep
  // discriminator we do NOT retarget this matrix-structure integration onto
  // soon-to-convert CBC; it retires with Phase C / the matrix iterate.

  it("an aux-fan-out replica with iterate consumer still anchors above first body child (Slice-2 invariant)", () => {
    // Slice-2 anchor logic still applies to aux-fan-out replicas — the
    // narrow scope-aware fix only changes spine-replica placement.
    // Synthetic fixture mirrors the Slice-2 case but ensures the replica
    // is NOT the spine entry: `src` emits a STATE edge to a non-iterate
    // leaf (`spine-target`, the spineSuccessor) AND an AUX edge to an
    // iterate (`iter`). After replication:
    //   - `src@->spine-target` is the spine-replica (flows at source's
    //     old slot, NOT tested here).
    //   - `src@->iter` is an AUX-FAN-OUT replica with iterate consumer
    //     → THIS one tests the Slice-2 anchor.
    //
    // The replica uses `replicateHighFanoutSources` so the spine flag
    // is set correctly by the production code path (not hand-marked
    // in the fixture).
    const firstBodyId = "first-body";
    const iterId = "iter";
    const spineTargetId = "spine-target";
    const srcId = "src";
    const g: CipherGraph = {
      nodes: [
        { stepId: srcId, stepType: "test.source", label: srcId, containerPath: [] },
        {
          stepId: spineTargetId,
          stepType: "test.consumer",
          label: spineTargetId,
          containerPath: [],
        },
        {
          stepId: firstBodyId,
          stepType: "test.consumer",
          label: firstBodyId,
          containerPath: [iterId],
        },
      ],
      containers: [
        {
          kind: "iterate",
          id: iterId,
          label: iterId,
          containerPath: [],
          childIds: [firstBodyId],
          blockSpan: 1,
        },
      ],
      edges: [
        // State edge from src → spine-target makes spine-target the
        // spineSuccessor. The replica `src@->spine-target` flags
        // isSpineReplica=true.
        { from: srcId, to: spineTargetId, auxKey: "state", kind: "state" },
        // Two aux edges (need fanout ≥ 2 for replication eligibility):
        // one to the iterate, one to a throwaway leaf so total outgoing
        // count is ≥ 2. The iterate-target one tests Slice-2 anchor.
        { from: srcId, to: spineTargetId, auxKey: "aux-1", kind: "aux" },
        { from: srcId, to: iterId, auxKey: "aux-2", kind: "aux" },
      ],
      rootIds: [srcId, spineTargetId, iterId],
    };
    // threshold=1 → src qualifies (fanout=2 > 1).
    const replicated = replicateHighFanoutSources(g, 1);
    const consts = layoutConstantsFor("normal");
    const empty = new Map<string, { x: number; y: number }>();
    const { boxes } = layoutRoot(replicated, empty, consts);

    const auxReplicaId = "src@->iter";
    const replicaBox = boxes.get(auxReplicaId);
    const iterateBox = boxes.get(iterId);
    const firstChildBox = boxes.get(firstBodyId);
    if (!replicaBox || !iterateBox || !firstChildBox) {
      throw new Error(
        `missing box: replica=${!!replicaBox} iterate=${!!iterateBox} firstChild=${!!firstChildBox}`,
      );
    }

    // Slice-2 anchor: aux-fan-out replica.x === first body child's x.
    // Half-leaf tolerance for future CONTAINER_PAD/LEAF_W ratio shifts.
    expect(Math.abs(replicaBox.x - firstChildBox.x)).toBeLessThanOrEqual(consts.LEAF_W / 2);
    // Replica is shifted RIGHT of the iterate's own left edge.
    expect(replicaBox.x).toBeGreaterThan(iterateBox.x);
    // Replica is LIFTED above its consumer (the original Slice-2 invariant).
    expect(replicaBox.y).toBeLessThan(iterateBox.y);
  });

  it("falls back to the iterate's left edge when the iterate body is empty (collapsed)", () => {
    // Defensive: a collapsed iterate has `childIds === []` (collapseGraph
    // clears them). The anchor lookup should degrade to the iterate's own
    // x — the previous behavior — so collapsing doesn't crash or place
    // the replica off-canvas.
    //
    // Synthetic graph: one source, one iterate consumer with no body
    // (childIds empty), one aux edge. Mirrors how a post-collapse graph
    // looks to layoutRoot.
    const consumerId = "iterate";
    const replicaId = "src->iterate";
    const g: CipherGraph = {
      nodes: [
        {
          stepId: "src",
          stepType: "test.source",
          label: "src",
          containerPath: [],
        },
        {
          stepId: replicaId,
          stepType: "test.source",
          label: replicaId,
          containerPath: [],
          replicaOf: "src",
        },
      ],
      containers: [
        {
          kind: "iterate",
          id: consumerId,
          label: "iterate",
          containerPath: [],
          childIds: [], // Collapsed — no body children.
          blockSpan: 1,
        },
      ],
      edges: [{ from: replicaId, to: consumerId, auxKey: "test-key", kind: "aux" }],
      rootIds: ["src", replicaId, consumerId],
    };
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const r = boxes.get(replicaId);
    const c = boxes.get(consumerId);
    if (!r || !c) throw new Error("missing collapsed-iterate box");
    // Fallback: replica.x === consumer.x (no first-child to anchor to).
    expect(r.x).toBe(c.x);
    expect(r.y).toBeLessThan(c.y);
  });

  it("non-iterate consumers (leaves) are unaffected — replica still sits at consumer.x", () => {
    // Slice 2 only special-cases iterate consumers. A replica whose
    // consumer is a regular leaf must continue to land at consumer.x —
    // the polish item #2 stacking test (`root: two replicas → same
    // consumer get distinct x positions`) already pins this for the
    // leaf-consumer case, but verify here too as a focused regression.
    const g = makeMultiReplicaGraphForLeaf("consumer", ["src-a->consumer"]);
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const r = boxes.get("src-a->consumer");
    const c = boxes.get("consumer");
    if (!r || !c) throw new Error("missing synthetic box");
    // Leaf consumer → no special-case → replica still anchored at consumer.x.
    expect(r.x).toBe(c.x);
  });
});

// Small synthetic-graph helper kept module-local to the test file. Mirrors
// `makeMultiReplicaGraph` above but skipped the `containers` plumbing —
// this is purely for the "leaf consumer" regression case.
const makeMultiReplicaGraphForLeaf = (
  consumerId: string,
  replicaIds: readonly string[],
): CipherGraph => {
  const nodes: GraphNode[] = [
    {
      stepId: consumerId,
      stepType: "test.consumer",
      label: consumerId,
      containerPath: [],
    },
    ...replicaIds.map(
      (rid): GraphNode => ({
        stepId: rid,
        stepType: "test.source",
        label: rid,
        containerPath: [],
        replicaOf: rid.split("->")[0] ?? "src",
      }),
    ),
  ];
  const edges: GraphEdge[] = replicaIds.map((rid) => ({
    from: rid,
    to: consumerId,
    auxKey: "test-key",
    kind: "aux",
  }));
  return {
    nodes,
    containers: [],
    edges,
    rootIds: [...replicaIds, consumerId],
  };
};

/**
 * Slice-2 follow-up: `visualEdgeTargetId` retargets replica→iterate aux
 * edges to terminate at the iterate body's first child. Pure-function
 * tests exercise all four branches directly; one integration check
 * against the AES-128-ECB fixture confirms the helper composes with
 * the actual derived graph.
 *
 * The pure helper is exercised in isolation rather than asserting on
 * the rendered `<path d="...">` bezier coordinates — those would
 * re-baseline on every density tweak or curve refactor, and the
 * helper's branches are the actual behavior under test.
 */
describe("visualEdgeTargetId — retargets replica→iterate edges to first body child", () => {
  // Pure-helper tests build a `nodesById` + `containersById` pair
  // directly. The helper doesn't touch boxes or layout — it just maps
  // edge → target stepId, so synthetic inputs cover every branch
  // without running `layoutRoot`.
  const makeMaps = (
    nodes: readonly GraphNode[],
    containers: readonly ContainerNode[],
  ): {
    nodesById: Map<string, GraphNode>;
    containersById: Map<string, ContainerNode>;
  } => {
    const nodesById = new Map<string, GraphNode>();
    for (const n of nodes) nodesById.set(n.stepId, n);
    const containersById = new Map<string, ContainerNode>();
    for (const c of containers) containersById.set(c.id, c);
    return { nodesById, containersById };
  };

  it("retargets replica→iterate to first body child when iterate has children", () => {
    const replicaNode: GraphNode = {
      stepId: "src->iterate",
      stepType: "test.source",
      label: "replica",
      containerPath: [],
      replicaOf: "src",
    };
    const consumerNode: GraphNode = {
      stepId: "first-body-step",
      stepType: "test.consumer",
      label: "first-body-step",
      containerPath: ["iterate"],
    };
    const iterate: ContainerNode = {
      kind: "iterate",
      id: "iterate",
      label: "iterate",
      containerPath: [],
      childIds: ["first-body-step", "second-body-step"],
      blockSpan: 2,
    };
    const { nodesById, containersById } = makeMaps([replicaNode, consumerNode], [iterate]);
    const edge: GraphEdge = {
      from: "src->iterate",
      to: "iterate",
      auxKey: "blockCount",
      kind: "aux",
    };
    // Retarget kicks in: source is a replica, target is an iterate
    // with a body. Visual endpoint becomes the first body child.
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("first-body-step");
  });

  it("falls back to the iterate's own id when the iterate body is empty (collapsed)", () => {
    // `collapseGraph` clears `childIds` for collapsed containers.
    // The retarget can't pick a first child, so the visual endpoint
    // stays at the iterate itself — preserving the pre-fix arrow.
    const replicaNode: GraphNode = {
      stepId: "src->iterate",
      stepType: "test.source",
      label: "replica",
      containerPath: [],
      replicaOf: "src",
    };
    const collapsedIterate: ContainerNode = {
      kind: "iterate",
      id: "iterate",
      label: "iterate",
      containerPath: [],
      childIds: [],
      blockSpan: 4,
    };
    const { nodesById, containersById } = makeMaps([replicaNode], [collapsedIterate]);
    const edge: GraphEdge = {
      from: "src->iterate",
      to: "iterate",
      auxKey: "blockCount",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("iterate");
  });

  it("does NOT retarget when target is a leaf (not an iterate container)", () => {
    // Slice 2 + this follow-up only special-case iterate consumers.
    // A replica whose consumer is a regular leaf keeps the natural
    // edge endpoint — short arrow lands on the leaf itself.
    const replicaNode: GraphNode = {
      stepId: "src->consumer",
      stepType: "test.source",
      label: "replica",
      containerPath: [],
      replicaOf: "src",
    };
    const consumerNode: GraphNode = {
      stepId: "consumer",
      stepType: "test.consumer",
      label: "consumer",
      containerPath: [],
    };
    const { nodesById, containersById } = makeMaps([replicaNode, consumerNode], []);
    const edge: GraphEdge = {
      from: "src->consumer",
      to: "consumer",
      auxKey: "round-key",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("consumer");
  });

  it("does NOT retarget when target is a group container (only iterate triggers retarget)", () => {
    // Defensive: a hypothetical replica→group edge stays anchored on
    // the group. Today no such edge exists (state spine is sacred,
    // groups are never replication consumers in practice), but pin
    // the branch so a future refactor doesn't accidentally widen the
    // special case.
    const replicaNode: GraphNode = {
      stepId: "src->group",
      stepType: "test.source",
      label: "replica",
      containerPath: [],
      replicaOf: "src",
    };
    const group: ContainerNode = {
      kind: "group",
      id: "group",
      label: "group",
      containerPath: [],
      childIds: ["child-a", "child-b"],
    };
    const { nodesById, containersById } = makeMaps([replicaNode], [group]);
    const edge: GraphEdge = {
      from: "src->group",
      to: "group",
      auxKey: "test",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("group");
  });

  it("skips past in-body replicas to find the first REAL body step", () => {
    // `replicateHighFanoutSources` splices its synthetic replica chips
    // into the consumer's parent `childIds` immediately BEFORE the
    // consumer. For an iterate body, that means `childIds[0]` is often
    // a replica (e.g. `key-expansion@->initial.add-round-key`) ahead of
    // the actual first step (`initial.add-round-key`). Anchoring the
    // arrowhead at the replica chip would misleadingly suggest the
    // count flows into a key-expansion replica. Skip past replicas so
    // the visual target is the first non-replica body step.
    const outerReplicaNode: GraphNode = {
      stepId: "src->iterate",
      stepType: "test.source",
      label: "outer replica",
      containerPath: [],
      replicaOf: "src",
    };
    const inBodyReplicaNode: GraphNode = {
      stepId: "key-expansion@->initial.add-round-key",
      stepType: "test.source",
      label: "in-body replica",
      containerPath: ["iterate"],
      replicaOf: "key-expansion",
    };
    const realFirstStep: GraphNode = {
      stepId: "initial.add-round-key",
      stepType: "test.consumer",
      label: "initial.add-round-key",
      containerPath: ["iterate"],
    };
    const iterate: ContainerNode = {
      kind: "iterate",
      id: "iterate",
      label: "iterate",
      containerPath: [],
      // Replica spliced BEFORE the real first step — typical of the
      // post-replication graph.
      childIds: ["key-expansion@->initial.add-round-key", "initial.add-round-key"],
      blockSpan: 2,
    };
    const { nodesById, containersById } = makeMaps(
      [outerReplicaNode, inBodyReplicaNode, realFirstStep],
      [iterate],
    );
    const edge: GraphEdge = {
      from: "src->iterate",
      to: "iterate",
      auxKey: "blockCount",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("initial.add-round-key");
  });

  it("does NOT retarget when source is NOT a replica (non-replica → iterate stays anchored on the iterate)", () => {
    // The natural state-spine arrow into an iterate (e.g.
    // `compute-block-count → ecb-blocks` BEFORE replication forces a
    // replica) should keep landing at the iterate's center-top, where
    // the user sees "the iterate consumes this." The retarget is
    // strictly a replica-edge concern.
    const sourceNode: GraphNode = {
      stepId: "compute-block-count",
      stepType: "generic.compute-block-count@1",
      label: "compute-block-count",
      containerPath: [],
      // No replicaOf field → not a replica.
    };
    const iterate: ContainerNode = {
      kind: "iterate",
      id: "ecb-blocks",
      label: "ecb-blocks",
      containerPath: [],
      childIds: ["initial.add-round-key"],
      blockSpan: 2,
    };
    const { nodesById, containersById } = makeMaps([sourceNode], [iterate]);
    const edge: GraphEdge = {
      from: "compute-block-count",
      to: "ecb-blocks",
      auxKey: "blockCount",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("ecb-blocks");
  });

  // Option C — collapsed-iterate retarget escape hatch. When the iterate's
  // first non-replica child is a block chip (`blockChipOf !== undefined`,
  // produced by `expandCollapsedIterates`), the retarget MUST fall back
  // to the iterate id. Without this, the visual edge from a replica
  // lands on block 1's chip and the user reads "feeds only block 1" —
  // which contradicts the runtime (aux is consumed at iteration entry
  // and seeds every block).
  it("does NOT retarget past a block-chip first child (Option C — collapsed iterate)", () => {
    const replicaNode: GraphNode = {
      stepId: "src@->iter",
      stepType: "test.source",
      label: "replica",
      containerPath: [],
      replicaOf: "src",
    };
    const blockChip: GraphNode = {
      stepId: "iter@block0",
      stepType: "__block_chip__",
      label: "block 1",
      containerPath: ["iter"],
      blockChipOf: "iter",
    };
    const iter: ContainerNode = {
      kind: "iterate",
      id: "iter",
      label: "iter",
      containerPath: [],
      childIds: ["iter@block0"],
      blockSpan: 2,
    };
    const { nodesById, containersById } = makeMaps([replicaNode, blockChip], [iter]);
    const edge: GraphEdge = {
      from: "src@->iter",
      to: "iter",
      auxKey: "key",
      kind: "aux",
    };
    expect(visualEdgeTargetId(edge, nodesById, containersById)).toBe("iter");
  });
});
