// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot`.

/**
 * Slice 2 of the draggable-replicas plan (2026-05-19).
 *
 * Layout-engine layer: `layoutRoot` and `layoutNode` accept an optional
 * `relativePins` map. Synthetic-id chips (aux replicas, block chips)
 * get their auto-laid position adjusted by `(dx, dy)` before the box
 * lands in `out`. The pin is RELATIVE — when the chip's anchor moves
 * (the consumer is dragged, the iterate is repositioned), the chip
 * rides along.
 *
 * Properties this file pins:
 *
 *   1. **Zero-pin parity.** Calling `layoutRoot` without a `relativePins`
 *      argument is byte-identical to the legacy three-arg call. Defaults
 *      preserve every shipped placement.
 *   2. **Replica delta.** A single `{ dx, dy }` entry on a replica's
 *      synthetic id shifts ONLY that replica's rendered box; the other
 *      replicas and the consumer stay where the algorithm put them.
 *   3. **Block-chip delta.** A block-chip synthetic id (Slice-6 collapse
 *      form) also accepts a delta. The chip flows through `layoutNode`'s
 *      regular leaf path, so the same mechanism covers chips without a
 *      separate code path.
 *   4. **Anchor-follows.** Dragging the consumer (absolute pin on
 *      `pinned`) moves the replica's auto position with it; with a
 *      relative pin layered on top, the replica box ends up at
 *      `newAuto + delta`. The chip "rides" the consumer.
 *   5. **Flow isolation.** A relative pin on a chip does NOT shift the
 *      chip's flow siblings — `layoutNode` returns the AUTO box for
 *      flow advancement, so a pinned chip leaves a hole at its old slot
 *      instead of sucking neighbours leftward.
 */

import type { CipherGraph, ContainerNode, GraphEdge, GraphNode } from "@/core/graph";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Helpers (mirrored shape from graph-view-replica-placement.test.ts) ───

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

const consumerNode = (id: string): GraphNode => ({
  stepId: id,
  stepType: "test.consumer",
  label: id,
  containerPath: [],
});

const replicaNode = (id: string, sourceId: string): GraphNode => ({
  stepId: id,
  stepType: "test.source",
  label: id,
  containerPath: [],
  replicaOf: sourceId,
});

const auxEdge = (from: string, to: string): GraphEdge => ({
  from,
  to,
  auxKey: "test-key",
  kind: "aux",
});

const EMPTY_PIN_MAP = new Map<string, { x: number; y: number }>();

// Realistic-shaped synthetic ids: `${source}@->${consumer}` is what
// `replicateHighFanoutSources` actually emits. Tests use the same format
// so a future change to the synthetic-id grammar surfaces here.
const REPLICA_ID = "key@->c1";

const buildOneReplicaGraph = (): CipherGraph =>
  buildSyntheticGraph({
    nodes: [consumerNode("c1"), consumerNode("c2"), replicaNode(REPLICA_ID, "key")],
    edges: [auxEdge(REPLICA_ID, "c1")],
    rootIds: [REPLICA_ID, "c1", "c2"],
  });

// ─── Test 1: Zero-pin parity ──────────────────────────────────────────────

describe("draggable-replicas layout — zero-pin parity", () => {
  it("layoutRoot without relativePins is byte-identical to legacy 3-arg call", () => {
    const g = buildOneReplicaGraph();
    const consts = layoutConstantsFor("normal");
    const legacy = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const withEmpty = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, new Map());
    for (const [id, box] of legacy.boxes) {
      expect(withEmpty.boxes.get(id)).toEqual(box);
    }
    expect(withEmpty.canvasW).toBe(legacy.canvasW);
    expect(withEmpty.canvasH).toBe(legacy.canvasH);
  });
});

// ─── Test 2: Replica delta ────────────────────────────────────────────────

describe("draggable-replicas layout — replica delta application", () => {
  it("a relative pin on a replica id shifts ONLY that replica box by (dx, dy)", () => {
    const g = buildOneReplicaGraph();
    const consts = layoutConstantsFor("normal");
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const autoReplica = auto.boxes.get(REPLICA_ID);
    const autoC1 = auto.boxes.get("c1");
    if (!autoReplica || !autoC1) throw new Error("missing auto boxes");

    const relativePins = new Map<string, { dx: number; dy: number }>([
      [REPLICA_ID, { dx: 30, dy: -12 }],
    ]);
    const pinned = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, relativePins);
    const pinnedReplica = pinned.boxes.get(REPLICA_ID);
    const pinnedC1 = pinned.boxes.get("c1");
    if (!pinnedReplica || !pinnedC1) throw new Error("missing pinned boxes");

    // Replica shifted by delta exactly.
    expect(pinnedReplica.x).toBe(autoReplica.x + 30);
    expect(pinnedReplica.y).toBe(autoReplica.y - 12);

    // Consumer unaffected — the consumer's flow position is independent
    // of any replica pin (the replica is in the lifted row, not the
    // flow row).
    expect(pinnedC1.x).toBe(autoC1.x);
    expect(pinnedC1.y).toBe(autoC1.y);
  });

  it("canvas extent grows to fit a chip dragged off the auto bounds", () => {
    const g = buildOneReplicaGraph();
    const consts = layoutConstantsFor("normal");
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);

    // Drag the replica 500 px to the right — canvasW must grow.
    const relativePins = new Map<string, { dx: number; dy: number }>([
      [REPLICA_ID, { dx: 500, dy: 0 }],
    ]);
    const pinned = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, relativePins);
    expect(pinned.canvasW).toBeGreaterThan(auto.canvasW);
  });
});

// ─── Test 3: Block-chip delta ─────────────────────────────────────────────

describe("draggable-replicas layout — block-chip delta application", () => {
  it("a relative pin on a block-chip id shifts the chip's rendered box", () => {
    // Build a synthetic collapsed-iterate graph with chip ids. Mirrors
    // what `expandIterateChildrenAsChips` (in core/graph.ts) produces:
    // chips become the iterate container's childIds, each chip carries
    // `blockChipOf` pointing at the iterate id.
    const ITERATE_ID = "iter";
    const CHIP_0 = "iter@block0";
    const CHIP_1 = "iter@block1";
    const g = buildSyntheticGraph({
      nodes: [
        {
          stepId: CHIP_0,
          stepType: "__block_chip__",
          label: "block 1",
          containerPath: [ITERATE_ID],
          blockChipOf: ITERATE_ID,
        },
        {
          stepId: CHIP_1,
          stepType: "__block_chip__",
          label: "block 2",
          containerPath: [ITERATE_ID],
          blockChipOf: ITERATE_ID,
        },
      ],
      containers: [
        {
          id: ITERATE_ID,
          kind: "iterate",
          label: "iter",
          containerPath: [],
          childIds: [CHIP_0, CHIP_1],
        },
      ],
      edges: [],
      rootIds: [ITERATE_ID],
    });
    const consts = layoutConstantsFor("normal");
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const autoChip = auto.boxes.get(CHIP_1);
    if (!autoChip) throw new Error("missing auto chip box");

    const relativePins = new Map<string, { dx: number; dy: number }>([[CHIP_1, { dx: 0, dy: 40 }]]);
    const pinned = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, relativePins);
    const pinnedChip = pinned.boxes.get(CHIP_1);
    if (!pinnedChip) throw new Error("missing pinned chip box");

    expect(pinnedChip.x).toBe(autoChip.x);
    expect(pinnedChip.y).toBe(autoChip.y + 40);
  });

  it("canvasH grows to fit a block chip dragged downward past the iterate's natural bottom", () => {
    // Bug reproduction (2026-05-19 manual smoke): the user reports that
    // dragging a replica chip downward leaves it visually clipped — the
    // SVG height (driven by `canvasH`) does NOT grow to include the
    // chip's new bottom. Other root-level drags (e.g. dragging a
    // root-level leaf) DO grow the canvas. The asymmetry traces to
    // `layoutRoot`'s extent tracking: root replicas update `maxBottom`
    // (line 1530) but iterate-body chips/replicas only update an x-
    // extent (`maxIterateReplicaRight`) and the container's `box.h` is
    // computed from natural child sizes — so a pin that pushes the
    // chip below the container's natural bottom escapes the canvas
    // extent calculation entirely.
    //
    // Property: after dragging an iterate-body block chip 200 px down,
    // `canvasH` must be at least the chip's new bottom + CANVAS_MARGIN.
    const ITERATE_ID = "iter";
    const CHIP_0 = "iter@block0";
    const g = buildSyntheticGraph({
      nodes: [
        {
          stepId: CHIP_0,
          stepType: "__block_chip__",
          label: "block 1",
          containerPath: [ITERATE_ID],
          blockChipOf: ITERATE_ID,
        },
      ],
      containers: [
        {
          id: ITERATE_ID,
          kind: "iterate",
          label: "iter",
          containerPath: [],
          childIds: [CHIP_0],
        },
      ],
      edges: [],
      rootIds: [ITERATE_ID],
    });
    const consts = layoutConstantsFor("normal");
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const autoChip = auto.boxes.get(CHIP_0);
    if (!autoChip) throw new Error("missing auto chip box");

    const DRAG_DOWN = 200;
    const relativePins = new Map<string, { dx: number; dy: number }>([
      [CHIP_0, { dx: 0, dy: DRAG_DOWN }],
    ]);
    const pinned = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, relativePins);
    const pinnedChip = pinned.boxes.get(CHIP_0);
    if (!pinnedChip) throw new Error("missing pinned chip box");

    const chipBottom = pinnedChip.y + pinnedChip.h;
    // Allow whatever CANVAS_MARGIN the layout uses by asserting the
    // STRICT inequality: canvasH must be greater than the chip's
    // bottom, not just equal. (Margin > 0 means a strict gap exists.)
    expect(pinned.canvasH).toBeGreaterThan(chipBottom);
  });

  it("chip pin does NOT shift sibling chips' flow positions (auto box returned for flow)", () => {
    // Two chips: chip0 then chip1. Pin chip0 with a horizontal delta;
    // chip1's auto position must stay where it would be if chip0 hadn't
    // moved — otherwise dragging a chip would push its siblings around,
    // which is not what the user wants from a "personal taste" pin.
    const ITERATE_ID = "iter";
    const CHIP_0 = "iter@block0";
    const CHIP_1 = "iter@block1";
    const g = buildSyntheticGraph({
      nodes: [
        {
          stepId: CHIP_0,
          stepType: "__block_chip__",
          label: "block 1",
          containerPath: [ITERATE_ID],
          blockChipOf: ITERATE_ID,
        },
        {
          stepId: CHIP_1,
          stepType: "__block_chip__",
          label: "block 2",
          containerPath: [ITERATE_ID],
          blockChipOf: ITERATE_ID,
        },
      ],
      containers: [
        {
          id: ITERATE_ID,
          kind: "iterate",
          label: "iter",
          containerPath: [],
          childIds: [CHIP_0, CHIP_1],
        },
      ],
      edges: [],
      rootIds: [ITERATE_ID],
    });
    const consts = layoutConstantsFor("normal");
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const autoChip1 = auto.boxes.get(CHIP_1);
    if (!autoChip1) throw new Error("missing chip1 box");

    const relativePins = new Map<string, { dx: number; dy: number }>([
      [CHIP_0, { dx: 100, dy: 100 }],
    ]);
    const pinned = layoutRoot(g, EMPTY_PIN_MAP, consts, new Set(), undefined, relativePins);
    const pinnedChip1 = pinned.boxes.get(CHIP_1);
    if (!pinnedChip1) throw new Error("missing pinned chip1 box");

    // chip1 sits where it always sat — chip0's pin is visual-only.
    expect(pinnedChip1.x).toBe(autoChip1.x);
    expect(pinnedChip1.y).toBe(autoChip1.y);
  });
});

// ─── Test 4: Anchor-follows ───────────────────────────────────────────────

describe("draggable-replicas layout — anchor-follows behavior", () => {
  it("dragging the consumer (absolute pin) shifts the replica's auto position; layered relative pin still applies", () => {
    const g = buildOneReplicaGraph();
    const consts = layoutConstantsFor("normal");
    // Baseline: no pins at all.
    const auto = layoutRoot(g, EMPTY_PIN_MAP, consts);
    const autoReplica = auto.boxes.get(REPLICA_ID);
    const autoC1 = auto.boxes.get("c1");
    if (!autoReplica || !autoC1) throw new Error("missing auto boxes");

    // Pin the CONSUMER absolutely 200 px to the right + 50 px down.
    const consumerPin = new Map<string, { x: number; y: number }>([
      ["c1", { x: autoC1.x + 200, y: autoC1.y + 50 }],
    ]);
    // Layer a relative pin (10, -5) on the replica.
    const relativePins = new Map<string, { dx: number; dy: number }>([
      [REPLICA_ID, { dx: 10, dy: -5 }],
    ]);
    const pinned = layoutRoot(g, consumerPin, consts, new Set(), undefined, relativePins);
    const pinnedReplica = pinned.boxes.get(REPLICA_ID);
    const pinnedC1 = pinned.boxes.get("c1");
    if (!pinnedReplica || !pinnedC1) throw new Error("missing pinned boxes");

    // Consumer landed at the absolute pin.
    expect(pinnedC1.x).toBe(autoC1.x + 200);
    expect(pinnedC1.y).toBe(autoC1.y + 50);

    // The replica's auto position is derived from the consumer's box
    // (`replicaSlotPosition(consumerBox.x, consumerBox.y, ...)`), so a
    // consumer pinned 200/50 over carries the replica's auto position
    // with it. Adding the relative (10, -5) on top:
    //   newReplica = (autoReplica.x + 200) + 10, (autoReplica.y + 50) − 5
    expect(pinnedReplica.x).toBe(autoReplica.x + 200 + 10);
    expect(pinnedReplica.y).toBe(autoReplica.y + 50 - 5);
  });
});
