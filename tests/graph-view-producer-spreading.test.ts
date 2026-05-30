// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure helper exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the test
// only calls `buildProducerPortAssignment` + `producerPortOffset`.

/**
 * Port-spreading at producer tail — per-producer slot semantics (the
 * outgoing-edge mirror of `graph-view-port-spreading.test.ts`). Where the
 * consumer-head spreader distributes N INCOMING arrows across a consumer's
 * attach edge, this distributes N OUTGOING arrows across a producer's exit
 * edge — so a node that fans out to several consumers (AES `key-expansion`
 * → 11 round keys with replication OFF) emits each tail from a distinct
 * point on its bottom / right edge instead of stacking them at one centre.
 *
 * Properties pinned here:
 *
 *   1. **Single-outgoing no-op** — a source with one outgoing edge gets
 *      `slotOf.get(edge) === undefined` → offset 0 for any `portGap`.
 *   2. **Multi-outgoing spread** — N outgoing edges from one source →
 *      offsets `(i - (N-1)/2) * portGap`, centred on the exit-edge midpoint.
 *   3. **Target-ordered slots** — when a target-coordinate callback is
 *      supplied, slots follow target position (cross-axis) so the fan-out
 *      leaves in target order and doesn't cross at the source.
 *   4. **Side bucketing** — edges leaving DIFFERENT sides of one source
 *      (e.g. one bottom, one right) get independent slot pools, exactly
 *      mirroring the consumer builder's `(target, side)` keying.
 *   5. **Replica no-op** — fan-out replicas own one outgoing edge each, so
 *      each lands in a size-1 bucket → offset 0 (they disambiguate via the
 *      diagonal `replicaSourceXOffset` stagger instead; producer-spread
 *      must not double-shift them).
 *   6. **Cap scaling** — `producerPortOffset` reuses the shared
 *      `slotCenteredOffset` cap behavior (outermost slots land on ±cap).
 */

import type { CipherGraph, GraphEdge, GraphNode } from "@/core/graph";
import { buildProducerPortAssignment, producerPortOffset } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Make a plain leaf node at root level. */
const node = (id: string): GraphNode => ({
  stepId: id,
  stepType: "test.node",
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

/** Make an aux edge from → to. */
const auxEdge = (from: string, to: string, auxKey = "test-key"): GraphEdge => ({
  from,
  to,
  auxKey,
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

// ─── Test 1: Single-outgoing no-op ────────────────────────────────────────

describe("producer-spreading — single-outgoing no-op", () => {
  it("returns 0 for a source whose only outgoing edge goes to one consumer", () => {
    const g = buildSyntheticGraph({
      nodes: [node("A"), node("c1")],
      edges: [auxEdge("A", "c1")],
      rootIds: ["A", "c1"],
    });
    const ports = buildProducerPortAssignment(g);
    const only = g.edges[0];
    if (!only) throw new Error("missing edge");
    expect(ports.slotOf.get(only)).toBeUndefined();
    expect(producerPortOffset(only, ports, 13)).toBe(0);
    // Single-out source is absent from bucketSizeBySource.
    expect(ports.bucketSizeBySource.has("A")).toBe(false);
  });
});

// ─── Test 2: Multi-outgoing spread (deterministic baseline) ───────────────

describe("producer-spreading — multi-outgoing spread at one source", () => {
  it("two outgoing edges at PORT_GAP=10 → offsets -5 and +5", () => {
    // No targetCoordOf → comparator falls to `edge.to` ascending (c1 < c2).
    const g = buildSyntheticGraph({
      nodes: [node("A"), node("c1"), node("c2")],
      edges: [auxEdge("A", "c1"), auxEdge("A", "c2")],
      rootIds: ["A", "c1", "c2"],
    });
    const ports = buildProducerPortAssignment(g);
    const [e1, e2] = g.edges;
    if (!e1 || !e2) throw new Error("missing edges");
    expect(ports.bucketSizeBySource.get("A")).toBe(2);
    expect(producerPortOffset(e1, ports, 10)).toBe(-5);
    expect(producerPortOffset(e2, ports, 10)).toBe(+5);
  });

  it("three outgoing edges at PORT_GAP=10 → offsets -10, 0, +10", () => {
    const g = buildSyntheticGraph({
      nodes: [node("A"), node("c1"), node("c2"), node("c3")],
      edges: [auxEdge("A", "c1"), auxEdge("A", "c2"), auxEdge("A", "c3")],
      rootIds: ["A", "c1", "c2", "c3"],
    });
    const ports = buildProducerPortAssignment(g);
    const [e1, e2, e3] = g.edges;
    if (!e1 || !e2 || !e3) throw new Error("missing edges");
    expect(producerPortOffset(e1, ports, 10)).toBe(-10);
    expect(producerPortOffset(e2, ports, 10)).toBe(0);
    expect(producerPortOffset(e3, ports, 10)).toBe(+10);
  });
});

// ─── Test 3: Target-ordered slots ─────────────────────────────────────────

describe("producer-spreading — slots follow target position (no crossover)", () => {
  it("orders a bottom-exit fan-out by target centre-X, not insertion order", () => {
    // Source A fans to t1, t2, t3 — all BELOW A (vertical exit → bottom
    // edge, slots along X). Targets sit at x = 300, 100, 200 respectively,
    // declared out of order. The slot order must follow target X
    // (t2 @100 → slot 0, t3 @200 → slot 1, t1 @300 → slot 2) so the tails
    // leave left-to-right matching where they're going.
    const g = buildSyntheticGraph({
      nodes: [node("A"), node("t1"), node("t2"), node("t3")],
      edges: [auxEdge("A", "t1"), auxEdge("A", "t2"), auxEdge("A", "t3")],
      rootIds: ["A", "t1", "t2", "t3"],
    });
    const targetX: Record<string, number> = { t1: 300, t2: 100, t3: 200 };
    const targetCoordOf = (e: GraphEdge): number | undefined => targetX[e.to];
    const sideOf = (): "bottom" => "bottom";
    const ports = buildProducerPortAssignment(g, targetCoordOf, sideOf);
    const [eT1, eT2, eT3] = g.edges;
    if (!eT1 || !eT2 || !eT3) throw new Error("missing edges");
    // t2 leftmost → slot 0 → -10; t3 → slot 1 → 0; t1 rightmost → slot 2 → +10.
    expect(producerPortOffset(eT2, ports, 10)).toBe(-10);
    expect(producerPortOffset(eT3, ports, 10)).toBe(0);
    expect(producerPortOffset(eT1, ports, 10)).toBe(+10);
  });
});

// ─── Test 4: Side bucketing ───────────────────────────────────────────────

describe("producer-spreading — independent slot pools per exit side", () => {
  it("a source exiting 2 edges bottom + 1 edge right keeps the right edge centred", () => {
    // Buckets: (A,bottom) = {b1, b2}; (A,right) = {r1}. The two bottom
    // tails spread ±5; the lone right tail stays centred (size-1 bucket).
    const g = buildSyntheticGraph({
      nodes: [node("A"), node("b1"), node("b2"), node("r1")],
      edges: [auxEdge("A", "b1"), auxEdge("A", "b2"), auxEdge("A", "r1")],
      rootIds: ["A", "b1", "b2", "r1"],
    });
    const sideMap: Record<string, "bottom" | "right"> = { b1: "bottom", b2: "bottom", r1: "right" };
    const sideOf = (e: GraphEdge): "bottom" | "right" | undefined => sideMap[e.to];
    const ports = buildProducerPortAssignment(g, undefined, sideOf);
    const [eB1, eB2, eR1] = g.edges;
    if (!eB1 || !eB2 || !eR1) throw new Error("missing edges");
    // bucketSizeBySource is side-agnostic: A has 3 outgoing total.
    expect(ports.bucketSizeBySource.get("A")).toBe(3);
    // Two bottom tails spread; right tail centred.
    expect(producerPortOffset(eB1, ports, 10)).toBe(-5);
    expect(producerPortOffset(eB2, ports, 10)).toBe(+5);
    expect(producerPortOffset(eR1, ports, 10)).toBe(0);
  });
});

// ─── Test 5: Replica no-op ────────────────────────────────────────────────

describe("producer-spreading — fan-out replicas stay centred (no double-shift)", () => {
  it("returns 0 for every replica edge (each replica owns one outgoing edge)", () => {
    // Three replicas of `src`, each with a single outgoing edge. Bucketing
    // by raw `edge.from` puts each in its own size-1 bucket → offset 0.
    // (Replicas disambiguate via replicaSourceXOffset's diagonal stagger.)
    const g = buildSyntheticGraph({
      nodes: [
        node("c1"),
        node("c2"),
        node("c3"),
        replicaNode("src->c1", "src"),
        replicaNode("src->c2", "src"),
        replicaNode("src->c3", "src"),
      ],
      edges: [auxEdge("src->c1", "c1"), auxEdge("src->c2", "c2"), auxEdge("src->c3", "c3")],
      rootIds: ["src->c1", "c1", "src->c2", "c2", "src->c3", "c3"],
    });
    const ports = buildProducerPortAssignment(g);
    for (const edge of g.edges) {
      expect(producerPortOffset(edge, ports, 13)).toBe(0);
    }
    // No source id has >1 outgoing edge → bucketSizeBySource is empty.
    expect(ports.bucketSizeBySource.size).toBe(0);
  });
});

// ─── Test 6: Cap scaling ──────────────────────────────────────────────────

describe("producer-spreading — cap scales the gap so slots stay within ±cap", () => {
  it("8 outgoing edges with natural extent 35 collapse onto a ±16 window", () => {
    // 8 edges, portGap 10 → natural extent ((8-1)/2)*10 = 35. With cap 16
    // the effective gap shrinks to 32/7 ≈ 4.571 so slot 0 → -16 and slot 7
    // → +16 (mirrors the SHA-256 final.assemble clamp behavior, here on the
    // producer side). targetCoordOf orders the slots t0..t7 by index.
    const consumers = Array.from({ length: 8 }, (_v, i) => node(`t${i}`));
    const edges = consumers.map((c) => auxEdge("A", c.stepId));
    const g = buildSyntheticGraph({
      nodes: [node("A"), ...consumers],
      edges,
      rootIds: ["A", ...consumers.map((c) => c.stepId)],
    });
    const order: Record<string, number> = Object.fromEntries(
      consumers.map((c, i) => [c.stepId, i]),
    );
    const targetCoordOf = (e: GraphEdge): number | undefined => order[e.to];
    const sideOf = (): "bottom" => "bottom";
    const ports = buildProducerPortAssignment(g, targetCoordOf, sideOf);
    const offsets = g.edges.map((e) => producerPortOffset(e, ports, 10, 16));
    // Every slot within the cap window.
    for (const o of offsets) {
      expect(Math.abs(o)).toBeLessThanOrEqual(16 + 1e-9);
    }
    // Outermost slots land exactly on ±16.
    expect(Math.min(...offsets)).toBeCloseTo(-16, 6);
    expect(Math.max(...offsets)).toBeCloseTo(+16, 6);
    // Monotonic in target order.
    const inTargetOrder = consumers.map((c) => {
      const e = g.edges.find((ed) => ed.to === c.stepId);
      if (!e) throw new Error("missing edge");
      return producerPortOffset(e, ports, 10, 16);
    });
    for (let i = 1; i < inTargetOrder.length; i++) {
      const prev = inTargetOrder[i - 1];
      const cur = inTargetOrder[i];
      if (prev === undefined || cur === undefined) throw new Error("offset gap");
      expect(cur).toBeGreaterThan(prev);
    }
  });
});
