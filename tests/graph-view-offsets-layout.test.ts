// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`.

/**
 * Offsets-hatch layout (2026-05-28 experiment).
 *
 * Pins the three rules the `?offsets=1` URL hatch applies to `layoutRoot`:
 *
 *   1. **Alternation** — non-group, non-iterate root members alternate
 *      between base y and `base + LEAF_H`. Counter resets after every
 *      iterate or run-of-groups.
 *   2. **Iterate cascade** — an iterate at root has its immediate
 *      children (block chips, or expanded body children) shifted to
 *      cascade vertically inside the container box.
 *   3. **Group staircase** — consecutive root-level groups form a
 *      down-and-right diagonal: each shifted by
 *      `(LEAF_W/2, prevGroup.h + STACK_GAP)` from the previous. After
 *      the run ends, the next non-group sibling resumes the horizontal
 *      flow with `altCounter = 0`.
 *
 * Hatch OFF (default) layout is byte-identical to the pre-hatch path and
 * is covered by `tests/graph-view-replica-placement.test.ts` and the
 * other existing layout tests — we don't re-pin that here. We do pin
 * one OFF-case as a regression guard against accidental coupling.
 */

import type { CipherGraph, ContainerNode, GraphNode } from "@/core/graph";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ────────────────────────────────────────────────────────────

const leaf = (id: string): GraphNode => ({
  stepId: id,
  stepType: "test.leaf",
  label: id,
  containerPath: [],
});

const groupContainer = (id: string, children: readonly string[]): ContainerNode => ({
  kind: "group",
  id,
  label: id,
  containerPath: [],
  childIds: children,
});

const iterateContainer = (id: string, children: readonly string[]): ContainerNode => ({
  kind: "iterate",
  id,
  label: id,
  containerPath: [],
  childIds: children,
});

const makeGraph = (parts: {
  readonly nodes?: readonly GraphNode[];
  readonly containers?: readonly ContainerNode[];
  readonly rootIds: readonly string[];
}): CipherGraph => ({
  nodes: parts.nodes ?? [],
  containers: parts.containers ?? [],
  edges: [],
  rootIds: parts.rootIds,
});

const emptyPinned = new Map<string, { x: number; y: number }>();

// ─── Tests ───────────────────────────────────────────────────────────────

describe("offsets-hatch — Rule 1 alternation (root leaves)", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(true);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("alternates root leaves' y between base and base+LEAF_H", () => {
    const consts = layoutConstantsFor("normal");
    const graph = makeGraph({
      nodes: [leaf("L1"), leaf("L2"), leaf("L3"), leaf("L4"), leaf("L5")],
      rootIds: ["L1", "L2", "L3", "L4", "L5"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const ys = ["L1", "L2", "L3", "L4", "L5"].map((id) => boxes.get(id)?.y);
    // L1 at base, L2 at base + LEAF_H, L3 at base, L4 at base + LEAF_H, L5 at base.
    expect(ys[0]).toBeDefined();
    expect(ys[1]).toBe((ys[0] as number) + consts.LEAF_H);
    expect(ys[2]).toBe(ys[0]);
    expect(ys[3]).toBe((ys[0] as number) + consts.LEAF_H);
    expect(ys[4]).toBe(ys[0]);
  });

  it("alternation counter resets after an iterate", () => {
    const consts = layoutConstantsFor("normal");
    // L1 (base), L2 (+H), iterate (base — counts but resets after),
    // L3 should be at BASE (counter reset), L4 at +H.
    const graph = makeGraph({
      nodes: [leaf("L1"), leaf("L2"), leaf("L3"), leaf("L4"), leaf("body")],
      containers: [iterateContainer("IT", ["body"])],
      rootIds: ["L1", "L2", "IT", "L3", "L4"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const yL1 = boxes.get("L1")?.y;
    const yL2 = boxes.get("L2")?.y;
    const yL3 = boxes.get("L3")?.y;
    const yL4 = boxes.get("L4")?.y;
    expect(yL1).toBeDefined();
    expect(yL2).toBe((yL1 as number) + consts.LEAF_H);
    // Post-iterate reset: L3 at base again.
    expect(yL3).toBe(yL1);
    expect(yL4).toBe((yL1 as number) + consts.LEAF_H);
  });
});

describe("offsets-hatch — Rule 2 iterate cascade", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(true);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("cascades iterate immediate children down by LEAF_H + STACK_GAP", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["b0", "b1", "b2", "b3"];
    const graph = makeGraph({
      nodes: children.map((id) => ({
        stepId: id,
        stepType: "block-chip",
        label: id,
        containerPath: ["IT"],
      })),
      containers: [iterateContainer("IT", children)],
      rootIds: ["IT"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const ys = children.map((id) => boxes.get(id)?.y);
    expect(ys[0]).toBeDefined();
    const step = consts.LEAF_H + consts.STACK_GAP;
    expect(ys[1]).toBe((ys[0] as number) + step);
    expect(ys[2]).toBe((ys[0] as number) + 2 * step);
    expect(ys[3]).toBe((ys[0] as number) + 3 * step);
  });

  it("grows the iterate container box H to contain the cascaded children", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["b0", "b1", "b2"];
    const graph = makeGraph({
      nodes: children.map((id) => ({
        stepId: id,
        stepType: "block-chip",
        label: id,
        containerPath: ["IT"],
      })),
      containers: [iterateContainer("IT", children)],
      rootIds: ["IT"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const itBox = boxes.get("IT");
    const lastChild = boxes.get("b2");
    expect(itBox).toBeDefined();
    expect(lastChild).toBeDefined();
    // Iterate's bottom must enclose the last cascaded child.
    const itBottom = (itBox as { y: number; h: number }).y + (itBox as { h: number }).h;
    const childBottom = (lastChild as { y: number; h: number }).y + (lastChild as { h: number }).h;
    expect(itBottom).toBeGreaterThanOrEqual(childBottom);
  });
});

describe("offsets-hatch — Rule 3 group staircase", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(true);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("descends consecutive root groups by (LEAF_W/2, prevH + STACK_GAP)", () => {
    const consts = layoutConstantsFor("normal");
    // Three group containers each with one leaf inside (so they have
    // non-zero h). Default-collapsed-at-render machinery isn't invoked
    // here — the test exercises the staircase rule for any kind="group".
    const graph = makeGraph({
      nodes: [leaf("body1"), leaf("body2"), leaf("body3")],
      containers: [
        groupContainer("G1", ["body1"]),
        groupContainer("G2", ["body2"]),
        groupContainer("G3", ["body3"]),
      ],
      rootIds: ["G1", "G2", "G3"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const g1 = boxes.get("G1");
    const g2 = boxes.get("G2");
    const g3 = boxes.get("G3");
    expect(g1).toBeDefined();
    expect(g2).toBeDefined();
    expect(g3).toBeDefined();
    const stepX = Math.round(consts.LEAF_W / 2);
    expect((g2 as { x: number }).x).toBe((g1 as { x: number }).x + stepX);
    expect((g3 as { x: number }).x).toBe((g2 as { x: number }).x + stepX);
    // Vertical descent: each group below the previous one's bottom + STACK_GAP.
    const g1Bottom = (g1 as { y: number; h: number }).y + (g1 as { h: number }).h;
    expect((g2 as { y: number }).y).toBe(g1Bottom + consts.STACK_GAP);
    const g2Bottom = (g2 as { y: number; h: number }).y + (g2 as { h: number }).h;
    expect((g3 as { y: number }).y).toBe(g2Bottom + consts.STACK_GAP);
  });

  it("resumes horizontal flow at base y with reset counter after group run", () => {
    const consts = layoutConstantsFor("normal");
    const graph = makeGraph({
      nodes: [leaf("body1"), leaf("body2"), leaf("post1"), leaf("post2"), leaf("post3")],
      containers: [groupContainer("G1", ["body1"]), groupContainer("G2", ["body2"])],
      rootIds: ["G1", "G2", "post1", "post2", "post3"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const post1 = boxes.get("post1");
    const post2 = boxes.get("post2");
    const post3 = boxes.get("post3");
    expect(post1).toBeDefined();
    expect(post2).toBeDefined();
    expect(post3).toBeDefined();
    // post1 starts a fresh alternation: base y; post2 at +LEAF_H; post3 back at base.
    expect((post2 as { y: number }).y).toBe((post1 as { y: number }).y + consts.LEAF_H);
    expect((post3 as { y: number }).y).toBe((post1 as { y: number }).y);
    // post1's x starts AFTER the last group's right edge.
    const g2 = boxes.get("G2");
    expect(g2).toBeDefined();
    const g2Right = (g2 as { x: number; w: number }).x + (g2 as { w: number }).w;
    expect((post1 as { x: number }).x).toBeGreaterThanOrEqual(g2Right);
  });
});

describe("offsets-hatch — OFF (default) regression guard", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(false);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("does not alternate when hatch is off", () => {
    const consts = layoutConstantsFor("normal");
    const graph = makeGraph({
      nodes: [leaf("L1"), leaf("L2"), leaf("L3")],
      rootIds: ["L1", "L2", "L3"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const ys = ["L1", "L2", "L3"].map((id) => boxes.get(id)?.y);
    // All three at the SAME y — no alternation.
    expect(ys[1]).toBe(ys[0]);
    expect(ys[2]).toBe(ys[0]);
  });
});
