// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`.

/**
 * Offsets-hatch layout (2026-05-28 experiment, `?offsets=1`).
 *
 * The rule a member gets depends on the FLOW ORIENTATION of the context
 * it sits in:
 *
 *   - HORIZONTAL-flow context (root flow; iterate body): members
 *     alternate y up/down — even index at base, odd index one LEAF_H
 *     lower. Collapsed round chips at root therefore zig-zag, they do
 *     NOT staircase.
 *   - VERTICAL-flow context (expanded group body): members staircase
 *     right — child i shifted +LEAF_W/2 × i from the column's left
 *     edge, cumulative, on top of the normal vertical advance.
 *
 * Hatch OFF (default) layout is byte-identical to the pre-hatch path and
 * is covered by the other layout tests — we pin one OFF case here as a
 * regression guard against accidental coupling.
 */

import type { CipherGraph, ContainerNode, GraphNode } from "@/core/graph";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ────────────────────────────────────────────────────────────

const leaf = (id: string, containerPath: readonly string[] = []): GraphNode => ({
  stepId: id,
  stepType: "test.leaf",
  label: id,
  containerPath,
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

// ─── Rule: root horizontal-flow alternation ───────────────────────────────

describe("offsets-hatch — root alternation (horizontal-flow context)", () => {
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
    expect(ys[0]).toBeDefined();
    expect(ys[1]).toBe((ys[0] as number) + consts.LEAF_H);
    expect(ys[2]).toBe(ys[0]);
    expect(ys[3]).toBe((ys[0] as number) + consts.LEAF_H);
    expect(ys[4]).toBe(ys[0]);
  });

  it("collapsed root groups alternate up/down — they do NOT staircase", () => {
    const consts = layoutConstantsFor("normal");
    // Collapsed groups have empty childIds (collapseGraph clears them).
    // They render as chip-sized boxes and must zig-zag like any other
    // root member — the screenshot-1 regression this experiment fixes.
    const graph = makeGraph({
      containers: [
        groupContainer("R0", []),
        groupContainer("R1", []),
        groupContainer("R2", []),
        groupContainer("R3", []),
      ],
      rootIds: ["R0", "R1", "R2", "R3"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const r0 = boxes.get("R0");
    const r1 = boxes.get("R1");
    const r2 = boxes.get("R2");
    const r3 = boxes.get("R3");
    // y alternates (NOT a monotonic descent).
    expect((r1 as { y: number }).y).toBe((r0 as { y: number }).y + consts.LEAF_H);
    expect((r2 as { y: number }).y).toBe((r0 as { y: number }).y);
    expect((r3 as { y: number }).y).toBe((r0 as { y: number }).y + consts.LEAF_H);
    // x strictly increases left-to-right (regular horizontal flow, no
    // staircase indent reuse).
    expect((r1 as { x: number }).x).toBeGreaterThan((r0 as { x: number }).x);
    expect((r2 as { x: number }).x).toBeGreaterThan((r1 as { x: number }).x);
    expect((r3 as { x: number }).x).toBeGreaterThan((r2 as { x: number }).x);
  });
});

// ─── Rule: expanded group vertical-flow staircase ─────────────────────────

describe("offsets-hatch — group staircase (vertical-flow context)", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(true);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("staircases an expanded group's children right by LEAF_W/2 cumulatively", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["c0", "c1", "c2", "c3"];
    const graph = makeGraph({
      nodes: children.map((id) => leaf(id, ["G"])),
      containers: [groupContainer("G", children)],
      rootIds: ["G"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const xs = children.map((id) => boxes.get(id)?.x);
    const ys = children.map((id) => boxes.get(id)?.y);
    expect(xs[0]).toBeDefined();
    const step = Math.round(consts.LEAF_W / 2);
    // x grows by step per child (cumulative staircase).
    expect(xs[1]).toBe((xs[0] as number) + step);
    expect(xs[2]).toBe((xs[0] as number) + 2 * step);
    expect(xs[3]).toBe((xs[0] as number) + 3 * step);
    // y still advances downward (vertical flow preserved).
    expect(ys[1] as number).toBeGreaterThan(ys[0] as number);
    expect(ys[2] as number).toBeGreaterThan(ys[1] as number);
    expect(ys[3] as number).toBeGreaterThan(ys[2] as number);
  });

  it("grows the group box width to contain the staircase diagonal", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["c0", "c1", "c2", "c3", "c4"];
    const graph = makeGraph({
      nodes: children.map((id) => leaf(id, ["G"])),
      containers: [groupContainer("G", children)],
      rootIds: ["G"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const gBox = boxes.get("G");
    const last = boxes.get("c4");
    expect(gBox).toBeDefined();
    expect(last).toBeDefined();
    const gRight = (gBox as { x: number; w: number }).x + (gBox as { w: number }).w;
    const lastRight = (last as { x: number; w: number }).x + (last as { w: number }).w;
    expect(gRight).toBeGreaterThanOrEqual(lastRight);
  });
});

// ─── Rule: expanded iterate horizontal-flow alternation ───────────────────

describe("offsets-hatch — iterate alternation (horizontal-flow context)", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(true);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("alternates an iterate's children up/down by LEAF_H", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["m0", "m1", "m2", "m3"];
    const graph = makeGraph({
      nodes: children.map((id) => leaf(id, ["IT"])),
      containers: [iterateContainer("IT", children)],
      rootIds: ["IT"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const xs = children.map((id) => boxes.get(id)?.x);
    const ys = children.map((id) => boxes.get(id)?.y);
    expect(ys[0]).toBeDefined();
    // y alternates: even index at base, odd index +LEAF_H.
    expect(ys[1]).toBe((ys[0] as number) + consts.LEAF_H);
    expect(ys[2]).toBe(ys[0]);
    expect(ys[3]).toBe((ys[0] as number) + consts.LEAF_H);
    // x advances left-to-right (horizontal flow preserved).
    expect(xs[1] as number).toBeGreaterThan(xs[0] as number);
    expect(xs[2] as number).toBeGreaterThan(xs[1] as number);
    expect(xs[3] as number).toBeGreaterThan(xs[2] as number);
  });

  it("grows the iterate box height to contain the lowered odd rows", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["m0", "m1"];
    const graph = makeGraph({
      nodes: children.map((id) => leaf(id, ["IT"])),
      containers: [iterateContainer("IT", children)],
      rootIds: ["IT"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const itBox = boxes.get("IT");
    const m1 = boxes.get("m1");
    expect(itBox).toBeDefined();
    expect(m1).toBeDefined();
    const itBottom = (itBox as { y: number; h: number }).y + (itBox as { h: number }).h;
    const m1Bottom = (m1 as { y: number; h: number }).y + (m1 as { h: number }).h;
    expect(itBottom).toBeGreaterThanOrEqual(m1Bottom);
  });
});

// ─── OFF (default) regression guard ───────────────────────────────────────

describe("offsets-hatch — OFF (default)", () => {
  beforeEach(() => {
    __setOffsetsEnabledForTest(false);
  });
  afterEach(() => {
    __setOffsetsEnabledForTest(null);
  });

  it("does not alternate root members when hatch is off", () => {
    const consts = layoutConstantsFor("normal");
    const graph = makeGraph({
      nodes: [leaf("L1"), leaf("L2"), leaf("L3")],
      rootIds: ["L1", "L2", "L3"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const ys = ["L1", "L2", "L3"].map((id) => boxes.get(id)?.y);
    expect(ys[1]).toBe(ys[0]);
    expect(ys[2]).toBe(ys[0]);
  });

  it("does not staircase group children when hatch is off", () => {
    const consts = layoutConstantsFor("normal");
    const children = ["c0", "c1", "c2"];
    const graph = makeGraph({
      nodes: children.map((id) => leaf(id, ["G"])),
      containers: [groupContainer("G", children)],
      rootIds: ["G"],
    });
    const { boxes } = layoutRoot(graph, emptyPinned, consts);
    const xs = children.map((id) => boxes.get(id)?.x);
    // All children share the same x (plain vertical stack).
    expect(xs[1]).toBe(xs[0]);
    expect(xs[2]).toBe(xs[0]);
  });
});
