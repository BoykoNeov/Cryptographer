// @vitest-environment jsdom

/**
 * Phase 6b-iii of the DES + branching primitive plan
 * (`docs/plans/des-feistel.md`).
 *
 * Pins the `rejoinSwapSourceXSign` helper that drives diagonal
 * X-crossings between Feistel rounds. The helper is pure (in,
 * containerNodesById, edge → -1 | 0 | 1) so we test it directly
 * with hand-rolled fixtures rather than building a full graph.
 *
 * What the X visualises pedagogically: `L_{n+1} = R_n` and
 * `R_{n+1} = L_n ⊕ F(R_n, K_n)`. The arrow from `roundN:rejoin` to
 * the next round's L-column passthrough EXITS from the rejoin's
 * RIGHT side; the arrow to the next round's R-column first leaf
 * EXITS from the rejoin's LEFT side. Visually, the two arrows
 * cross. For `feistel-no-swap` (DES round 16) the arrows go
 * straight — there's nothing to encode.
 */

import type { ContainerNode, GraphEdge, GraphNode } from "@/core/graph";
import { rejoinSwapSourceXSign } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

const STATE_EDGE = (from: string, to: string): GraphEdge => ({
  from,
  to,
  auxKey: "state",
  kind: "state",
});

const buildFixture = (combineKind: string) => {
  const round1: ContainerNode = {
    kind: "feistel",
    id: "round.1",
    label: "Round 1",
    containerPath: [],
    childIds: ["round.1:passthrough-0", "round.1.expand-R", "round.1.xor-K", "round.1:rejoin"],
    feistelTracks: [["round.1:passthrough-0"], ["round.1.expand-R", "round.1.xor-K"]],
    feistelTrackNames: ["L", "R"],
    feistelCombineKind: combineKind,
  };
  const round2: ContainerNode = {
    kind: "feistel",
    id: "round.2",
    label: "Round 2",
    containerPath: [],
    childIds: ["round.2:passthrough-0", "round.2.expand-R", "round.2.xor-K", "round.2:rejoin"],
    feistelTracks: [["round.2:passthrough-0"], ["round.2.expand-R", "round.2.xor-K"]],
    feistelTrackNames: ["L", "R"],
    feistelCombineKind: combineKind,
  };
  const containersById = new Map<string, ContainerNode>([
    ["round.1", round1],
    ["round.2", round2],
  ]);
  const rejoinNode1: GraphNode = {
    stepId: "round.1:rejoin",
    stepType: "__rejoin__",
    label: "round.1:rejoin",
    containerPath: ["round.1"],
    synthetic: "rejoin",
  };
  const passthrough2: GraphNode = {
    stepId: "round.2:passthrough-0",
    stepType: "__passthrough__",
    label: "round.2:passthrough-0",
    containerPath: ["round.2"],
    synthetic: "passthrough",
  };
  const expandR2: GraphNode = {
    stepId: "round.2.expand-R",
    stepType: "des.expand-r@1",
    label: "round.2.expand-R",
    containerPath: ["round.2"],
  };
  const finalLeaf: GraphNode = {
    stepId: "final-permutation",
    stepType: "des.final-permutation@1",
    label: "final-permutation",
    containerPath: [],
  };
  const preLeaf: GraphNode = {
    stepId: "initial-permutation",
    stepType: "des.initial-permutation@1",
    label: "initial-permutation",
    containerPath: [],
  };
  const nodesById = new Map<string, GraphNode>([
    [rejoinNode1.stepId, rejoinNode1],
    [passthrough2.stepId, passthrough2],
    [expandR2.stepId, expandR2],
    [finalLeaf.stepId, finalLeaf],
    [preLeaf.stepId, preLeaf],
  ]);
  return { nodesById, containersById };
};

describe("rejoinSwapSourceXSign — Feistel X-crossing routing (Phase 6b-iii)", () => {
  it("feistel-standard + L-target: returns +1 (source from rejoin's RIGHT)", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    const edge = STATE_EDGE("round.1:rejoin", "round.2:passthrough-0");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(1);
  });

  it("feistel-standard + R-target: returns -1 (source from rejoin's LEFT)", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    const edge = STATE_EDGE("round.1:rejoin", "round.2.expand-R");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(-1);
  });

  it("feistel-no-swap: returns 0 (no X — parallel arrows encode no-swap)", () => {
    const { nodesById, containersById } = buildFixture("feistel-no-swap");
    const edgeL = STATE_EDGE("round.1:rejoin", "round.2:passthrough-0");
    const edgeR = STATE_EDGE("round.1:rejoin", "round.2.expand-R");
    expect(rejoinSwapSourceXSign(edgeL, nodesById, containersById)).toBe(0);
    expect(rejoinSwapSourceXSign(edgeR, nodesById, containersById)).toBe(0);
  });

  it("non-rejoin source: returns 0", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    const edge = STATE_EDGE("initial-permutation", "round.2.expand-R");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(0);
  });

  it("rejoin source + target outside a feistel-round: returns 0 (e.g. round 16 → final-permutation)", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    const edge = STATE_EDGE("round.1:rejoin", "final-permutation");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(0);
  });

  it("feistel-add-into-left: returns 0 (not standardised visually; no shipped cipher exercises it)", () => {
    const { nodesById, containersById } = buildFixture("feistel-add-into-left");
    const edge = STATE_EDGE("round.1:rejoin", "round.2:passthrough-0");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(0);
  });

  // Phase 6e finding A — when a feistel-round is collapsed, `collapseGraph`
  // clears its child ids and remaps outgoing edges to start from the
  // container id instead of the (now-hidden) rejoin synthetic. The same
  // X-crossing pedagogy still applies because the eye reads two outgoing
  // edges to the next round's two columns — they should still cross.
  it("collapsed feistel-standard source + L-target: returns +1 (X-crossing applies through collapsed source)", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    // Edge `from` is the round container id itself (round.1), not the
    // rejoin synthetic — matches `collapseGraph`'s remap when round.1 is
    // collapsed.
    const edge = STATE_EDGE("round.1", "round.2:passthrough-0");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(1);
  });

  it("collapsed feistel-standard source + R-target: returns -1", () => {
    const { nodesById, containersById } = buildFixture("feistel-standard");
    const edge = STATE_EDGE("round.1", "round.2.expand-R");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(-1);
  });

  it("collapsed feistel-no-swap source: returns 0 (only the swap-bearing kind triggers X)", () => {
    const { nodesById, containersById } = buildFixture("feistel-no-swap");
    const edge = STATE_EDGE("round.1", "round.2:passthrough-0");
    expect(rejoinSwapSourceXSign(edge, nodesById, containersById)).toBe(0);
  });
});
