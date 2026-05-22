/**
 * Phase 6 of the DES + branching primitive plan
 * (`docs/plans/des-feistel.md`).
 *
 * The plan §Phase 2 originally proposed adding a separate
 * `collapseFeistelRoundEdges` pure transform alongside `collapseGraph`
 * to handle edges touching a collapsed feistel-round. Advisor's Phase 6
 * review (2026-05-20) flagged that generic `collapseGraph` already
 * remaps any edge endpoint to its outermost collapsed-ancestor on
 * `containerPath`; this file proved (via the assertions below) that
 * generic collapse is sufficient, so the planned new transform was
 * never written.
 *
 * Concrete things pinned here:
 *
 *   - Every edge touching a R-track leaf id (round.3.expand-R etc.)
 *     remaps to `round.3` post-collapse; rejoin synthetic remaps too.
 *   - Inter-round spine still threads: round.2:rejoin → round.3 →
 *     round.4.expand-R.
 *   - Self-loops created by both endpoints remapping to round.3 are
 *     dropped by collapseGraph (the within-R-track chain).
 *   - Aux fan-out from key-schedule lands at the collapsed round.3
 *     with the right K_i (roundKey.2 for round 3 in encrypt).
 *
 * The Phase 6c task ("collapse to single round chip") therefore needs
 * NO new core code — both the edge remap (above) and the layout
 * branch (the `childIds.length === 0` short-circuit at GraphView.tsx
 * line 969, which fires before the kind === "feistel" branch I added
 * in Phase 6a) work for free. The cipher-shape-independent test in
 * `graph-view-des-feistel.test.tsx` exercises the rendering path.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { collapseGraph, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

// A real trace so the aux-edge assertions have something to bite on.
// FIPS 46-3 Appendix B test vector — same one tests/des-vectors.test.ts uses.
const desTrace = runSpec(desSpec, buildDefaultRegistry(), {
  initialState: { shape: "bytes" as const, bytes: bytesFromHex("0123456789abcdef") },
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
});

const emptyTrace = {
  frames: [],
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(8) },
  finalAux: new Map(),
};

describe("Phase 6 experiment — collapseGraph on a feistel-round (DES)", () => {
  it("remaps round.3's R-track-leaf endpoints to round.3 when round.3 is collapsed", () => {
    const raw = deriveAuxGraph(emptyTrace, desSpec);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));

    // No edge should reference any round.3 R-track leaf id post-collapse.
    const round3LeafIds = [
      "round.3.expand-R",
      "round.3.xor-K",
      "round.3.s-boxes",
      "round.3.p-permute",
    ];
    for (const leafId of round3LeafIds) {
      const offending = collapsed.edges.filter((e) => e.from === leafId || e.to === leafId);
      expect(offending.length, `Edge endpoint should have remapped from ${leafId} to round.3`).toBe(
        0,
      );
    }

    // The rejoin synthetic id sits inside round.3's containerPath
    // (per graph.ts:511) so it should also remap to round.3.
    const rejoinOffending = collapsed.edges.filter(
      (e) => e.from === "round.3:rejoin" || e.to === "round.3:rejoin",
    );
    expect(
      rejoinOffending.length,
      "Edge endpoint should have remapped from round.3:rejoin to round.3",
    ).toBe(0);
  });

  it("preserves the inter-round spine: predecessor → round.3 → round.4", () => {
    const raw = deriveAuxGraph(emptyTrace, desSpec);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));

    // What flowed into round.3.expand-R (R-track first leaf) and round.3:rejoin
    // (passthrough for empty L track) should now flow to round.3 itself.
    // What flowed out of round.3:rejoin should now flow from round.3.
    // Round 3's spine predecessor is round.2:rejoin (continuation edge);
    // its successor is the first leaf of round 4 (round.4.expand-R).
    const stateEdges = collapsed.edges.filter((e) => e.kind === "state");
    const has = (from: string, to: string): boolean =>
      stateEdges.some((e) => e.from === from && e.to === to);

    // After collapse, the spine entering round.3 from round.2's rejoin.
    expect(has("round.2:rejoin", "round.3"), "spine should enter collapsed round.3").toBe(true);
    // And the spine exiting round.3 onto round.4. UX-D candidate (b),
    // 2026-05-22 — round.4's R-track now starts with the R-bypass
    // chip (`:passthrough-1`), so the chain edge from round.3's
    // (collapsed) chip exits into the chip, not directly into expand-R.
    expect(has("round.3", "round.4:passthrough-1"), "spine should exit collapsed round.3").toBe(
      true,
    );
  });

  it("drops self-loops created by collapse (round.3.* → round.3.* edges)", () => {
    const raw = deriveAuxGraph(emptyTrace, desSpec);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));
    // No edge should be round.3 → round.3 (the within-round R-track chain
    // becomes a self-loop after both endpoints remap to round.3).
    const selfLoops = collapsed.edges.filter((e) => e.from === "round.3" && e.to === "round.3");
    expect(selfLoops.length, "self-loops should be dropped by collapseGraph").toBe(0);
  });

  it("keeps the aux fan-out of key-schedule onto round.3 (now landing at round.3 as one edge)", () => {
    // Aux edges require a real trace's frame.auxRead entries, so this
    // assertion uses the FIPS 46-3 Appendix B vector — empty trace
    // produces no aux edges at all.
    const raw = deriveAuxGraph(desTrace, desSpec);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));
    // Pre-collapse: key-schedule → round.3.xor-K carrying `roundKey.2`
    // (round 3's K_i, auxIdx 2 — round indices are 1-based, K indices are
    // 0-based for encrypt). Post-collapse: that edge should land at
    // round.3 with the same auxKey.
    const auxEdgesToRound3 = collapsed.edges.filter(
      (e) => e.to === "round.3" && e.kind === "aux" && e.from === "key-schedule",
    );
    expect(
      auxEdgesToRound3.length,
      "key-schedule should still feed round.3 with one aux edge",
    ).toBeGreaterThan(0);
    expect(
      auxEdgesToRound3.some((e) => e.auxKey === "roundKey.2"),
      "the aux key flowing into round.3 should be roundKey.2 (round 3's K_i)",
    ).toBe(true);
  });
});
