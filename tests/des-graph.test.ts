/**
 * Phase 3 of the DES + branching primitive plan: graph-derivation smoke
 * for the full DES spec. The toy fixture in `feistel-graph.test.ts`
 * exercises the container *kind* but not (a) 16 feistel-round containers
 * sharing a parent group, (b) consumer-side aux fanning of `key-schedule`
 * across 16 `xor-with-K` leaves spread across track bodies, or (c) the
 * F-internals chain (4 leaves per round in the R track). This file pins
 * those shapes WITHOUT recomputing the whole graph contract — Phase 6's
 * manual smoke pass is the comprehensive check; this is the structural
 * sanity that catches a derivation regression cheaply.
 */

import { desSpec } from "@/ciphers/des";
import { deriveAuxGraph } from "@/core/graph";
import { describe, expect, it } from "vitest";

const emptyTrace = {
  frames: [],
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(8) },
  finalAux: new Map(),
};

describe("DES graph derivation — structural sanity", () => {
  it("emits 16 feistel-kind containers (one per round)", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    const feistelContainers = graph.containers.filter((c) => c.kind === "feistel");
    expect(feistelContainers.length).toBe(16);
    for (let r = 1; r <= 16; r++) {
      expect(feistelContainers.find((c) => c.id === `round.${r}`)).toBeDefined();
    }
  });

  it("each round's R-track carries the 4 F-internal leaves; L-track holds a synthetic passthrough chip (Phase 6b-ii)", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    for (let r = 1; r <= 16; r++) {
      const round = graph.containers.find((c) => c.id === `round.${r}`);
      // Phase 6b-ii — empty L tracks now carry a per-track
      // passthrough synthetic so the L column reads as
      // "passes through unchanged" instead of empty space.
      // Naming via `feistelPassthroughId`:
      // `${roundId}:passthrough-${trackIdx}` (track 0 == L).
      expect(round?.feistelTracks?.[0], `round.${r} L track`).toEqual([`round.${r}:passthrough-0`]);
      // UX-D candidate (b), 2026-05-22 — rounds 1..15 (`feistel-standard`)
      // prepend a passthrough chip at the head of the R-track that
      // represents R_in flowing unchanged to the rejoin alongside the
      // F-stack. Round 16 (`feistel-no-swap`) keeps the legacy 4-leaf
      // shape since the bypass narrative doesn't apply.
      const expectedRTrack =
        r === 16
          ? [
              `round.${r}.expand-R`,
              `round.${r}.xor-K`,
              `round.${r}.s-boxes`,
              `round.${r}.p-permute`,
            ]
          : [
              `round.${r}:passthrough-1`,
              `round.${r}.expand-R`,
              `round.${r}.xor-K`,
              `round.${r}.s-boxes`,
              `round.${r}.p-permute`,
            ];
      expect(round?.feistelTracks?.[1], `round.${r} R track`).toEqual(expectedRTrack);
    }
  });

  it("synthesizes one passthrough node per empty L track (Phase 6b-ii)", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    for (let r = 1; r <= 16; r++) {
      const pt = graph.nodes.find((n) => n.stepId === `round.${r}:passthrough-0`);
      expect(pt, `round.${r}:passthrough-0`).toBeDefined();
      expect(pt?.synthetic).toBe("passthrough");
      expect(pt?.containerPath).toEqual(["rounds", `round.${r}`]);
    }
  });

  it("round 16 uses combineKind 'feistel-no-swap'; rounds 1..15 use 'feistel-standard'", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    for (let r = 1; r <= 15; r++) {
      expect(graph.containers.find((c) => c.id === `round.${r}`)?.feistelCombineKind).toBe(
        "feistel-standard",
      );
    }
    expect(graph.containers.find((c) => c.id === "round.16")?.feistelCombineKind).toBe(
      "feistel-no-swap",
    );
  });

  it("synthesizes one rejoin node per round", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    for (let r = 1; r <= 16; r++) {
      const rejoin = graph.nodes.find((n) => n.stepId === `round.${r}:rejoin`);
      expect(rejoin, `round.${r}:rejoin`).toBeDefined();
      expect(rejoin?.synthetic).toBe("rejoin");
    }
  });

  it("does not throw on the full 16-round DES spec", () => {
    // Cheap blanket assertion: any derivation regression that produces
    // a malformed graph (orphaned container, missing edge endpoint,
    // throw in port-spread) lands here.
    expect(() => deriveAuxGraph(emptyTrace, desSpec)).not.toThrow();
  });

  // UX-D candidate (b), 2026-05-22 — rounds 1..15 (`feistel-standard`)
  // get a synthetic R-bypass passthrough chip (`:passthrough-1`) sitting
  // at the head of the R-column. The chip's incoming arrow is from the
  // round's predecessor, outgoing arrow is directly to `:rejoin`,
  // running in parallel with the F-stack. Together with the existing
  // L-passthrough this makes both halves of the Feistel swap visible:
  // L_in → :rejoin via the L chip, R_in → :rejoin via the R chip,
  // F(R_in, K_i) → :rejoin via the F-stack. Round 16 (`feistel-no-swap`)
  // skips the R chip — the bypass narrative doesn't apply there.
  //
  // Candidate (a) — synthesized arrow expand-R → rejoin — was tried
  // first (commit `83502de`) and reverted because the arrow visually
  // suggested expand-R PRODUCED R_in. expand-R consumes R_in and
  // produces E(R); the chip moves the arrow's origin off expand-R.
  describe("UX-D candidate (b) — R-bypass passthrough chip", () => {
    it("synthesizes a passthrough chip at the head of the R-track for each of rounds 1..15", () => {
      const graph = deriveAuxGraph(emptyTrace, desSpec);
      for (let r = 1; r <= 15; r++) {
        const chip = graph.nodes.find((n) => n.stepId === `round.${r}:passthrough-1`);
        expect(chip, `round.${r}:passthrough-1`).toBeDefined();
        expect(chip?.synthetic).toBe("passthrough");
        expect(chip?.containerPath).toEqual(["rounds", `round.${r}`]);
      }
    });

    it("does NOT synthesize an R-bypass chip for round 16 (feistel-no-swap)", () => {
      const graph = deriveAuxGraph(emptyTrace, desSpec);
      const chip = graph.nodes.find((n) => n.stepId === "round.16:passthrough-1");
      expect(chip, "round.16 must not carry the R-bypass chip").toBeUndefined();
    });

    it("routes predecessor → chip → rejoin around the F-stack for each of rounds 1..15", () => {
      const graph = deriveAuxGraph(emptyTrace, desSpec);
      const stateEdges = graph.edges.filter((e) => e.kind === "state");
      const has = (from: string, to: string): boolean =>
        stateEdges.some((e) => e.from === from && e.to === to && e.auxKey === "state");
      for (let r = 1; r <= 15; r++) {
        // The predecessor is whatever leaf sits before the round in
        // the parent spine — for round 1 that's `initial-permutation`,
        // for round k>1 that's `round.k-1:rejoin`. Outgoing edge is
        // always to the round's chip (which is the chain head now).
        const predecessor = r === 1 ? "initial-permutation" : `round.${r - 1}:rejoin`;
        expect(
          has(predecessor, `round.${r}:passthrough-1`),
          `predecessor → round.${r}:passthrough-1`,
        ).toBe(true);
        expect(
          has(`round.${r}:passthrough-1`, `round.${r}:rejoin`),
          `round.${r}:passthrough-1 → rejoin`,
        ).toBe(true);
        // Chip is now upstream of expand-R, so the chain edge
        // chip → expand-R must exist too.
        expect(
          has(`round.${r}:passthrough-1`, `round.${r}.expand-R`),
          `round.${r}:passthrough-1 → expand-R`,
        ).toBe(true);
      }
    });

    it("keeps the existing F-output edge (p-permute → rejoin) intact alongside the chip", () => {
      // Sanity: adding the R-bypass chip and its edges must NOT
      // replace or suppress the pre-existing fan-out edge from the
      // R-track's LAST leaf. Both arrows should reach rejoin —
      // chip carries R_in, fan-out carries F(R_in, K_i).
      const graph = deriveAuxGraph(emptyTrace, desSpec);
      const fanOut = graph.edges.find(
        (e) => e.from === "round.1.p-permute" && e.to === "round.1:rejoin" && e.auxKey === "state",
      );
      expect(fanOut, "round.1 F-output edge").toBeDefined();
    });

    it("does NOT route predecessor → R-bypass-chip for round 16 (feistel-no-swap)", () => {
      const graph = deriveAuxGraph(emptyTrace, desSpec);
      // The chip doesn't exist for round 16, so neither edge should.
      const incoming = graph.edges.find((e) => e.to === "round.16:passthrough-1");
      const outgoing = graph.edges.find((e) => e.from === "round.16:passthrough-1");
      expect(
        incoming,
        "round.16 must not have an incoming edge to a non-existent chip",
      ).toBeUndefined();
      expect(
        outgoing,
        "round.16 must not have an outgoing edge from a non-existent chip",
      ).toBeUndefined();
    });
  });
});
