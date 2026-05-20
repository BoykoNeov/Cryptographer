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
      expect(round?.feistelTracks?.[1], `round.${r} R track`).toEqual([
        `round.${r}.expand-R`,
        `round.${r}.xor-K`,
        `round.${r}.s-boxes`,
        `round.${r}.p-permute`,
      ]);
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
});
