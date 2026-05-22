/**
 * Phase 2 of the DES + branching primitive plan (`docs/plans/des-feistel.md`).
 * Pins graph-derivation behavior for the new `feistel-round` container kind:
 *
 *   - ContainerNode with `kind: "feistel"` and per-track child id lists.
 *   - Rejoin synthetic node (`{roundId}:rejoin`, `synthetic: "rejoin"`).
 *   - State edges: fan-in (predecessor → first leaf of each non-empty
 *     track), passthrough (predecessor → rejoin for empty tracks),
 *     fan-out (track's last leaf → rejoin), continuation (rejoin →
 *     successor).
 *   - No across-track state edges.
 *   - No direct predecessor → round-id edge.
 *
 * The fixtures live alongside the test — keeping the toy spec used in
 * `feistel-primitive.test.ts` for KAT pinning, but adding spec variants
 * here to exercise fan-in / fan-out under different shapes.
 */

import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { deriveAuxGraph } from "@/core/graph";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = {
  frames: [],
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(4) },
  finalAux: new Map(),
};

describe("feistel-round graph derivation", () => {
  it("produces a feistel-kind ContainerNode with per-track child id lists", () => {
    const graph = deriveAuxGraph(emptyTrace, FEISTEL_TOY_SPEC);
    const round1 = graph.containers.find((c) => c.id === "round.1");
    expect(round1).toBeDefined();
    expect(round1?.kind).toBe("feistel");
    // Phase 6b-ii — empty L track now carries a per-track passthrough
    // synthetic so the L column reads as "carries L_in through
    // unchanged" instead of empty space. Named via
    // `feistelPassthroughId(roundId, trackIdx)`.
    //
    // UX-D candidate (b), 2026-05-22 — populated R-track in a
    // `feistel-standard` round (this fixture qualifies) prepends an
    // R-bypass passthrough chip at the head of the R-column. The chip
    // shares the empty-track naming convention (`:passthrough-1`)
    // because it represents the same semantic — R_in carried unchanged
    // to rejoin — and `lookupPassthroughBytes` resolves both via the
    // same regex.
    expect(round1?.feistelTracks).toEqual([
      ["round.1:passthrough-0"],
      ["round.1:passthrough-1", "round.1.add-k"],
    ]);
    expect(round1?.feistelTrackNames).toEqual(["L", "R"]);
    expect(round1?.feistelCombineKind).toBe("feistel-standard");
  });

  it("synthesizes one rejoin node per round, inside the round's containerPath", () => {
    const graph = deriveAuxGraph(emptyTrace, FEISTEL_TOY_SPEC);
    const r1 = graph.nodes.find((n) => n.stepId === "round.1:rejoin");
    expect(r1).toBeDefined();
    expect(r1?.synthetic).toBe("rejoin");
    expect(r1?.stepType).toBe("__rejoin__");
    expect(r1?.containerPath).toEqual(["round.1"]);
    const r2 = graph.nodes.find((n) => n.stepId === "round.2:rejoin");
    expect(r2).toBeDefined();
    expect(r2?.containerPath).toEqual(["round.2"]);
  });

  it("emits NO direct predecessor → round-id state edges", () => {
    // The toy's round.1 has no in-scope predecessor (it IS the first
    // sibling), but the spec below adds one. Verify both: in the toy,
    // the only edges touching round.1 are fan-in / fan-out / continuation;
    // round.1 ITSELF is never the endpoint of any edge.
    const graph = deriveAuxGraph(emptyTrace, FEISTEL_TOY_SPEC);
    for (const e of graph.edges) {
      expect(e.from).not.toBe("round.1");
      expect(e.to).not.toBe("round.1");
      expect(e.from).not.toBe("round.2");
      expect(e.to).not.toBe("round.2");
    }
  });

  it("fan-in: predecessor edges to R's first leaf AND through the L passthrough chip to rejoin", () => {
    // Build a spec where the round has a CONCRETE predecessor in the
    // parent chain so we can pin the fan-in shape. Layout: a single
    // pre-leaf, then the round, then a single post-leaf.
    const toyRound = FEISTEL_TOY_SPEC.steps[0];
    if (!toyRound) throw new Error("FEISTEL_TOY_SPEC has no round.1");
    const wrapped: CipherSpec = {
      id: "feistel-toy-wrapped@1",
      name: "Toy Feistel with neighbors",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 2 } },
      steps: [
        { kind: "step", id: "pre", type: "feistel.toy-add-k@1", params: { k: 0 } },
        // Re-use the toy's round.1 verbatim.
        toyRound,
        { kind: "step", id: "post", type: "feistel.toy-add-k@1", params: { k: 0 } },
      ],
    };
    const graph = deriveAuxGraph(emptyTrace, wrapped);
    const stateEdges = graph.edges.filter((e) => e.kind === "state");
    const has = (from: string, to: string): boolean =>
      stateEdges.some((e) => e.from === from && e.to === to);
    // UX-D candidate (b), 2026-05-22 — `feistel-standard` rounds with
    // populated R-tracks splice an R-bypass passthrough chip at the
    // head of the R-column. Fan-in is now predecessor → chip; chip's
    // outgoing edges are chip → trackFirst AND chip → rejoin.
    expect(has("pre", "round.1:passthrough-1")).toBe(true);
    expect(has("round.1:passthrough-1", "round.1.add-k")).toBe(true);
    expect(has("round.1:passthrough-1", "round.1:rejoin")).toBe(true);
    // The pre-candidate-(b) fan-in `predecessor → trackFirst` is now
    // routed through the chip; the direct edge should be gone.
    expect(has("pre", "round.1.add-k")).toBe(false);
    // Phase 6b-ii — empty L track is still routed through its own
    // synthetic passthrough chip (`{roundId}:passthrough-{trackIdx}`).
    expect(has("pre", "round.1:passthrough-0")).toBe(true);
    expect(has("round.1:passthrough-0", "round.1:rejoin")).toBe(true);
    // The direct predecessor → rejoin shortcut from Phase 6a is gone:
    expect(has("pre", "round.1:rejoin")).toBe(false);
    // Fan-out from R-track last leaf to rejoin:
    expect(has("round.1.add-k", "round.1:rejoin")).toBe(true);
    // Continuation from rejoin onto the successor:
    expect(has("round.1:rejoin", "post")).toBe(true);
    // NO direct predecessor → successor bridging edge (the spine
    // genuinely passes through the round; never skips it).
    expect(has("pre", "post")).toBe(false);
  });

  it("within-track DFS still emits state edges between consecutive leaves", () => {
    // Synthesize a single round with a 3-step R track to verify within-
    // track chaining.
    const richTrack: CipherSpec = {
      id: "feistel-rich-r@1",
      name: "Toy Feistel — 3 R steps",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 2 } },
      steps: [
        {
          kind: "feistel-round",
          id: "round.rich",
          tracks: [
            { name: "L", inputBytes: [0, 1], children: [] },
            {
              name: "R",
              inputBytes: [2, 3],
              children: [
                {
                  kind: "step",
                  id: "round.rich.a",
                  type: "feistel.toy-add-k@1",
                  params: { k: 0x01 },
                },
                {
                  kind: "step",
                  id: "round.rich.b",
                  type: "feistel.toy-add-k@1",
                  params: { k: 0x02 },
                },
                {
                  kind: "step",
                  id: "round.rich.c",
                  type: "feistel.toy-add-k@1",
                  params: { k: 0x03 },
                },
              ],
            },
          ],
          combineKind: "feistel-standard",
        },
      ],
    };
    const graph = deriveAuxGraph(emptyTrace, richTrack);
    const stateEdges = graph.edges.filter((e) => e.kind === "state");
    const has = (from: string, to: string): boolean =>
      stateEdges.some((e) => e.from === from && e.to === to);
    // Within-track chain edges:
    expect(has("round.rich.a", "round.rich.b")).toBe(true);
    expect(has("round.rich.b", "round.rich.c")).toBe(true);
    // Last R-track leaf → rejoin:
    expect(has("round.rich.c", "round.rich:rejoin")).toBe(true);
    // UX-D candidate (b), 2026-05-22 — the populated R-track in a
    // `feistel-standard` round gets a synthetic R-bypass passthrough
    // chip (`:passthrough-1`) at the head of the column. The chip
    // sits upstream of round.rich.a (the F-stack head), so the chain
    // runs chip → a → b → c with the bypass coming off the chip
    // (chip → rejoin) in parallel with the F-stack's terminal fan-out.
    expect(has("round.rich:passthrough-1", "round.rich.a")).toBe(true);
    expect(has("round.rich:passthrough-1", "round.rich:rejoin")).toBe(true);
    // round.rich.a's only outgoing edge is to round.rich.b
    // (the chip is upstream, not parallel — the bypass arrow leaves
    // the chip, not round.rich.a).
    for (const e of stateEdges) {
      if (e.from === "round.rich.a") {
        expect(e.to).toBe("round.rich.b");
      }
    }
  });
});
