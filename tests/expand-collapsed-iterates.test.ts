/**
 * Tests for `src/core/graph.ts::expandCollapsedIterates` (Slice 6 of the
 * graph-narrative-and-zoom plan).
 *
 * The transform turns each COLLAPSED iterate container into N synthetic
 * "block-chip" GraphNodes (capped at 6 visible items, ellipsis chip when
 * N > 6). It runs AFTER `collapseGraph` and BEFORE
 * `replicateHighFanoutSources` in the GraphView pipeline so chips become
 * replication candidates (e.g. `key-expansion@always` produces one tiny
 * replica per chip).
 *
 * Coverage targets:
 *   - Cap math: N ∈ {1, 2, 5, 6, 7, 10, 100}
 *   - Edge fanning: every edge with the iterate as endpoint duplicates
 *     across all chips, regardless of `kind`
 *   - rootIds / parent-childIds splice replaces the iterate slot
 *   - Identity short-circuit: empty collapsedIds, iterate-without-blockSpan,
 *     iterate-not-in-collapsedIds — input returned by reference
 *   - End-to-end on AES-128 ECB (real spec + trace, 4 blocks): chips
 *     receive the same fanned aux edges that the iterate did
 *   - Composition: chained with `replicateHighFanoutSources(threshold=4)`
 *     yields one `key-expansion` replica per visible chip
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  type CipherGraph,
  type ContainerNode,
  type GraphEdge,
  type GraphNode,
  collapseGraph,
  deriveAuxGraph,
  expandCollapsedIterates,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Synthetic graph fixture ─────────────────────────────────────────────
//
// Hand-built graphs let the cap-math tests vary N without needing a
// matching plaintext size. Real-spec coverage lives in the
// "AES-128 ECB end-to-end" describe block below.

/** Minimal graph: one source leaf, one iterate (with N blockSpan), one sink leaf. */
const makeIterateGraph = (N: number): CipherGraph => {
  const nodes: GraphNode[] = [
    { stepId: "src", stepType: "src.type", label: "src", containerPath: [] },
    { stepId: "snk", stepType: "snk.type", label: "snk", containerPath: [] },
    // Body leaf inside the iterate — included for shape parity with real
    // specs (`split-blocks → iterate(body) → concat-blocks`). Not consumed
    // by the chip-expansion transform but exercises the container's
    // childIds path.
    {
      stepId: "iter.body",
      stepType: "body.type",
      label: "iter.body",
      containerPath: ["iter"],
      blockSpan: N,
    },
  ];
  const containers: ContainerNode[] = [
    {
      kind: "iterate",
      id: "iter",
      label: "iter",
      containerPath: [],
      childIds: ["iter.body"],
      blockSpan: N,
    },
  ];
  const edges: GraphEdge[] = [
    // src → iterate (one aux edge into the iterate boundary)
    { from: "src", to: "iter", auxKey: "blocks-in", kind: "aux" },
    // iterate → snk (one aux edge out)
    { from: "iter", to: "snk", auxKey: "blocks-out", kind: "aux" },
  ];
  return {
    nodes,
    containers,
    edges,
    rootIds: ["src", "iter", "snk"],
  };
};

/** Same as above but COLLAPSED: childIds cleared, mimicking `collapseGraph`. */
const makeCollapsedIterateGraph = (N: number): CipherGraph => {
  const g = makeIterateGraph(N);
  return {
    ...g,
    nodes: g.nodes.filter((n) => n.containerPath.length === 0),
    containers: g.containers.map((c) => ({ ...c, childIds: [] as readonly string[] })),
  };
};

// ─── Cap math + chip-shape tests ─────────────────────────────────────────

describe("expandCollapsedIterates cap math", () => {
  it("N=1 produces exactly 1 chip and no ellipsis", () => {
    const g = makeCollapsedIterateGraph(1);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(1);
    expect(chips[0]?.label).toBe("block 1");
    expect(chips.find((c) => c.label.includes("more"))).toBeUndefined();
  });

  it("N=5 produces 5 chips and no ellipsis", () => {
    const g = makeCollapsedIterateGraph(5);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(5);
    expect(chips.map((c) => c.label)).toEqual([
      "block 1",
      "block 2",
      "block 3",
      "block 4",
      "block 5",
    ]);
  });

  it("N=6 produces 6 chips and no ellipsis (boundary case)", () => {
    const g = makeCollapsedIterateGraph(6);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(6);
    expect(chips.find((c) => c.label.includes("more"))).toBeUndefined();
  });

  it("N=7 produces 5 chips + 1 ellipsis (first overflow)", () => {
    const g = makeCollapsedIterateGraph(7);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(6);
    expect(chips[5]?.label).toBe("+2 more blocks");
    expect(chips[5]?.stepId).toBe("iter@blockMore");
  });

  it("N=10 produces 5 chips + 1 ellipsis labeled '+5 more blocks'", () => {
    const g = makeCollapsedIterateGraph(10);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(6);
    expect(chips[5]?.label).toBe("+5 more blocks");
  });

  it("N=100 still caps at 5 chips + ellipsis '+95 more blocks'", () => {
    const g = makeCollapsedIterateGraph(100);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    expect(chips).toHaveLength(6);
    expect(chips[5]?.label).toBe("+95 more blocks");
  });
});

// ─── Edge fanning ────────────────────────────────────────────────────────

describe("expandCollapsedIterates edge fanning", () => {
  it("fans an edge ending at the iterate to one edge per chip", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const incomingFromSrc = out.edges.filter((e) => e.from === "src" && e.auxKey === "blocks-in");
    expect(incomingFromSrc).toHaveLength(3);
    expect(incomingFromSrc.map((e) => e.to).sort()).toEqual([
      "iter@block0",
      "iter@block1",
      "iter@block2",
    ]);
    // Each fanned edge preserves the original kind + auxKey.
    for (const e of incomingFromSrc) {
      expect(e.kind).toBe("aux");
    }
  });

  it("fans an edge starting at the iterate to one edge per chip", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const outgoingToSnk = out.edges.filter((e) => e.to === "snk" && e.auxKey === "blocks-out");
    expect(outgoingToSnk).toHaveLength(3);
    expect(outgoingToSnk.map((e) => e.from).sort()).toEqual([
      "iter@block0",
      "iter@block1",
      "iter@block2",
    ]);
  });

  it("removes the iterate from containers and from rootIds", () => {
    const g = makeCollapsedIterateGraph(2);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    expect(out.containers.find((c) => c.id === "iter")).toBeUndefined();
    expect(out.rootIds.includes("iter")).toBe(false);
  });

  it("splices chip ids in spec order at the iterate's old rootIds slot", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    expect(out.rootIds).toEqual(["src", "iter@block0", "iter@block1", "iter@block2", "snk"]);
  });

  it("includes the ellipsis chip in the fanned-edge set when N > cap", () => {
    const g = makeCollapsedIterateGraph(10);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const incoming = out.edges.filter((e) => e.to === "iter@blockMore");
    expect(incoming).toHaveLength(1);
    expect(incoming[0]?.from).toBe("src");
  });

  it("fans state edges as well as aux edges (defensive against future routing)", () => {
    // Inject a synthetic state edge ending at the iterate. Real specs
    // don't produce this today, but the transform must not silently
    // drop it when a future pipeline change adds one.
    const g = makeCollapsedIterateGraph(2);
    const withState: CipherGraph = {
      ...g,
      edges: [...g.edges, { from: "src", to: "iter", auxKey: "state", kind: "state" }],
    };
    const out = expandCollapsedIterates(withState, new Set(["iter"]));
    const stateEdges = out.edges.filter((e) => e.kind === "state");
    expect(stateEdges).toHaveLength(2);
    expect(stateEdges.map((e) => e.to).sort()).toEqual(["iter@block0", "iter@block1"]);
  });
});

// ─── Identity short-circuits ─────────────────────────────────────────────

describe("expandCollapsedIterates short-circuits", () => {
  it("returns input by reference when collapsedIds is empty", () => {
    const g = makeIterateGraph(4);
    const out = expandCollapsedIterates(g, new Set());
    expect(out).toBe(g);
  });

  it("returns input by reference when no iterate is in collapsedIds", () => {
    const g = makeIterateGraph(4);
    // Collapsed set names a non-existent id — no qualifying iterate.
    const out = expandCollapsedIterates(g, new Set(["bogus"]));
    expect(out).toBe(g);
  });

  it("leaves untouched a collapsed iterate whose blockSpan is undefined (pre-run)", () => {
    const g = makeCollapsedIterateGraph(3);
    // Strip blockSpan from the iterate to simulate a pre-run state.
    const preRun: CipherGraph = {
      ...g,
      containers: g.containers.map((c) => {
        const { blockSpan: _b, ...rest } = c;
        return rest as ContainerNode;
      }),
    };
    const out = expandCollapsedIterates(preRun, new Set(["iter"]));
    expect(out).toBe(preRun);
  });

  it("leaves a collapsed group (kind != 'iterate') untouched", () => {
    const g: CipherGraph = {
      nodes: [
        {
          stepId: "g.body",
          stepType: "body.type",
          label: "g.body",
          containerPath: ["g"],
        },
      ],
      containers: [{ kind: "group", id: "g", label: "g", containerPath: [], childIds: [] }],
      edges: [],
      rootIds: ["g"],
    };
    const out = expandCollapsedIterates(g, new Set(["g"]));
    expect(out).toBe(g);
  });
});

// ─── Real-spec end-to-end ────────────────────────────────────────────────

const ECB_PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const runAes128Ecb = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c")],
    ]),
  });

describe("expandCollapsedIterates on AES-128 ECB (4 blocks)", () => {
  it("collapsing 'ecb-blocks' produces 4 chips with the iterate's edges fanned", () => {
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));

    // Sanity: the iterate is present pre-expansion with blockSpan=4 and
    // edges from `split-blocks → ecb-blocks → concat-blocks`.
    const iterPre = collapsed.containers.find((c) => c.id === "ecb-blocks");
    expect(iterPre?.blockSpan).toBe(4);
    expect(collapsed.edges.some((e) => e.from === "split-blocks" && e.to === "ecb-blocks")).toBe(
      true,
    );
    expect(collapsed.edges.some((e) => e.from === "ecb-blocks" && e.to === "concat-blocks")).toBe(
      true,
    );

    const expanded = expandCollapsedIterates(collapsed, new Set(["ecb-blocks"]));

    // 4 chips, no ellipsis (N=4 ≤ cap).
    const chips = expanded.nodes.filter((n) => n.blockChipOf === "ecb-blocks");
    expect(chips).toHaveLength(4);
    expect(chips.map((c) => c.label)).toEqual(["block 1", "block 2", "block 3", "block 4"]);

    // Iterate is gone from containers + rootIds.
    expect(expanded.containers.find((c) => c.id === "ecb-blocks")).toBeUndefined();
    expect(expanded.rootIds.includes("ecb-blocks")).toBe(false);
    // …replaced in rootIds in spec order — chips appear contiguously at
    // the iterate's old slot. Locate the first chip and assert the run.
    const firstChipIdx = expanded.rootIds.indexOf("ecb-blocks@block0");
    expect(firstChipIdx).toBeGreaterThanOrEqual(0);
    expect(expanded.rootIds.slice(firstChipIdx, firstChipIdx + 4)).toEqual([
      "ecb-blocks@block0",
      "ecb-blocks@block1",
      "ecb-blocks@block2",
      "ecb-blocks@block3",
    ]);

    // Edges from `split-blocks` and `compute-block-count` to the iterate
    // each fan to 4 (one per chip), preserving auxKey + kind.
    const splitEdges = expanded.edges.filter(
      (e) => e.from === "split-blocks" && e.to.startsWith("ecb-blocks@block"),
    );
    expect(splitEdges).toHaveLength(4);

    // Edges from the iterate to `concat-blocks` fan the same way.
    const concatEdges = expanded.edges.filter(
      (e) => e.from.startsWith("ecb-blocks@block") && e.to === "concat-blocks",
    );
    expect(concatEdges).toHaveLength(4);
  });

  it("composes with replicateHighFanoutSources: key-expansion replicates per chip", () => {
    // For today's AES-128 ECB the round keys flow into add-round-key leaves
    // INSIDE the iterate body, so collapsing hides those consumers and
    // key-expansion has nothing left to replicate against. Future specs
    // that aux-feed the iterate boundary directly (e.g. a hash compression
    // function with `key`/`schedule` as a per-block aux) WILL hit the
    // composition. We pin that contract on a hand-built fixture rather
    // than a real spec — keeps the assertion robust to today's ECB
    // accidentally not exercising the path.

    const fixture: CipherGraph = {
      nodes: [
        { stepId: "key-expansion", stepType: "ke", label: "key-expansion", containerPath: [] },
        { stepId: "iter", stepType: "iterate", label: "iter", containerPath: [] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "iter",
          label: "iter",
          containerPath: [],
          childIds: [],
          blockSpan: 3,
        },
      ],
      edges: [{ from: "key-expansion", to: "iter", auxKey: "key", kind: "aux" }],
      rootIds: ["key-expansion", "iter"],
    };
    const expandedFixture = expandCollapsedIterates(fixture, new Set(["iter"]));
    // Now key-expansion has 3 outgoing aux edges (one per chip).
    const replicated = replicateHighFanoutSources(expandedFixture, 2);
    // Replication kicks in (3 > threshold 2) → 3 replicas, one per chip.
    const replicas = replicated.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas).toHaveLength(3);
  });
});
