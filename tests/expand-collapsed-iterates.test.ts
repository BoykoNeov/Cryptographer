/**
 * Tests for `src/core/graph.ts::expandCollapsedIterates` (Slice 6 of the
 * graph-narrative-and-zoom plan).
 *
 * Option C contract (current):
 *   - Each COLLAPSED iterate is KEPT in `containers` with its `childIds`
 *     replaced by N synthetic "block-chip" GraphNodes (capped at 6 visible
 *     items, ellipsis chip when N > 6). The chips' `containerPath`
 *     includes the iterate id so layout recurses into the iterate body.
 *   - Edges to/from the iterate STAY on the iterate id — they are NOT
 *     fanned to chips. External arrows point at the box; the chips are
 *     a visual representation of "what runs inside," not first-class
 *     dataflow participants.
 *   - The iterate's header chevron handles re-expand (clicking it
 *     removes the iterate from `collapsedGroups`).
 *   - Pre-Option-C (Option B) contract — drop iterate, fan edges per chip
 *     — is preserved in `expandCollapsedIterates` history; the tests below
 *     pin Option C explicitly.
 *
 * Coverage targets:
 *   - Cap math: N ∈ {1, 2, 5, 6, 7, 10, 100}
 *   - Iterate is RETAINED in containers + rootIds; childIds rewired to
 *     chip ids
 *   - Edges with the iterate as endpoint stay untouched
 *   - Identity short-circuit: empty collapsedIds, iterate-without-blockSpan,
 *     iterate-not-in-collapsedIds — input returned by reference
 *   - End-to-end on AES-128 ECB (real spec + trace, 4 blocks): chip
 *     children inside the kept iterate container
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

// ─── Iterate retention + childIds rewrite (Option C contract) ────────────

describe("expandCollapsedIterates iterate retention", () => {
  it("keeps the iterate in `containers` and replaces its childIds with chip ids", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const iter = out.containers.find((c) => c.id === "iter");
    expect(iter).toBeDefined();
    expect(iter?.childIds).toEqual(["iter@block0", "iter@block1", "iter@block2"]);
  });

  it("keeps the iterate's slot in `rootIds` (no splice)", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    // rootIds untouched — only iterate.childIds gets rewritten.
    expect(out.rootIds).toEqual(["src", "iter", "snk"]);
  });

  it("places chip nodes inside the iterate's containerPath", () => {
    const g = makeCollapsedIterateGraph(2);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    const chips = out.nodes.filter((n) => n.blockChipOf === "iter");
    for (const chip of chips) {
      expect(chip.containerPath).toEqual(["iter"]);
    }
  });

  it("leaves edges with the iterate as endpoint untouched (no fanning)", () => {
    const g = makeCollapsedIterateGraph(3);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    // src → iter and iter → snk both stay as single edges anchored on
    // the iterate id. Chips don't appear in any edge endpoint.
    const incoming = out.edges.filter((e) => e.to === "iter");
    expect(incoming).toHaveLength(1);
    expect(incoming[0]?.from).toBe("src");
    const outgoing = out.edges.filter((e) => e.from === "iter");
    expect(outgoing).toHaveLength(1);
    expect(outgoing[0]?.to).toBe("snk");
    // No edge touches any chip.
    for (const e of out.edges) {
      expect(e.from.startsWith("iter@")).toBe(false);
      expect(e.to.startsWith("iter@")).toBe(false);
    }
  });

  it("does not fan state edges either (state edges follow the same retention rule)", () => {
    const g = makeCollapsedIterateGraph(2);
    const withState: CipherGraph = {
      ...g,
      edges: [...g.edges, { from: "src", to: "iter", auxKey: "state", kind: "state" }],
    };
    const out = expandCollapsedIterates(withState, new Set(["iter"]));
    const stateEdges = out.edges.filter((e) => e.kind === "state");
    expect(stateEdges).toHaveLength(1);
    expect(stateEdges[0]?.to).toBe("iter");
  });

  it("never returns the input by reference when at least one iterate qualifies", () => {
    // The transform rebuilds containers + nodes for any qualifying
    // iterate, so identity equality must NOT hold (catches a regression
    // where someone re-introduces a "no actual change needed" short-circuit
    // that would skip the childIds rewrite).
    const g = makeCollapsedIterateGraph(2);
    const out = expandCollapsedIterates(g, new Set(["iter"]));
    expect(out).not.toBe(g);
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
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    portedDispatchEnabled: true,
  });

describe("expandCollapsedIterates on AES-128 ECB (4 blocks)", () => {
  it("collapsing 'ecb-blocks' keeps the iterate and adds 4 chip children", () => {
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));

    // Sanity: the iterate is present pre-expansion with blockSpan=4. (Byte-
    // native ECB — B1.4 — has no `split-blocks`/`concat-blocks` boundary
    // leaves; blockSpan is driven by `frame.blockIndex`, which the port-mode
    // iterate still stamps, so the chip mechanics below are unchanged.)
    const iterPre = collapsed.containers.find((c) => c.id === "ecb-blocks");
    expect(iterPre?.blockSpan).toBe(4);

    const expanded = expandCollapsedIterates(collapsed, new Set(["ecb-blocks"]));

    // 4 chips, no ellipsis (N=4 ≤ cap).
    const chips = expanded.nodes.filter((n) => n.blockChipOf === "ecb-blocks");
    expect(chips).toHaveLength(4);
    expect(chips.map((c) => c.label)).toEqual(["block 1", "block 2", "block 3", "block 4"]);

    // Option C: iterate STAYS in containers + rootIds; childIds rewired.
    const iterPost = expanded.containers.find((c) => c.id === "ecb-blocks");
    expect(iterPost).toBeDefined();
    expect(iterPost?.childIds).toEqual([
      "ecb-blocks@block0",
      "ecb-blocks@block1",
      "ecb-blocks@block2",
      "ecb-blocks@block3",
    ]);
    expect(expanded.rootIds.includes("ecb-blocks")).toBe(true);

    // The Option-C invariant that matters regardless of cipher shape: external
    // edges stay on the iterate boundary (NOT fanned to chips). Chips are
    // inside-the-box; no edge endpoint mentions a chip id.
    for (const e of expanded.edges) {
      expect(e.from.startsWith("ecb-blocks@block")).toBe(false);
      expect(e.to.startsWith("ecb-blocks@block")).toBe(false);
    }
  });

  it("composes with replicateHighFanoutSources: edge count is per-iterate, not per-chip", () => {
    // Under Option C, edges to the iterate STAY on the iterate id (no
    // fanning). So a source with one outgoing edge to a collapsed
    // iterate has fanout 1 regardless of N — the chips don't multiply
    // the edge count. The earlier Option B "1 source → N chip edges"
    // composition is intentionally absent. (Pin the edge-count contract;
    // the replication function's threshold + tie-breaking semantics
    // live in its own unit tests.)

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
    // key-expansion still has exactly 1 outgoing aux edge, and its
    // endpoint is the iterate (not any chip).
    const outEdges = expandedFixture.edges.filter((e) => e.from === "key-expansion");
    expect(outEdges).toHaveLength(1);
    expect(outEdges[0]?.to).toBe("iter");
    // Reference to replicateHighFanoutSources kept so the import doesn't
    // become unused — it's still part of the pipeline this transform
    // composes with, even though Option C neutralizes the per-chip
    // multiplier the old (Option B) contract used to produce.
    const replicated = replicateHighFanoutSources(expandedFixture, 100);
    expect(replicated.nodes.length).toBeGreaterThanOrEqual(expandedFixture.nodes.length);
  });
});
