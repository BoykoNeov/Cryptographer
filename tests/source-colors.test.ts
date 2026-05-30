/**
 * Unit tests for `src/core/source-colors.ts`. Pure helpers — node env,
 * no DOM.
 *
 * Coverage map (matches the four properties enumerated in the plan stub
 * `docs/plans/source-color-coding.md`):
 *
 *   1. `resolveCanonicalSource` — replica resolution, plain edge,
 *      endpoint pill returns undefined.
 *   2. `multiFanoutSources` — alphabetical, ≥ 2 only, endpoint pills
 *      skipped, replicas count toward canonical source.
 *   3. `colorForSourceIndex` — palette for i < 8, golden-angle HSL for
 *      i ≥ 8, fixed S/L on the generated tail.
 *   4. `assignSourceColors` — deterministic same-graph → same-map,
 *      multi-fanout-only.
 */

import { CIPHER_INPUT_ID, type CipherGraph, type GraphEdge, type GraphNode } from "@/core/graph";
import {
  SOURCE_COLOR_PALETTE,
  allColorableSources,
  assignSourceColors,
  colorForEdge,
  colorForSourceIndex,
  multiFanoutSources,
  resolveCanonicalSource,
} from "@/core/source-colors";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Plain leaf node at root. */
const leaf = (stepId: string): GraphNode => ({
  stepId,
  stepType: "test.leaf",
  label: stepId,
  containerPath: [],
});

/** Replica node pointing back at `sourceId` via `replicaOf`. */
const replica = (stepId: string, sourceId: string): GraphNode => ({
  stepId,
  stepType: "test.replica",
  label: stepId,
  containerPath: [],
  replicaOf: sourceId,
});

/** Build an aux edge with a default key (tests rarely care about the key). */
const auxEdge = (from: string, to: string, auxKey = "k"): GraphEdge => ({
  from,
  to,
  auxKey,
  kind: "aux",
});

/** Assemble a graph from raw parts. */
const graph = (nodes: GraphNode[], edges: GraphEdge[]): CipherGraph => ({
  nodes,
  containers: [],
  edges,
  rootIds: nodes.map((n) => n.stepId),
});

// ─── 1. resolveCanonicalSource ────────────────────────────────────────────

describe("resolveCanonicalSource", () => {
  it("returns edge.from for a plain (non-replica) leaf", () => {
    const g = graph([leaf("source"), leaf("consumer")], [auxEdge("source", "consumer")]);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing test edge");
    expect(resolveCanonicalSource(edge, g)).toBe("source");
  });

  it("resolves a replica node to its replicaOf canonical source", () => {
    // Replica's stepId is the synthetic `${src}@->${consumer}` form;
    // its `replicaOf` points back at `key-expansion`. The function
    // should return `key-expansion`, not the synthetic id.
    const g = graph(
      [leaf("consumer"), replica("key-expansion@->consumer", "key-expansion")],
      [auxEdge("key-expansion@->consumer", "consumer", "rk")],
    );
    const edge = g.edges[0];
    if (!edge) throw new Error("missing test edge");
    expect(resolveCanonicalSource(edge, g)).toBe("key-expansion");
  });

  it("returns undefined for an edge whose source is a synthetic endpoint pill", () => {
    // The plaintext / ciphertext pill carries no canonical source — its
    // edges fall through to today's kind-based styling.
    const g = graph(
      [leaf("first-step")],
      [
        {
          from: CIPHER_INPUT_ID,
          to: "first-step",
          auxKey: "input",
          kind: "state",
        },
      ],
    );
    const edge = g.edges[0];
    if (!edge) throw new Error("missing test edge");
    expect(resolveCanonicalSource(edge, g)).toBeUndefined();
  });
});

// ─── 2. multiFanoutSources ────────────────────────────────────────────────

describe("multiFanoutSources", () => {
  it("returns sources with fanout >= 2 only (auto-coloring policy)", () => {
    // `single` has fanout 1 → excluded. `multi` has fanout 3 → included.
    // Single-fanout sources participate in `allColorableSources` (the
    // panel-listing helper for the "include single-output" toggle) but
    // not in `multiFanoutSources`, which drives auto-coloring.
    const g = graph(
      [leaf("single"), leaf("multi"), leaf("c1"), leaf("c2"), leaf("c3"), leaf("c4")],
      [
        auxEdge("single", "c1"),
        auxEdge("multi", "c2"),
        auxEdge("multi", "c3"),
        auxEdge("multi", "c4"),
      ],
    );
    expect(multiFanoutSources(g)).toEqual(["multi"]);
  });

  it("returns multi-fanout sources sorted alphabetically", () => {
    // Three sources, all with fanout ≥ 2. Alphabetical order is
    // `apple`, `banana`, `cherry` regardless of insertion order.
    const g = graph(
      [
        leaf("cherry"),
        leaf("apple"),
        leaf("banana"),
        leaf("c1"),
        leaf("c2"),
        leaf("c3"),
        leaf("c4"),
        leaf("c5"),
        leaf("c6"),
      ],
      [
        auxEdge("cherry", "c1"),
        auxEdge("cherry", "c2"),
        auxEdge("apple", "c3"),
        auxEdge("apple", "c4"),
        auxEdge("banana", "c5"),
        auxEdge("banana", "c6"),
      ],
    );
    expect(multiFanoutSources(g)).toEqual(["apple", "banana", "cherry"]);
  });

  it("counts replica edges toward their canonical source (replicaOf)", () => {
    // Five replicas pointing back to the same canonical
    // `key-expansion` source → canonical fanout 5, included even
    // though no edge has `from: 'key-expansion'` literally.
    const nodes = [
      leaf("c1"),
      leaf("c2"),
      leaf("c3"),
      leaf("c4"),
      leaf("c5"),
      replica("key-expansion@->c1", "key-expansion"),
      replica("key-expansion@->c2", "key-expansion"),
      replica("key-expansion@->c3", "key-expansion"),
      replica("key-expansion@->c4", "key-expansion"),
      replica("key-expansion@->c5", "key-expansion"),
    ];
    const edges = [
      auxEdge("key-expansion@->c1", "c1", "rk"),
      auxEdge("key-expansion@->c2", "c2", "rk"),
      auxEdge("key-expansion@->c3", "c3", "rk"),
      auxEdge("key-expansion@->c4", "c4", "rk"),
      auxEdge("key-expansion@->c5", "c5", "rk"),
    ];
    expect(multiFanoutSources(graph(nodes, edges))).toEqual(["key-expansion"]);
  });

  it("ignores edges whose source is an endpoint pill", () => {
    // Two state edges from CIPHER_INPUT_ID to two different first-steps
    // would naively count as fanout 2 for the pill. But pills aren't
    // colorable, so they're filtered out entirely.
    const g = graph(
      [leaf("a"), leaf("b")],
      [
        { from: CIPHER_INPUT_ID, to: "a", auxKey: "in", kind: "state" },
        { from: CIPHER_INPUT_ID, to: "b", auxKey: "in", kind: "state" },
      ],
    );
    expect(multiFanoutSources(g)).toEqual([]);
  });
});

// ─── 2b. allColorableSources (panel-listing helper) ───────────────────────

describe("allColorableSources", () => {
  it("includes single-fanout sources too (drives the include-single panel toggle)", () => {
    // Same input as `multiFanoutSources`'s first test; this helper
    // returns BOTH sources. The panel uses this when the user flips
    // the "include single-output sources" sub-toggle.
    const g = graph(
      [leaf("single"), leaf("multi"), leaf("c1"), leaf("c2"), leaf("c3"), leaf("c4")],
      [
        auxEdge("single", "c1"),
        auxEdge("multi", "c2"),
        auxEdge("multi", "c3"),
        auxEdge("multi", "c4"),
      ],
    );
    expect(allColorableSources(g)).toEqual(["multi", "single"]);
  });

  it("still skips endpoint-pill sources", () => {
    const g = graph([leaf("a")], [{ from: CIPHER_INPUT_ID, to: "a", auxKey: "in", kind: "state" }]);
    expect(allColorableSources(g)).toEqual([]);
  });
});

// ─── 3. colorForSourceIndex ───────────────────────────────────────────────

describe("colorForSourceIndex", () => {
  it("returns the curated palette entry for indices 0..7", () => {
    for (let i = 0; i < SOURCE_COLOR_PALETTE.length; i++) {
      expect(colorForSourceIndex(i)).toBe(SOURCE_COLOR_PALETTE[i]);
    }
  });

  it("returns a hex color generated from the golden-angle hue for indices >= 8", () => {
    // Index 8 → hue = 8 * 137.508 = 1100.064 → mod 360 → 20.064...
    // Index 9 → hue = 9 * 137.508 = 1237.572 → mod 360 → 157.572...
    // Both go through HSL→hex conversion with fixed 65% saturation +
    // 55% luminance. The exact hex string isn't pinned (hex
    // conversion's small rounding is stable but brittle to assert
    // digit-for-digit); the SHAPE is pinned + the "different sources
    // produce different colors" property.
    const c8 = colorForSourceIndex(8);
    const c9 = colorForSourceIndex(9);
    expect(c8).toMatch(/^#[0-9a-f]{6}$/);
    expect(c9).toMatch(/^#[0-9a-f]{6}$/);
    // Different hues — golden angle stepping never produces equal hues
    // within a single 360° cycle.
    expect(c8).not.toBe(c9);
  });

  it("is deterministic across calls (no random / time dependence)", () => {
    // Critical for screenshot stability. Call twice for several indices
    // and assert byte-identical results.
    for (const i of [0, 3, 7, 8, 15, 42]) {
      expect(colorForSourceIndex(i)).toBe(colorForSourceIndex(i));
    }
  });
});

// ─── 4. assignSourceColors ────────────────────────────────────────────────

describe("assignSourceColors", () => {
  it("assigns palette[0..K] to the alphabetically-sorted sources", () => {
    // Three sources in non-alphabetical insertion order; sorted is
    // [`apple`, `banana`, `cherry`] → palette[0..2].
    const g = graph(
      [
        leaf("cherry"),
        leaf("apple"),
        leaf("banana"),
        leaf("c1"),
        leaf("c2"),
        leaf("c3"),
        leaf("c4"),
        leaf("c5"),
        leaf("c6"),
      ],
      [
        auxEdge("cherry", "c1"),
        auxEdge("cherry", "c2"),
        auxEdge("apple", "c3"),
        auxEdge("apple", "c4"),
        auxEdge("banana", "c5"),
        auxEdge("banana", "c6"),
      ],
    );
    const colors = assignSourceColors(g);
    expect(colors.get("apple")).toBe(SOURCE_COLOR_PALETTE[0]);
    expect(colors.get("banana")).toBe(SOURCE_COLOR_PALETTE[1]);
    expect(colors.get("cherry")).toBe(SOURCE_COLOR_PALETTE[2]);
  });

  it("returns an empty map when no source has fanout >= 2", () => {
    // Every source fans out to exactly one consumer → no entries in
    // the auto map. Single-fanout sources can still be MANUALLY
    // coloured via the panel (when the include-single sub-toggle is
    // ON) — those overrides live in the store, not in this map.
    const g = graph(
      [leaf("a"), leaf("b"), leaf("c1"), leaf("c2")],
      [auxEdge("a", "c1"), auxEdge("b", "c2")],
    );
    expect(assignSourceColors(g).size).toBe(0);
  });

  it("auto-colors only multi-fanout sources (single-fanout absent)", () => {
    // `multi` fanout 2 → in map. `single` fanout 1 → NOT in map. The
    // panel's "include single-output sources" toggle adds rows for
    // single-fanout sources but they start UNCOLOURED (no auto entry,
    // no manual entry yet) — the user picks a colour to add a manual
    // entry on top of the auto map.
    const g = graph(
      [leaf("multi"), leaf("single"), leaf("c1"), leaf("c2"), leaf("c3")],
      [auxEdge("multi", "c1"), auxEdge("multi", "c2"), auxEdge("single", "c3")],
    );
    const colors = assignSourceColors(g);
    expect(colors.has("multi")).toBe(true);
    expect(colors.has("single")).toBe(false);
  });

  it("is deterministic across calls on the same graph (screenshot stability)", () => {
    const g = graph(
      [leaf("zeta"), leaf("alpha"), leaf("c1"), leaf("c2"), leaf("c3"), leaf("c4")],
      [
        auxEdge("zeta", "c1"),
        auxEdge("zeta", "c2"),
        auxEdge("alpha", "c3"),
        auxEdge("alpha", "c4"),
      ],
    );
    const a = assignSourceColors(g);
    const b = assignSourceColors(g);
    // Compare entry-by-entry — Map equality is reference, but we want
    // value equality.
    expect([...a.entries()].sort()).toEqual([...b.entries()].sort());
  });

  it("extends beyond the 8-color palette with HSL generation when N > 8", () => {
    // 10 sources, all fanout 2. Sources 0..7 (alphabetically) get the
    // palette; sources 8 and 9 get HSL strings. Pin the "extends, doesn't
    // cycle" property — cycling would mean source[8] === source[0],
    // which user explicitly rejected.
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    // Use letter prefixes so the alphabetical sort matches insertion
    // order: a, b, c, ... j.
    for (let i = 0; i < 10; i++) {
      const src = `${String.fromCharCode(97 + i)}-src`;
      const c1 = `${src}-c1`;
      const c2 = `${src}-c2`;
      nodes.push(leaf(src), leaf(c1), leaf(c2));
      edges.push(auxEdge(src, c1), auxEdge(src, c2));
    }
    const g = graph(nodes, edges);
    const colors = assignSourceColors(g);
    expect(colors.size).toBe(10);
    expect(colors.get("a-src")).toBe(SOURCE_COLOR_PALETTE[0]);
    expect(colors.get("h-src")).toBe(SOURCE_COLOR_PALETTE[7]); // last palette slot
    // Index 8+ → algorithmically-generated hex.
    expect(colors.get("i-src")).toMatch(/^#[0-9a-f]{6}$/);
    expect(colors.get("j-src")).toMatch(/^#[0-9a-f]{6}$/);
    expect(colors.get("i-src")).not.toBe(colors.get("a-src"));
  });
});

// ─── 4b. fanout threshold parameter (2026-05-30) ──────────────────────────

describe("multiFanoutSources / assignSourceColors — threshold parameter", () => {
  // Fixture: `big` fanout 3, `mid` fanout 2, `single` fanout 1.
  const fixture = (): CipherGraph =>
    graph(
      [
        leaf("big"),
        leaf("mid"),
        leaf("single"),
        leaf("c1"),
        leaf("c2"),
        leaf("c3"),
        leaf("c4"),
        leaf("c5"),
        leaf("c6"),
      ],
      [
        auxEdge("big", "c1"),
        auxEdge("big", "c2"),
        auxEdge("big", "c3"),
        auxEdge("mid", "c4"),
        auxEdge("mid", "c5"),
        auxEdge("single", "c6"),
      ],
    );

  it("defaults to >= 2 when no threshold is passed (backward-compatible)", () => {
    expect(multiFanoutSources(fixture())).toEqual(["big", "mid"]);
  });

  it("threshold 3 includes only fanout >= 3 sources", () => {
    expect(multiFanoutSources(fixture(), 3)).toEqual(["big"]);
  });

  it("threshold 0 includes EVERY non-endpoint source (all edges colorable)", () => {
    // fanout 0 cutoff → every source with at least one outgoing edge.
    expect(multiFanoutSources(fixture(), 0)).toEqual(["big", "mid", "single"]);
  });

  it("threshold 1 also includes single-fanout sources", () => {
    expect(multiFanoutSources(fixture(), 1)).toEqual(["big", "mid", "single"]);
  });

  it("assignSourceColors honors the threshold (single-fanout colored at 0)", () => {
    const colorsDefault = assignSourceColors(fixture());
    expect(colorsDefault.has("single")).toBe(false);
    const colorsAll = assignSourceColors(fixture(), 0);
    expect(colorsAll.has("single")).toBe(true);
    expect(colorsAll.has("mid")).toBe(true);
    expect(colorsAll.has("big")).toBe(true);
  });

  it("assignSourceColors at threshold 3 drops the fanout-2 source's color", () => {
    const colors = assignSourceColors(fixture(), 3);
    expect(colors.has("big")).toBe(true);
    expect(colors.has("mid")).toBe(false);
  });
});

// ─── 5. colorForEdge ──────────────────────────────────────────────────────

describe("colorForEdge", () => {
  it("returns the auto-assigned color for a multi-fanout source", () => {
    const g = graph(
      [leaf("src"), leaf("c1"), leaf("c2")],
      [auxEdge("src", "c1"), auxEdge("src", "c2")],
    );
    const autos = assignSourceColors(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(colorForEdge(edge, g, autos, new Map())).toBe(SOURCE_COLOR_PALETTE[0]);
  });

  it("manual override wins over the auto color", () => {
    const g = graph(
      [leaf("src"), leaf("c1"), leaf("c2")],
      [auxEdge("src", "c1"), auxEdge("src", "c2")],
    );
    const autos = assignSourceColors(g);
    const manual = new Map<string, string>([["src", "#FF1234"]]);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(colorForEdge(edge, g, autos, manual)).toBe("#FF1234");
  });

  it("returns undefined for single-fanout source (caller falls through to kind styling)", () => {
    // Auto map only contains multi-fanout sources. A single-fanout
    // source's edge gets `undefined` → EdgePath falls through to the
    // kind class. (If the user manually colours it via the include-
    // single sub-toggle, that override is passed as the 4th arg —
    // not exercised here.)
    const g = graph([leaf("src"), leaf("c1")], [auxEdge("src", "c1")]);
    const autos = assignSourceColors(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(colorForEdge(edge, g, autos, new Map())).toBeUndefined();
  });

  it("returns undefined for an endpoint-pill-sourced edge", () => {
    const g = graph([leaf("a")], [{ from: CIPHER_INPUT_ID, to: "a", auxKey: "in", kind: "state" }]);
    const autos = assignSourceColors(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(colorForEdge(edge, g, autos, new Map())).toBeUndefined();
  });

  it("colors a replica's edge by its canonical source", () => {
    // Two replicas of `src` → multi-fanout 2 → `src` in the auto map.
    // Each replica's edge should color by that canonical color.
    const g = graph(
      [leaf("c1"), leaf("c2"), replica("src@->c1", "src"), replica("src@->c2", "src")],
      [auxEdge("src@->c1", "c1"), auxEdge("src@->c2", "c2")],
    );
    const autos = assignSourceColors(g);
    const edge0 = g.edges[0];
    const edge1 = g.edges[1];
    if (!edge0 || !edge1) throw new Error("missing edges");
    expect(colorForEdge(edge0, g, autos, new Map())).toBe(SOURCE_COLOR_PALETTE[0]);
    expect(colorForEdge(edge1, g, autos, new Map())).toBe(SOURCE_COLOR_PALETTE[0]);
  });
});
