/**
 * Unit tests for `src/core/source-strokes.ts`. Pure helpers — node env,
 * no DOM. Mirrors `tests/source-colors.test.ts`.
 *
 * Coverage map (the properties enumerated in `docs/plans/toasty-zooming-harp.md`
 * "Part A → Tests"):
 *
 *   1. `STROKE_STYLE_CATALOGUE` shape — 24 tiered entries, index 0 = solid,
 *      names unique, tiers apply weight/phase (NOT modulo-cycling).
 *   2. `strokeStyleByName` — known name → bundle; unknown/legacy → solid
 *      (forward-compat).
 *   3. `strokeForSourceIndex` — index 0 = solid, tier separation
 *      (index 2 ≠ index 10), determinism.
 *   4. `assignSourceStrokes` — deterministic, alphabetical, multi-fanout
 *      only, honors threshold, replica-collapsing (via the shared resolver).
 *   5. `strokeForEdge` — auto name, manual override wins, undefined for
 *      single-fanout / endpoint pills, replica canonical resolution.
 */

import { CIPHER_INPUT_ID, type CipherGraph, type GraphEdge, type GraphNode } from "@/core/graph";
import {
  SOLID_STROKE,
  STROKE_STYLE_CATALOGUE,
  STROKE_TIER_SIZE,
  assignSourceStrokes,
  resolveCanonicalSource,
  strokeForEdge,
  strokeForSourceIndex,
  strokeStyleByName,
} from "@/core/source-strokes";
import { describe, expect, it } from "vitest";

// ─── Helpers (mirror source-colors.test.ts) ───────────────────────────────

const leaf = (stepId: string): GraphNode => ({
  stepId,
  stepType: "test.leaf",
  label: stepId,
  containerPath: [],
});

const replica = (stepId: string, sourceId: string): GraphNode => ({
  stepId,
  stepType: "test.replica",
  label: stepId,
  containerPath: [],
  replicaOf: sourceId,
});

const auxEdge = (from: string, to: string, auxKey = "k"): GraphEdge => ({
  from,
  to,
  auxKey,
  kind: "aux",
});

const graph = (nodes: GraphNode[], edges: GraphEdge[]): CipherGraph => ({
  nodes,
  containers: [],
  edges,
  rootIds: nodes.map((n) => n.stepId),
});

/** Build N multi-fanout sources named `a-src`..`(a+N)-src`, each fanout 2. */
const nSourceGraph = (n: number): CipherGraph => {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (let i = 0; i < n; i++) {
    const src = `${String.fromCharCode(97 + i)}-src`;
    const c1 = `${src}-c1`;
    const c2 = `${src}-c2`;
    nodes.push(leaf(src), leaf(c1), leaf(c2));
    edges.push(auxEdge(src, c1), auxEdge(src, c2));
  }
  return graph(nodes, edges);
};

// ─── 1. STROKE_STYLE_CATALOGUE shape ──────────────────────────────────────

describe("STROKE_STYLE_CATALOGUE", () => {
  it("has exactly 24 entries (8 base patterns × 3 tiers)", () => {
    expect(STROKE_STYLE_CATALOGUE.length).toBe(24);
    expect(STROKE_TIER_SIZE).toBe(8);
  });

  it("starts with the solid baseline at index 0", () => {
    const first = STROKE_STYLE_CATALOGUE[0];
    expect(first?.name).toBe("solid");
    expect(first?.dasharray).toBeNull();
    expect(first?.widthMul).toBe(1);
    expect(first?.dashoffset).toBeUndefined();
    // Exported SOLID_STROKE is that same baseline.
    expect(SOLID_STROKE.name).toBe("solid");
  });

  it("has unique names across all 24 entries (persisted value must be unambiguous)", () => {
    const names = STROKE_STYLE_CATALOGUE.map((s) => s.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("tier 1 (heavy) re-walks the base patterns with widthMul 1.75", () => {
    // Index 8 = base index 0 ('solid') at the heavy tier.
    const heavySolid = STROKE_STYLE_CATALOGUE[8];
    expect(heavySolid?.name).toBe("solid-heavy");
    expect(heavySolid?.widthMul).toBe(1.75);
    // Same dash pattern as its base twin, only the weight differs.
    expect(heavySolid?.dasharray).toBe(STROKE_STYLE_CATALOGUE[0]?.dasharray ?? null);
  });

  it("tier 2 (phase) re-walks with a half-period dashoffset on dashed patterns", () => {
    // Index 16 = base 0 ('solid') phase tier — solid has no period, so no offset.
    const phaseSolid = STROKE_STYLE_CATALOGUE[16];
    expect(phaseSolid?.name).toBe("solid-phase");
    expect(phaseSolid?.dashoffset).toBeUndefined();
    // Index 18 = base 2 ('short-dash', '4 3') → period 7 → offset 3.5.
    const phaseShort = STROKE_STYLE_CATALOGUE[18];
    expect(phaseShort?.name).toBe("short-dash-phase");
    expect(phaseShort?.dashoffset).toBe(3.5);
    expect(phaseShort?.widthMul).toBe(1);
  });
});

// ─── 2. strokeStyleByName ─────────────────────────────────────────────────

describe("strokeStyleByName", () => {
  it("returns the matching bundle for a known catalogue name", () => {
    expect(strokeStyleByName("short-dash").dasharray).toBe("4 3");
    expect(strokeStyleByName("round-dot").linecap).toBe("round");
    expect(strokeStyleByName("solid-heavy").widthMul).toBe(1.75);
  });

  it("falls back to solid for an unknown/legacy name (forward-compat)", () => {
    // A doc written by a future, larger catalogue opens on an older build:
    // the unrecognised name renders unstyled rather than hard-failing.
    expect(strokeStyleByName("some-future-style-2099")).toBe(SOLID_STROKE);
    expect(strokeStyleByName("").name).toBe("solid");
  });
});

// ─── 3. strokeForSourceIndex ──────────────────────────────────────────────

describe("strokeForSourceIndex", () => {
  it("returns the solid baseline for index 0 (unlike colour's orange)", () => {
    expect(strokeForSourceIndex(0).name).toBe("solid");
  });

  it("separates tiers: index 2 and index 10 share a dash but differ in weight", () => {
    // The advisor's canonical anti-modulo check: a naive CATALOGUE[i % 8]
    // would make these EQUAL, silently defeating the multi-channel design.
    const a = strokeForSourceIndex(2); // short-dash
    const b = strokeForSourceIndex(10); // short-dash-heavy
    expect(a.dasharray).toBe(b.dasharray); // same base pattern
    expect(a.name).not.toBe(b.name); // ...but distinct styles
    expect(a.widthMul).toBe(1);
    expect(b.widthMul).toBe(1.75);
  });

  it("assigns 24 distinct styles before any repeat", () => {
    const names = new Set<string>();
    for (let i = 0; i < 24; i++) names.add(strokeForSourceIndex(i).name);
    expect(names.size).toBe(24);
  });

  it("cycles past the catalogue (index 24 wraps to solid — graceful degradation)", () => {
    expect(strokeForSourceIndex(24).name).toBe(strokeForSourceIndex(0).name);
  });

  it("is deterministic across calls (screenshot stability)", () => {
    for (const i of [0, 3, 7, 10, 18, 42]) {
      expect(strokeForSourceIndex(i)).toBe(strokeForSourceIndex(i));
    }
  });
});

// ─── 4. assignSourceStrokes ───────────────────────────────────────────────

describe("assignSourceStrokes", () => {
  it("assigns catalogue names to alphabetically-sorted sources (first = solid)", () => {
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
    const strokes = assignSourceStrokes(g);
    expect(strokes.get("apple")).toBe(strokeForSourceIndex(0).name); // "solid"
    expect(strokes.get("banana")).toBe(strokeForSourceIndex(1).name);
    expect(strokes.get("cherry")).toBe(strokeForSourceIndex(2).name);
  });

  it("returns an empty map when no source has fanout >= 2", () => {
    const g = graph(
      [leaf("a"), leaf("b"), leaf("c1"), leaf("c2")],
      [auxEdge("a", "c1"), auxEdge("b", "c2")],
    );
    expect(assignSourceStrokes(g).size).toBe(0);
  });

  it("styles only multi-fanout sources (single-fanout absent)", () => {
    const g = graph(
      [leaf("multi"), leaf("single"), leaf("c1"), leaf("c2"), leaf("c3")],
      [auxEdge("multi", "c1"), auxEdge("multi", "c2"), auxEdge("single", "c3")],
    );
    const strokes = assignSourceStrokes(g);
    expect(strokes.has("multi")).toBe(true);
    expect(strokes.has("single")).toBe(false);
  });

  it("counts replica edges toward their canonical source (shared resolver)", () => {
    const nodes = [
      leaf("c1"),
      leaf("c2"),
      replica("key-expansion@->c1", "key-expansion"),
      replica("key-expansion@->c2", "key-expansion"),
    ];
    const edges = [
      auxEdge("key-expansion@->c1", "c1", "rk"),
      auxEdge("key-expansion@->c2", "c2", "rk"),
    ];
    const strokes = assignSourceStrokes(graph(nodes, edges));
    // The canonical source gets a single entry (fanout 2), not two synthetic ones.
    expect(strokes.has("key-expansion")).toBe(true);
    expect(strokes.size).toBe(1);
  });

  it("extends past the 8-pattern base tier without repeating (10 sources)", () => {
    // Sources a..j alphabetical; index 8 lands in the heavy tier, distinct
    // from the base-tier index 0 — the anti-cycling property at the map level.
    const strokes = assignSourceStrokes(nSourceGraph(10));
    expect(strokes.size).toBe(10);
    expect(strokes.get("a-src")).toBe(strokeForSourceIndex(0).name); // solid
    expect(strokes.get("i-src")).toBe(strokeForSourceIndex(8).name); // solid-heavy
    expect(strokes.get("i-src")).not.toBe(strokes.get("a-src"));
  });

  it("is deterministic across calls on the same graph", () => {
    const g = nSourceGraph(5);
    const a = assignSourceStrokes(g);
    const b = assignSourceStrokes(g);
    expect([...a.entries()].sort()).toEqual([...b.entries()].sort());
  });

  it("honors the fanout threshold parameter", () => {
    // `big` fanout 3, `mid` fanout 2.
    const g = graph(
      [leaf("big"), leaf("mid"), leaf("c1"), leaf("c2"), leaf("c3"), leaf("c4"), leaf("c5")],
      [
        auxEdge("big", "c1"),
        auxEdge("big", "c2"),
        auxEdge("big", "c3"),
        auxEdge("mid", "c4"),
        auxEdge("mid", "c5"),
      ],
    );
    expect(assignSourceStrokes(g, 3).has("mid")).toBe(false);
    expect(assignSourceStrokes(g, 3).has("big")).toBe(true);
    expect(assignSourceStrokes(g, 2).has("mid")).toBe(true);
  });
});

// ─── 5. strokeForEdge ─────────────────────────────────────────────────────

describe("strokeForEdge", () => {
  it("returns the auto-assigned name for a multi-fanout source", () => {
    const g = graph(
      [leaf("src"), leaf("c1"), leaf("c2")],
      [auxEdge("src", "c1"), auxEdge("src", "c2")],
    );
    const autos = assignSourceStrokes(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(strokeForEdge(edge, g, autos, new Map())).toBe(strokeForSourceIndex(0).name);
  });

  it("manual override wins over the auto style", () => {
    const g = graph(
      [leaf("src"), leaf("c1"), leaf("c2")],
      [auxEdge("src", "c1"), auxEdge("src", "c2")],
    );
    const autos = assignSourceStrokes(g);
    const manual = new Map<string, string>([["src", "long-dash"]]);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(strokeForEdge(edge, g, autos, manual)).toBe("long-dash");
  });

  it("returns undefined for a single-fanout source (caller falls through)", () => {
    const g = graph([leaf("src"), leaf("c1")], [auxEdge("src", "c1")]);
    const autos = assignSourceStrokes(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(strokeForEdge(edge, g, autos, new Map())).toBeUndefined();
  });

  it("returns undefined for an endpoint-pill-sourced edge", () => {
    const g = graph([leaf("a")], [{ from: CIPHER_INPUT_ID, to: "a", auxKey: "in", kind: "state" }]);
    const autos = assignSourceStrokes(g);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(strokeForEdge(edge, g, autos, new Map())).toBeUndefined();
  });

  it("styles a replica's edge by its canonical source", () => {
    const g = graph(
      [leaf("c1"), leaf("c2"), replica("src@->c1", "src"), replica("src@->c2", "src")],
      [auxEdge("src@->c1", "c1"), auxEdge("src@->c2", "c2")],
    );
    const autos = assignSourceStrokes(g);
    const edge0 = g.edges[0];
    const edge1 = g.edges[1];
    if (!edge0 || !edge1) throw new Error("missing edges");
    expect(strokeForEdge(edge0, g, autos, new Map())).toBe(strokeForSourceIndex(0).name);
    expect(strokeForEdge(edge1, g, autos, new Map())).toBe(strokeForSourceIndex(0).name);
  });

  // Sanity: the shared resolver export is the same function source-colors uses.
  it("re-exports resolveCanonicalSource resolving replicas to canonical", () => {
    const g = graph([leaf("c1"), replica("src@->c1", "src")], [auxEdge("src@->c1", "c1")]);
    const edge = g.edges[0];
    if (!edge) throw new Error("missing edge");
    expect(resolveCanonicalSource(edge, g)).toBe("src");
  });
});
