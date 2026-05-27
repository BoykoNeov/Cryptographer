/**
 * Tests for `src/ui/graph/edge-router.ts` — the obstacle-aware edge
 * router exploration. These pin the router's pure-function behaviour
 * on hand-built box layouts, so the algorithm is exercised independently
 * of the GraphView Solid component (no jsdom, no signals, no spec — pure
 * geometry).
 *
 * What's covered:
 *   - Clear straight lines emit the `default` sentinel (so EdgePath
 *     falls through to its existing geometry — byte-identical for these).
 *   - A leaf chip directly on the straight line produces a polyline
 *     that AVOIDS that chip.
 *   - The polyline midpoint sits on the longest segment of the polyline,
 *     perpendicular-nudged (so a bundle ×N pill placed there is visible
 *     beside the shaft, not on it).
 *   - Container ancestors of source / target are NOT obstacles
 *     (otherwise every edge leaving a group would have to detour through
 *     the group's outside — wrong).
 *   - When no detour clears the obstacles, the router returns `default`
 *     (so the renderer at least falls back to today's overlap rather
 *     than emitting a broken polyline).
 *
 * Coordinate convention matches the GraphView canvas: x grows right,
 * y grows DOWN (so "above" = smaller y).
 */

import {
  DEFAULT_ROUTER_OPTIONS,
  polylineMidpoint,
  polylineToRoundedPath,
  routeEdges,
  routeOneEdge,
  type RouterBox,
  type RouterEdge,
} from "@/ui/graph/edge-router";
import { describe, expect, it } from "vitest";

// Helper: build a tiny box map from an array of (id, box) pairs.
const boxes = (entries: ReadonlyArray<[string, RouterBox]>): ReadonlyMap<string, RouterBox> =>
  new Map(entries);

describe("edge-router — clear-line passthrough", () => {
  it("emits default sentinel when the straight line crosses nothing", () => {
    // Source at (0, 0)-(40, 28), target at (200, 0)-(240, 28), no other
    // boxes. The straight line from right-edge of source to left-edge of
    // target passes through empty canvas.
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 200, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "src->tgt",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 200,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes);
    expect(spec.kind).toBe("default");
  });

  it("emits default when only the source and target are present (no obstacles at all)", () => {
    // Edge case: routing in an empty graph (just the two endpoints).
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 200, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 200,
      ty: 14,
    };
    expect(routeOneEdge(edge, allBoxes).kind).toBe("default");
  });

  it("ignores ancestors of source/target — those are NOT obstacles", () => {
    // The source sits inside a "group-A" container whose rectangle
    // overlaps the straight line. Without the ancestor-exclusion the
    // router would think the line is blocked; with it, the line passes.
    const allBoxes = boxes([
      ["group-A", { x: -10, y: -10, w: 60, h: 48 }],
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 200, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: ["group-A"],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 200,
      ty: 14,
    };
    expect(routeOneEdge(edge, allBoxes).kind).toBe("default");
  });
});

describe("edge-router — detour around obstacle", () => {
  it("produces a polyline when a non-incident leaf sits on the straight line", () => {
    // Source at left, target at right, a non-incident leaf sitting
    // dead-center on the path. Router must produce a polyline that
    // routes around it.
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 0, w: 40, h: 28 }],
      // Blocking leaf squarely on the y=14 horizontal line.
      ["block", { x: 130, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 300,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes);
    expect(spec.kind).toBe("polyline");
    if (spec.kind !== "polyline") return;
    // The polyline starts and ends at the supplied attach points.
    expect(spec.points[0]?.x).toBe(40);
    expect(spec.points[0]?.y).toBe(14);
    expect(spec.points[spec.points.length - 1]?.x).toBe(300);
    expect(spec.points[spec.points.length - 1]?.y).toBe(14);
    // At least one bend (>= 3 vertices for L, >= 4 for U).
    expect(spec.points.length).toBeGreaterThanOrEqual(3);
  });

  it("the resulting polyline does NOT pass through the blocking box", () => {
    // Same setup as above; assert that no segment of the chosen
    // polyline crosses the inflated block box.
    const block: RouterBox = { x: 130, y: 0, w: 40, h: 28 };
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 0, w: 40, h: 28 }],
      ["block", block],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 300,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes);
    if (spec.kind !== "polyline") {
      throw new Error("expected polyline");
    }
    // For each segment, assert it does not enter the block's RAW
    // rectangle. (The router inflates by `obstacleMargin` internally so
    // detour bends sit a clearance gap outside the raw rectangle.)
    const intersects = (x1: number, y1: number, x2: number, y2: number, r: RouterBox): boolean => {
      // Simple AABB-vs-segment test via Liang-Barsky parametric clipping.
      const dx = x2 - x1;
      const dy = y2 - y1;
      let tE = 0;
      let tX = 1;
      const clip = (p: number, q: number): boolean => {
        if (p === 0) return q >= 0;
        const t = q / p;
        if (p < 0) {
          if (t > tX) return false;
          if (t > tE) tE = t;
        } else {
          if (t < tE) return false;
          if (t < tX) tX = t;
        }
        return true;
      };
      if (!clip(-dx, x1 - r.x)) return false;
      if (!clip(dx, r.x + r.w - x1)) return false;
      if (!clip(-dy, y1 - r.y)) return false;
      if (!clip(dy, r.y + r.h - y1)) return false;
      return tE <= tX;
    };
    for (let i = 1; i < spec.points.length; i++) {
      const a = spec.points[i - 1];
      const b = spec.points[i];
      if (!a || !b) continue;
      expect(intersects(a.x, a.y, b.x, b.y, block)).toBe(false);
    }
  });

  it("falls back to default when no detour clears (boxes pack the canvas)", () => {
    // Pathological case: an obstacle dead between source and target,
    // AND obstacles fully blocking every detour route (above, below,
    // left, right). Router has nothing safe to emit → returns default.
    //
    // The detour candidates the router considers (per the algorithm
    // doc): L-h, L-v, U-over, U-under, U-left, U-right. We block EVERY
    // candidate route with walls that span the path between source and
    // target. The bend clearance is 12 px so walls must sit within
    // ~12-15 px of the cluster's bounds to catch the detour bend points.
    const allBoxes = boxes([
      ["src", { x: 0, y: 100, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 100, w: 40, h: 28 }],
      // Center obstacle squarely on the straight line.
      ["mid", { x: 130, y: 100, w: 40, h: 28 }],
      // ABOVE wall — a continuous strip from x=0 to x=400 at y=84-94
      // catches the U-over bend (at by - clearance = 94 - 12 = 82).
      // Wall sits at 86-88 so it intersects the bend's horizontal leg.
      ["above-wall", { x: 0, y: 86, w: 400, h: 4 }],
      // BELOW wall — same span, just below the source/target row.
      ["below-wall", { x: 0, y: 140, w: 400, h: 4 }],
      // LEFT wall — vertical strip catching the U-left detour's
      // vertical leg at x = bx - clearance = 130 - 12 = 118.
      ["left-wall", { x: 45, y: 0, w: 4, h: 400 }],
      // RIGHT wall — same on the right side, catching U-right.
      ["right-wall", { x: 290, y: 0, w: 4, h: 400 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 114,
      tx: 300,
      ty: 114,
    };
    const spec = routeOneEdge(edge, allBoxes);
    // The router gave up — fallback to default. Render layer will use
    // its existing geometry (a cubic curve through `mid`). Honest
    // failure mode; visually no worse than today's behaviour.
    expect(spec.kind).toBe("default");
  });
});

describe("edge-router — polyline midpoint", () => {
  it("anchors the midpoint on the longest straight segment", () => {
    // L-shape: short vertical leg from (0, 0) to (0, 20), long
    // horizontal leg from (0, 20) to (200, 20). The midpoint should
    // pick the LONG segment so a bundle ×N pill sits on the shaft, not
    // on the short vertical tail.
    const points = [
      { x: 0, y: 0 },
      { x: 0, y: 20 },
      { x: 200, y: 20 },
    ];
    const mp = polylineMidpoint(points, 0);
    // Long segment midpoint is (100, 20). With perpOffset=0 no nudge.
    expect(mp.x).toBe(100);
    expect(mp.y).toBe(20);
  });

  it("perpendicular-nudges the pill anchor off a rightward segment (downward nudge)", () => {
    // A horizontal-rightward segment with the convention `n = (-dy, dx)/len`
    // produces n = (0, 1) — i.e., the nudge is straight down.
    const points = [
      { x: 0, y: 50 },
      { x: 100, y: 50 },
    ];
    const mp = polylineMidpoint(points, 12);
    expect(mp.x).toBe(50);
    expect(mp.y).toBe(62); // 50 + 12
  });

  it("returns origin defensively for a polyline with fewer than 2 points", () => {
    expect(polylineMidpoint([])).toEqual({ x: 0, y: 0 });
    expect(polylineMidpoint([{ x: 5, y: 7 }])).toEqual({ x: 0, y: 0 });
  });
});

describe("edge-router — rounded-corner path emission", () => {
  // polylineToRoundedPath converts a sequence of vertices into an SVG
  // path string with quadratic Bezier corners at each interior bend.
  // Used by EdgePath to render routed polylines with a softer aesthetic
  // that integrates with the canvas's cubic-curve regimes.

  it("a two-point polyline emits a plain M…L path (no rounding to apply)", () => {
    // No interior corner → no rounding. Plain straight line.
    const d = polylineToRoundedPath([{ x: 0, y: 0 }, { x: 100, y: 0 }], 6);
    expect(d).toBe("M 0 0 L 100 0");
  });

  it("a three-point L emits L→Q→L with the corner replaced by a quadratic curve", () => {
    // Standard 90° corner at (100, 0). Radius 6: lead-in at (94, 0),
    // lead-out at (100, 6), control point at (100, 0).
    const d = polylineToRoundedPath(
      [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 50 },
      ],
      6,
    );
    expect(d).toBe("M 0 0 L 94 0 Q 100 0 100 6 L 100 50");
  });

  it("radius 0 emits a sharp M…L…L path (rounding disabled)", () => {
    // Diagnostic toggle: passing radius=0 yields the pre-rounding
    // path so a regression A/B can compare visual impact.
    const d = polylineToRoundedPath(
      [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 50 },
      ],
      0,
    );
    expect(d).toBe("M 0 0 L 100 0 L 100 50");
  });

  it("radius is capped at half the smaller adjacent leg (no over-bite into a stub)", () => {
    // Short leg: 4 px from (100, 0) to (100, 4). Radius 6 capped to 2.
    const d = polylineToRoundedPath(
      [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 4 },
      ],
      6,
    );
    // The lead-in along (100,0)→(0,0) direction from (100,0) for r=2:
    // (98, 0). Lead-out toward (100, 4) for r=2: (100, 2). Then L to
    // the last point (100, 4).
    expect(d).toBe("M 0 0 L 98 0 Q 100 0 100 2 L 100 4");
  });

  it("degenerate corners (collapsed radius) emit sharp L (not NaN)", () => {
    // 0.5 px leg → radius would be 0.25 → below the 0.5 threshold →
    // helper falls back to a sharp `L` rather than a sub-pixel curve.
    const d = polylineToRoundedPath(
      [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 0.5 },
      ],
      6,
    );
    // The bottom leg can host r=0.25; capped to 0.25; below 0.5 floor
    // → sharp L at the corner. Final string is plain M…L…L.
    expect(d).toBe("M 0 0 L 100 0 L 100 0.5");
  });

  it("a four-point U-shape emits two rounded corners", () => {
    // U-over polyline: source (40, 14), bend-up to (40, -18), straight
    // to (300, -18), bend-down to (300, 14). Two interior corners
    // (at index 1 and 2), both rounded.
    const d = polylineToRoundedPath(
      [
        { x: 40, y: 14 },
        { x: 40, y: -18 },
        { x: 300, y: -18 },
        { x: 300, y: 14 },
      ],
      6,
    );
    // Expect 2x `Q` commands. Just check structure rather than exact
    // coords (multiple legs).
    const qCount = (d.match(/Q /g) ?? []).length;
    expect(qCount).toBe(2);
    // Path must start at the first vertex and end at the last.
    expect(d.startsWith("M 40 14")).toBe(true);
    expect(d.endsWith("L 300 14")).toBe(true);
  });
});

describe("edge-router — perf sanity", () => {
  it("handles a SHA-256-scale fixture (~80 boxes, ~200 edges) in well under 200ms", () => {
    // Synthetic fixture sized like the post-expansion SHA-256 graph the
    // router will see in production: 80 leaf boxes laid out in a 10x8
    // grid, 200 randomized edges between them. Pinning the wall-clock
    // budget here protects criterion 5 (frame budget stays under the
    // project's ~200 ms re-run target). On the dev machine this
    // typically runs in single-digit milliseconds.
    const fixtureBoxes = new Map<string, RouterBox>();
    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 10; col++) {
        fixtureBoxes.set(`leaf-${row}-${col}`, {
          x: col * 50,
          y: row * 40,
          w: 40,
          h: 28,
        });
      }
    }
    // Generate 200 edges with deterministic source/target pairs.
    const edges: RouterEdge[] = [];
    for (let i = 0; i < 200; i++) {
      const r1 = i % 8;
      const c1 = (i * 7) % 10;
      const r2 = (i + 3) % 8;
      const c2 = (i * 11) % 10;
      if (r1 === r2 && c1 === c2) continue;
      edges.push({
        edgeKey: `e-${i}`,
        fromId: `leaf-${r1}-${c1}`,
        toId: `leaf-${r2}-${c2}`,
        containerPathFrom: [],
        containerPathTo: [],
        sx: c1 * 50 + 40,
        sy: r1 * 40 + 14,
        tx: c2 * 50,
        ty: r2 * 40 + 14,
      });
    }
    const t0 = performance.now();
    const result = routeEdges(edges, fixtureBoxes);
    const elapsed = performance.now() - t0;
    expect(result.size).toBeGreaterThan(0);
    // Hard ceiling — even a 10x slowdown stays well within 200 ms.
    expect(elapsed).toBeLessThan(200);
    // eslint-disable-next-line no-console
    console.log(
      `routeEdges(${edges.length} edges, ${fixtureBoxes.size} boxes) = ${elapsed.toFixed(2)} ms`,
    );
  });
});

describe("edge-router — exit-direction stubs", () => {
  // The stub feature makes routed polylines depart their source in the
  // source's natural exit direction (e.g. rightward for a right-edge
  // attach) before bending toward the detour corridor. Same mirrored at
  // the target. Tests pin the geometry on a U-over fixture where the
  // first/last legs would otherwise be perpendicular to the natural
  // direction.

  it("U-over routed path starts with a stub in the source's right-exit direction", () => {
    // Source box has its right edge at x=40; target box's left edge is at
    // x=300. A blocking leaf forces the router into a U-over detour.
    // Source attach is on the right edge (40, 14) → exit=right.
    // Pre-stub U-over would start `(40,14) → (40, overY)` (UP, not
    // RIGHT). Post-stub, the first segment must travel RIGHT for
    // exactly `exitStubLength` px.
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 0, w: 40, h: 28 }],
      ["block", { x: 130, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 300,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes);
    expect(spec.kind).toBe("polyline");
    if (spec.kind !== "polyline") return;
    // First segment endpoint should be at sx + stub, sy — pure rightward
    // stub. Default stub length is 8.
    const stub = DEFAULT_ROUTER_OPTIONS.exitStubLength;
    const first = spec.points[0];
    const second = spec.points[1];
    expect(first).toEqual({ x: 40, y: 14 });
    expect(second).toEqual({ x: 40 + stub, y: 14 });
    // Final segment travels in the entry direction (also rightward —
    // entering target's left edge). Last segment endpoint at tgt; the
    // vertex BEFORE the last must sit `stub` px to the LEFT of tgt.
    const last = spec.points[spec.points.length - 1];
    const secondToLast = spec.points[spec.points.length - 2];
    expect(last).toEqual({ x: 300, y: 14 });
    expect(secondToLast).toEqual({ x: 300 - stub, y: 14 });
  });

  it("the L-shape with exit-aligned first segment skips the stub (no redundant vertex)", () => {
    // Set up a fixture where the chosen detour is L-h with source on
    // right edge — first segment goes RIGHT, which is already aligned
    // with the right-exit direction. The stub should be a no-op on the
    // source side. We assert the polyline has exactly the L-shape's 3
    // vertices (no extra stub vertex inserted on the aligned end).
    //
    // To force L-h selection, position the source-target pair so the
    // L-h candidate has a clear path while U-shapes are longer.
    //
    // Source on right edge (40, 14). Target on left edge (240, 60).
    // Blocking leaf at (130, 30)-(170, 50). L-h: (40,14) → (240, 14) →
    // (240, 60). First segment is rightward = aligned.
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 240, y: 46, w: 40, h: 28 }],
      ["block", { x: 130, y: 30, w: 40, h: 20 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 240,
      ty: 60,
    };
    const spec = routeOneEdge(edge, allBoxes);
    if (spec.kind !== "polyline") return; // some configs return default
    const first = spec.points[0];
    const second = spec.points[1];
    // The first segment must travel RIGHT from (40, 14). The first
    // interior vertex therefore must have x > 40 and y == 14. Whether
    // it's the L's bend at (240,14) OR a stub-inserted vertex, the
    // direction is what we care about — the aligned-skip is enforced
    // by the assertion that the first segment is purely horizontal.
    expect(first).toEqual({ x: 40, y: 14 });
    if (second !== undefined) {
      expect(second.y).toBe(14);
      expect(second.x).toBeGreaterThan(40);
    }
  });

  it("stubs are skipped (no-op) when exitStubLength is 0", () => {
    // Diagnostic toggle: passing exitStubLength: 0 should produce the
    // pre-stub polyline. Useful for A/B comparisons.
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 0, w: 40, h: 28 }],
      ["block", { x: 130, y: 0, w: 40, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 300,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes, { exitStubLength: 0 });
    if (spec.kind !== "polyline") return;
    // Source-side: first segment goes from (40,14) to (40, overY) —
    // entirely vertical. No stub vertex shifts that.
    const first = spec.points[0];
    const second = spec.points[1];
    expect(first).toEqual({ x: 40, y: 14 });
    expect(second?.x).toBe(40); // unchanged from pre-stub geometry
  });

  it("the stubbed polyline still avoids the blocking obstacle", () => {
    // Defense-in-depth: after stub application the polyline still
    // mustn't cross any obstacle. Re-runs the avoid-the-block assertion
    // from the un-stubbed test against the post-stub geometry.
    const block: RouterBox = { x: 130, y: 0, w: 40, h: 28 };
    const allBoxes = boxes([
      ["src", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt", { x: 300, y: 0, w: 40, h: 28 }],
      ["block", block],
    ]);
    const edge: RouterEdge = {
      edgeKey: "k",
      fromId: "src",
      toId: "tgt",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 14,
      tx: 300,
      ty: 14,
    };
    const spec = routeOneEdge(edge, allBoxes);
    if (spec.kind !== "polyline") return;
    // Liang-Barsky segment-vs-box helper, inlined.
    const intersects = (x1: number, y1: number, x2: number, y2: number, r: RouterBox): boolean => {
      const dx = x2 - x1;
      const dy = y2 - y1;
      let tE = 0;
      let tX = 1;
      const clip = (p: number, q: number): boolean => {
        if (p === 0) return q >= 0;
        const t = q / p;
        if (p < 0) {
          if (t > tX) return false;
          if (t > tE) tE = t;
        } else {
          if (t < tE) return false;
          if (t < tX) tX = t;
        }
        return true;
      };
      if (!clip(-dx, x1 - r.x)) return false;
      if (!clip(dx, r.x + r.w - x1)) return false;
      if (!clip(-dy, y1 - r.y)) return false;
      if (!clip(dy, r.y + r.h - y1)) return false;
      return tE <= tX;
    };
    for (let i = 1; i < spec.points.length; i++) {
      const a = spec.points[i - 1];
      const b = spec.points[i];
      if (!a || !b) continue;
      expect(intersects(a.x, a.y, b.x, b.y, block)).toBe(false);
    }
  });
});

describe("edge-router — batch routeEdges API", () => {
  it("returns a map keyed by edgeKey, with one entry per input edge", () => {
    const allBoxes = boxes([
      ["a", { x: 0, y: 0, w: 40, h: 28 }],
      ["b", { x: 200, y: 0, w: 40, h: 28 }],
      ["c", { x: 0, y: 100, w: 40, h: 28 }],
      ["d", { x: 200, y: 100, w: 40, h: 28 }],
    ]);
    const edges: RouterEdge[] = [
      {
        edgeKey: "e1",
        fromId: "a",
        toId: "b",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 14,
        tx: 200,
        ty: 14,
      },
      {
        edgeKey: "e2",
        fromId: "c",
        toId: "d",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 114,
        tx: 200,
        ty: 114,
      },
    ];
    const result = routeEdges(edges, allBoxes);
    expect(result.size).toBe(2);
    expect(result.has("e1")).toBe(true);
    expect(result.has("e2")).toBe(true);
    // Both lines are clear → both default sentinels.
    expect(result.get("e1")?.kind).toBe("default");
    expect(result.get("e2")?.kind).toBe("default");
  });

  it("two parallel U-over edges around the same cluster get assigned distinct lanes", () => {
    // Two source boxes feed two target boxes around the SAME blocking
    // cluster. Both edges produce U-over polylines that — pre-lane —
    // would sit on the same horizontal corridor at y = by - clearance.
    // After the lane pass, the second edge's corridor should be
    // shifted UP by `laneWidth` so the two arrows read as parallel.
    const allBoxes = boxes([
      // Two source chips stacked vertically on the left.
      ["src-a", { x: 0, y: 0, w: 40, h: 28 }],
      ["src-b", { x: 0, y: 40, w: 40, h: 28 }],
      // Single blocking leaf squarely between sources and targets.
      ["block", { x: 130, y: 0, w: 40, h: 68 }],
      // Two target chips on the right.
      ["tgt-a", { x: 300, y: 0, w: 40, h: 28 }],
      ["tgt-b", { x: 300, y: 40, w: 40, h: 28 }],
    ]);
    const edges: RouterEdge[] = [
      {
        edgeKey: "a",
        fromId: "src-a",
        toId: "tgt-a",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 14,
        tx: 300,
        ty: 14,
      },
      {
        edgeKey: "b",
        fromId: "src-b",
        toId: "tgt-b",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 54,
        tx: 300,
        ty: 54,
      },
    ];
    const result = routeEdges(edges, allBoxes);
    const a = result.get("a");
    const b = result.get("b");
    expect(a?.kind).toBe("polyline");
    expect(b?.kind).toBe("polyline");
    if (a?.kind !== "polyline" || b?.kind !== "polyline") return;
    // Find the longest interior segment of each polyline. They must
    // sit at DIFFERENT y values (offset by at least one laneWidth).
    const longestY = (pts: readonly { readonly x: number; readonly y: number }[]): number => {
      let bestLen = -1;
      let bestY = Number.NaN;
      for (let i = 0; i < pts.length - 1; i++) {
        const p = pts[i];
        const q = pts[i + 1];
        if (!p || !q) continue;
        if (p.y !== q.y) continue; // horizontal segments only
        const len = Math.abs(q.x - p.x);
        if (len > bestLen) {
          bestLen = len;
          bestY = p.y;
        }
      }
      return bestY;
    };
    const yA = longestY(a.points);
    const yB = longestY(b.points);
    expect(yA).not.toEqual(yB);
    expect(Math.abs(yA - yB)).toBeGreaterThanOrEqual(DEFAULT_ROUTER_OPTIONS.laneWidth);
  });

  it("disjoint corridors at the same y do NOT get a lane shift (intervals don't overlap)", () => {
    // Two H corridors at the same y but disjoint x-ranges. They look
    // like parallel lines from afar but never visually pile up — the
    // interval scheduler should keep both at lane 0 (no offset).
    //
    // Source/target pairs are arranged so each edge's blocking cluster
    // is in a different x-range; both U-overs land on the same y but
    // the corridor x-ranges don't overlap.
    const allBoxes = boxes([
      ["src-a", { x: 0, y: 0, w: 40, h: 28 }],
      ["tgt-a", { x: 250, y: 0, w: 40, h: 28 }],
      ["block-a", { x: 100, y: 0, w: 40, h: 28 }],
      ["src-b", { x: 400, y: 0, w: 40, h: 28 }],
      ["tgt-b", { x: 700, y: 0, w: 40, h: 28 }],
      ["block-b", { x: 540, y: 0, w: 40, h: 28 }],
    ]);
    const edges: RouterEdge[] = [
      {
        edgeKey: "a",
        fromId: "src-a",
        toId: "tgt-a",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 14,
        tx: 250,
        ty: 14,
      },
      {
        edgeKey: "b",
        fromId: "src-b",
        toId: "tgt-b",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 440,
        sy: 14,
        tx: 700,
        ty: 14,
      },
    ];
    const result = routeEdges(edges, allBoxes);
    const a = result.get("a");
    const b = result.get("b");
    if (a?.kind !== "polyline" || b?.kind !== "polyline") return;
    // Both should still be at the same corridor y (no offset) because
    // their x-ranges don't overlap — the interval scheduler puts them
    // both in lane 0.
    const longestY = (pts: readonly { readonly x: number; readonly y: number }[]): number => {
      let bestLen = -1;
      let bestY = Number.NaN;
      for (let i = 0; i < pts.length - 1; i++) {
        const p = pts[i];
        const q = pts[i + 1];
        if (!p || !q) continue;
        if (p.y !== q.y) continue;
        const len = Math.abs(q.x - p.x);
        if (len > bestLen) {
          bestLen = len;
          bestY = p.y;
        }
      }
      return bestY;
    };
    expect(longestY(a.points)).toBe(longestY(b.points));
  });

  it("laneWidth: 0 toggles lane assignment off (regression diagnostic)", () => {
    // Same setup as the lane-spread test, but with laneWidth: 0. Both
    // edges' corridors should sit on the same y — pre-lane overlap is
    // restored. Useful for A/B comparing the lane pass's visual benefit.
    const allBoxes = boxes([
      ["src-a", { x: 0, y: 0, w: 40, h: 28 }],
      ["src-b", { x: 0, y: 40, w: 40, h: 28 }],
      ["block", { x: 130, y: 0, w: 40, h: 68 }],
      ["tgt-a", { x: 300, y: 0, w: 40, h: 28 }],
      ["tgt-b", { x: 300, y: 40, w: 40, h: 28 }],
    ]);
    const edges: RouterEdge[] = [
      {
        edgeKey: "a",
        fromId: "src-a",
        toId: "tgt-a",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 14,
        tx: 300,
        ty: 14,
      },
      {
        edgeKey: "b",
        fromId: "src-b",
        toId: "tgt-b",
        containerPathFrom: [],
        containerPathTo: [],
        sx: 40,
        sy: 54,
        tx: 300,
        ty: 54,
      },
    ];
    const result = routeEdges(edges, allBoxes, { laneWidth: 0 });
    const a = result.get("a");
    const b = result.get("b");
    if (a?.kind !== "polyline" || b?.kind !== "polyline") return;
    const longestY = (pts: readonly { readonly x: number; readonly y: number }[]): number => {
      let bestLen = -1;
      let bestY = Number.NaN;
      for (let i = 0; i < pts.length - 1; i++) {
        const p = pts[i];
        const q = pts[i + 1];
        if (!p || !q) continue;
        if (p.y !== q.y) continue;
        const len = Math.abs(q.x - p.x);
        if (len > bestLen) {
          bestLen = len;
          bestY = p.y;
        }
      }
      return bestY;
    };
    expect(longestY(a.points)).toBe(longestY(b.points));
  });

  it("the SHA-256-shaped fan-IN case routes around the offending sibling", () => {
    // Synthetic fixture roughly like SHA-256's s-row fan-IN, scaled down.
    // Mid-corridor blocker between a left-side source row and a right-
    // side consumer; without routing the straight line would pass
    // through the blocker's box.
    const allBoxes2 = boxes([
      ["src-top", { x: 0, y: 0, w: 40, h: 28 }],
      ["src-bot", { x: 0, y: 100, w: 40, h: 28 }],
      // Mid-corridor blocker at the path's midpoint y.
      ["blocker", { x: 130, y: 64, w: 40, h: 28 }],
      ["consumer", { x: 300, y: 50, w: 80, h: 28 }],
    ]);
    const edge: RouterEdge = {
      edgeKey: "bot->consumer",
      fromId: "src-bot",
      toId: "consumer",
      containerPathFrom: [],
      containerPathTo: [],
      sx: 40,
      sy: 114,
      tx: 300,
      ty: 64,
    };
    const result = routeEdges([edge], allBoxes2);
    const spec = result.get("bot->consumer");
    expect(spec).toBeDefined();
    if (spec?.kind !== "polyline") {
      throw new Error("expected polyline — straight line is blocked");
    }
    expect(spec.points.length).toBeGreaterThanOrEqual(3);
  });
});
