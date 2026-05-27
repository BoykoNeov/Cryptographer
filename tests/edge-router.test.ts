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
  type RouterBox,
  type RouterEdge,
  polylineMidpoint,
  routeEdges,
  routeOneEdge,
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
