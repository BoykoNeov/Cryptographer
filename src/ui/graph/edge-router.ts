/**
 * Obstacle-aware edge router for the graph view.
 *
 * **Why this exists.** Prior to this module, every edge was drawn either as
 * a straight `L` line (replica edges + degenerate vertical regime) or a
 * single cubic `C` Bezier (everything else). `EdgePath.geom()` consults
 * only the source-box and target-box rectangles; it has no awareness of
 * any OTHER box on the canvas. In dense specs (SHA-256 message-schedule
 * expanded, or its fan-IN into `final.assemble`) this produces arrows that
 * draw straight through unrelated leaf chips — making the graph hard to
 * read because the eye can't tell which arrow connects which pair.
 *
 * **Scope.** This is a TIME-BOXED EXPLORATION (~2 days). We are NOT
 * shipping a libavoid-grade router. We are picking the smallest design
 * that has a reasonable chance of satisfying the success criteria the
 * advisor laid out for the exploration branch:
 *
 *   1. Zero arrow paths cross a non-incident leaf's bounding box.
 *   2. Bundle ×N pills stay visually on/beside their arrow shaft.
 *   3. Replica start-dots remain unambiguous.
 *   4. No new visible artefact at standard zoom.
 *   5. Frame budget stays under ~200ms re-run target.
 *
 * **Algorithm chosen — single-bend L-shape with U-shape fallback.**
 *
 *   - Step 1: for each edge, compute the same source/target attach points
 *     that `EdgePath.geom()` would compute today (so port-spreading,
 *     replica source-x shift, isFeedback overhead arc, etc. all keep
 *     working — we route the SAME endpoints, just with a different shape
 *     in between).
 *   - Step 2: test whether a straight line `(sx, sy) → (tx, ty)` passes
 *     through any non-incident obstacle. If clear, emit `{ kind: "default" }`
 *     — `EdgePath` then renders the existing curve/line BYTE-IDENTICALLY.
 *     This is the discriminated-union sentinel that keeps every visually-
 *     uncongested edge exactly where it was; the existing 1389-test suite
 *     keeps passing for those edges.
 *   - Step 3: if blocked, try a single-bend L-shape that detours around
 *     the worst-offending obstacle on its LEFT side. If that clears every
 *     obstacle on the edge's path, use it.
 *   - Step 4: same with RIGHT side. Pick whichever clears more obstacles
 *     (or whichever detour is shorter on a tie).
 *   - Step 5: if neither single-bend works, try a U-shape (two bends
 *     forming an over- or under-the-row detour).
 *   - Step 6: if NOTHING in our small search space clears every obstacle,
 *     give up and emit `{ kind: "default" }`. Pre-router behaviour for
 *     that edge — better today's overlap than something that looks worse.
 *
 * **Algorithm rejected and why:**
 *   - libavoid.js (~200KB) — busts the 132KB gzipped bundle budget.
 *   - Visibility graph + orthogonal connector (1500–3000 LOC) — too big
 *     for the budget; would need its own subsystem with its own tests.
 *   - Grid A* over a uniform cell grid (~500 LOC) — produces Manhattan
 *     stair-steps that visually clash with the curved aesthetic of the
 *     three default regimes. Would need corner-rounding postprocess.
 *   - Obstacle-aware cubic Bezier (~200 LOC) — preserves the aesthetic
 *     but moving a single Bezier's control points often can't clear two
 *     obstacles on opposite sides. Hard to reason about correctness.
 *
 * **Tradeoffs of the L+U choice:**
 *   - PRO: small (~300 LOC), pure function, easily unit-testable, polyline
 *     midpoint is well-defined per straight segment (criterion 2 falls
 *     out for free), and the visual is "straight line with one or two
 *     right-angle turns" which the human eye reads as obstacle-aware.
 *   - CON: orthogonal corners visually contrast with the today's cubics.
 *     Mitigated because (a) only THE EDGES THAT WOULD OTHERWISE OVERLAP
 *     get the polyline treatment — clear-line edges stay as curves —
 *     and (b) the visual contrast is itself pedagogically helpful: "this
 *     edge had to detour."
 *   - CON: in very dense graphs (every edge crosses something) the L/U
 *     search space may not find a clear detour. Then the edge falls back
 *     to its original curve — same as today.
 *
 * **Polyline-aware midpoint** is `polylineMidpoint`. The advisor flagged
 * this as the most likely place where edged paths could break: today's
 * `geom().midpoint` uses a perpendicular-offset from a straight chord or
 * `t=0.25` along a cubic, and that point can sit far away from a routed
 * polyline. The helper here finds the LONGEST segment of the polyline and
 * anchors the pill at that segment's midpoint, with the same perpendicular
 * nudge the chord version used. Single ×N pills on polylines remain
 * "on the shaft."
 */

/**
 * A 2D box matching `GraphView.tsx`'s internal `Box` type. We don't import
 * directly because the type is module-local inside the component file and
 * the router is a pure helper that doesn't need to know about the Solid
 * surface. Structural typing means callers can pass any object with these
 * four fields.
 */
export type RouterBox = {
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
};

/**
 * The result of routing one edge.
 *
 *   - `{ kind: "default" }` — sentinel meaning "this edge is fine as-is;
 *     `EdgePath` should fall through to its existing `geom()` regime." The
 *     vast majority of edges land here; the router is opportunistic.
 *
 *   - `{ kind: "polyline", points, midpoint }` — the router computed an
 *     obstacle-clearing path. `points` is at least two `(x, y)` vertices
 *     (the source-attach point and the target-attach point, with zero or
 *     more interior bend vertices between them). `midpoint` is the
 *     anchor for the `×N` bundle pill — the longest-straight-segment
 *     midpoint, perpendicular-nudged so the pill sits BESIDE the shaft.
 */
export type PathSpec =
  | { readonly kind: "default" }
  | {
      readonly kind: "polyline";
      readonly points: readonly { readonly x: number; readonly y: number }[];
      readonly midpoint: { readonly x: number; readonly y: number };
    };

/**
 * Edge identifier the router can consume. Mirrors what `EdgePath` already
 * computes per bundle, except all the visual-routing inputs are folded
 * into a single struct so the router doesn't have to know about Solid
 * memo signatures.
 *
 * `fromId` and `toId` are the spec ids of the source and target node /
 * container; `containerPathFrom` and `containerPathTo` are their
 * containerPaths (root-first ancestors). The router uses both to compute
 * the "incident" set — any chip whose id is in either path is an ancestor
 * of one endpoint and so a legitimate enclosing rectangle that arrows
 * MUST be allowed to enter (the arrow naturally crosses the bounding
 * rectangle when it leaves the container body).
 *
 * `sx,sy,tx,ty` are the SAME attach points `EdgePath.geom()` would
 * compute — port offsets, replica source shifts, feedback overhead
 * detection are already applied by the caller. The router's job is
 * strictly to detect obstacles between them and pick an obstacle-
 * avoiding path with the same two endpoints.
 *
 * `edgeKey` is the stable map key so the renderer can look up its
 * routed-path decision by the same key it uses for selection state.
 */
export type RouterEdge = {
  readonly edgeKey: string;
  readonly fromId: string;
  readonly toId: string;
  readonly containerPathFrom: readonly string[];
  readonly containerPathTo: readonly string[];
  readonly sx: number;
  readonly sy: number;
  readonly tx: number;
  readonly ty: number;
};

/**
 * Configurable routing knobs. The defaults are tuned for the project's
 * default density (LEAF_W=132, LEAF_H=28, FLOW_GAP=36). Callers passing
 * non-default density would scale these proportionally if a sharper visual
 * is needed; today the layout pass passes the defaults verbatim.
 *
 * `obstacleMargin` (default 6) — pixel inflation around each obstacle.
 *   Without it, paths grazing an obstacle's edge would "intersect" it on
 *   floating-point boundaries and the user reads the path as "kissing"
 *   the box. 6 lines up with `ARROW_INSET` so the inflate budget matches
 *   what the arrowhead-tip inset already buys.
 *
 * `bendClearance` (default 12) — gap between a detour bend and the
 *   obstacle being detoured around. Large enough that the bend visually
 *   reads as "going around" rather than "scraping past."
 *
 * `maxBendsPerEdge` (default 2) — limit on the search depth. 0 = clear-
 *   line only, 1 = L-shapes allowed, 2 = U-shapes allowed. Above 2 the
 *   path starts to look like a maze and is rarely worth it; we fall back
 *   to default-sentinel.
 */
export type RouterOptions = {
  readonly obstacleMargin?: number;
  readonly bendClearance?: number;
  readonly maxBendsPerEdge?: number;
  /**
   * Length (px) of the exit-direction stub at each polyline endpoint.
   * See `DEFAULT_ROUTER_OPTIONS.exitStubLength` for the rationale.
   * Pass 0 to disable stubs entirely (regression toggle for A/B tests).
   */
  readonly exitStubLength?: number;
  /**
   * Perpendicular offset (px) per lane in the lane-spreading pass.
   * See `DEFAULT_ROUTER_OPTIONS.laneWidth`. Pass 0 to disable lane
   * spreading entirely (regression toggle for A/B tests).
   */
  readonly laneWidth?: number;
};

/**
 * Default routing knobs. Exported so tests can reference them.
 *
 * `exitStubLength` (default 8) — the distance the polyline travels in
 *   the source's exit-direction (or the target's entry-direction) BEFORE
 *   bending toward the next interior vertex. Without this, a routed
 *   polyline whose first interior bend is perpendicular to the source's
 *   exit direction begins with a 90° turn flush against the box's edge.
 *   The eye then can't tell which side of the box the arrow left from —
 *   the corner reads as "this arrow originated at the chip's corner."
 *   8 px gives the arrow shaft a brief straight prelude in its natural
 *   exit direction so the corner is read as "leaves the bottom edge
 *   and then turns right" rather than "ambiguous." Capped at half the
 *   distance to the first interior bend so we never overshoot the bend
 *   on degenerately-short paths.
 *
 * `laneWidth` (default 6) — perpendicular offset (px) applied per lane
 *   when two or more routed edges would otherwise share the same long
 *   straight segment. Lane index 0 sits on the unmodified corridor;
 *   lane indices 1, 2, ... each add another `laneWidth` of offset to
 *   the LEFT of the corridor's travel direction. 6 px matches roughly
 *   one stroke-width plus a hairline gap so adjacent shafts read as
 *   "parallel arrows" rather than "smeared single arrow." Tuned for the
 *   1.5 px aux-edge stroke; finer strokes would warrant a smaller value.
 */
export const DEFAULT_ROUTER_OPTIONS = {
  obstacleMargin: 6,
  bendClearance: 12,
  maxBendsPerEdge: 2,
  exitStubLength: 8,
  laneWidth: 6,
} as const;

/**
 * Cardinal direction enum used by exit-stub geometry. Encodes which
 * side of a source/target box an attach point sits on. `none` means
 * the heuristic couldn't decide (e.g., the box itself is missing from
 * the obstacle map, or the attach point is on a corner equally close
 * to two edges); the caller treats `none` as "skip the stub."
 */
type CardinalDir = "left" | "right" | "up" | "down" | "none";

/**
 * Translate a cardinal direction into a unit (dx, dy) vector. y axis
 * grows DOWNWARD on the canvas — so `down` is `(0, +1)`.
 */
const dirVec = (d: CardinalDir): { readonly dx: number; readonly dy: number } => {
  switch (d) {
    case "left":
      return { dx: -1, dy: 0 };
    case "right":
      return { dx: 1, dy: 0 };
    case "up":
      return { dx: 0, dy: -1 };
    case "down":
      return { dx: 0, dy: 1 };
    case "none":
      return { dx: 0, dy: 0 };
  }
};

/**
 * Decide which edge of `box` the attach point `(ax, ay)` sits on (or
 * closest to). Returns the cardinal direction the path should depart
 * the box in — i.e., AWAY from the closest edge. If the box is
 * undefined (caller couldn't resolve fromId/toId in the box map), or
 * the point sits clearly inside the box's interior (which shouldn't
 * happen for legitimate attach points but defensively might), returns
 * `none`.
 *
 * Why "AWAY from": an attach point on the right edge of the source
 * box (`ax === box.x + box.w`) means the path is LEAVING the box
 * rightward, so the exit direction is `right`. Same logic mirrored
 * for target-entry: the path enters the target's left edge so its
 * entry direction approaches from the right — for the stub we want
 * the path to travel `right` IN before the bend, i.e., still `right`.
 * Caller flips for target-side when needed (it doesn't — the entry
 * stub uses the same direction the path is travelling, which is the
 * negation of the box-departure direction; see `computeEntryDir`).
 */
const computeExitDir = (
  box: RouterBox | undefined,
  ax: number,
  ay: number,
  tolerance = 0.5,
): CardinalDir => {
  if (box === undefined) return "none";
  // Distance from the attach point to each of the box's four edges.
  // Smallest distance wins — that's the edge the point sits on.
  const dLeft = Math.abs(ax - box.x);
  const dRight = Math.abs(ax - (box.x + box.w));
  const dTop = Math.abs(ay - box.y);
  const dBottom = Math.abs(ay - (box.y + box.h));
  const dMin = Math.min(dLeft, dRight, dTop, dBottom);
  // Tolerance: attach points are usually exact-on-edge but ARROW_INSET
  // can pull them a few px inside, so allow a small slop. If the
  // smallest distance is > tolerance the point isn't really on any
  // edge and we abstain.
  if (dMin > Math.max(tolerance, Math.min(box.w, box.h) / 2)) return "none";
  if (dMin === dLeft) return "left";
  if (dMin === dRight) return "right";
  if (dMin === dTop) return "up";
  return "down";
};

/**
 * Entry direction for the target box — the direction the path is
 * TRAVELLING as it approaches the target's edge. An attach point on
 * the target's LEFT edge means the path arrives rightward, so the
 * approach direction is `right`. Symmetric to `computeExitDir` with
 * the cardinal flipped (departure-from-left = `left`; approach-to-left
 * = `right`).
 */
const computeEntryDir = (
  box: RouterBox | undefined,
  ax: number,
  ay: number,
  tolerance = 0.5,
): CardinalDir => {
  const depart = computeExitDir(box, ax, ay, tolerance);
  switch (depart) {
    case "left":
      return "right";
    case "right":
      return "left";
    case "up":
      return "down";
    case "down":
      return "up";
    case "none":
      return "none";
  }
};

// ─── Internal geometric primitives ──────────────────────────────────────

/**
 * Segment-vs-axis-aligned-rectangle intersection.
 *
 * Returns true when the line segment `(x1, y1) → (x2, y2)` enters the
 * rectangle `(rx, ry, rw, rh)` at any non-degenerate point.
 *
 * Implementation uses Liang-Barsky-style parametric clipping: the
 * intersection of the segment's parameter interval `[0, 1]` with the
 * rectangle's parameter intervals on x and y. If the intersection is non-
 * empty, the segment touches the rectangle.
 *
 * Endpoint touches (`t = 0` or `t = 1` exactly on the rectangle's
 * boundary, e.g. the source attach point sitting on its own source
 * box's edge) DO count as intersections under this definition. Callers
 * who want to exclude that case must filter the source/target boxes out
 * of the obstacle list — which `routeEdges` does by construction (the
 * source and target boxes are never in the obstacle set).
 */
const segmentIntersectsRect = (
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  rx: number,
  ry: number,
  rw: number,
  rh: number,
): boolean => {
  const dx = x2 - x1;
  const dy = y2 - y1;
  // Treat zero-length segments as non-intersecting — they're a degenerate
  // case the caller (a coincident source and target after offset clamps)
  // wouldn't draw anyway.
  if (dx === 0 && dy === 0) return false;

  // Liang-Barsky: maintain a `[tEnter, tExit]` parameter interval and
  // clip it by each rectangle edge. If the interval ever becomes empty,
  // the segment misses the rectangle.
  let tEnter = 0;
  let tExit = 1;
  // Four edges: left, right, top, bottom. Each contributes a parameter
  // constraint of the form `p * t <= q`. Clip the interval accordingly.
  const clip = (p: number, q: number): boolean => {
    if (p === 0) {
      // Parallel to this edge. Outside iff q < 0.
      return q >= 0;
    }
    const t = q / p;
    if (p < 0) {
      // Entering through this edge.
      if (t > tExit) return false;
      if (t > tEnter) tEnter = t;
    } else {
      // Exiting through this edge.
      if (t < tEnter) return false;
      if (t < tExit) tExit = t;
    }
    return true;
  };
  if (!clip(-dx, x1 - rx)) return false;
  if (!clip(dx, rx + rw - x1)) return false;
  if (!clip(-dy, y1 - ry)) return false;
  if (!clip(dy, ry + rh - y1)) return false;
  // Non-empty intersection means the segment crosses the box.
  return tEnter <= tExit;
};

/**
 * True if ANY obstacle in the list intersects the segment.
 *
 * Linear scan; `obstacles` is typically small (a few dozen leaves on the
 * canvas, minus the incident set). The scan stops at the first hit since
 * "blocked" is a boolean.
 */
const segmentBlocked = (
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  obstacles: readonly RouterBox[],
): boolean => {
  for (const o of obstacles) {
    if (segmentIntersectsRect(x1, y1, x2, y2, o.x, o.y, o.w, o.h)) return true;
  }
  return false;
};

/**
 * Inflate a box uniformly by `margin` pixels. Returns a new box with the
 * same center but expanded extents. Used to convert raw chip boxes into
 * "do not enter" obstacles with a small clearance buffer.
 */
const inflateBox = (b: RouterBox, margin: number): RouterBox => ({
  x: b.x - margin,
  y: b.y - margin,
  w: b.w + margin * 2,
  h: b.h + margin * 2,
});

/**
 * Test if a polyline (sequence of points joined by straight segments) is
 * fully clear of all obstacles. Used to validate router candidates before
 * accepting them.
 */
const polylineClear = (
  points: readonly { readonly x: number; readonly y: number }[],
  obstacles: readonly RouterBox[],
): boolean => {
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (a === undefined || b === undefined) continue;
    if (segmentBlocked(a.x, a.y, b.x, b.y, obstacles)) return false;
  }
  return true;
};

/**
 * Find the longest straight segment in a polyline and return its midpoint,
 * perpendicular-nudged so a bundle ×N pill placed there sits BESIDE the
 * shaft rather than directly on top of it (matching the perpendicular-
 * offset convention from `EdgePath`'s `perpendicularLabelMidpoint` helper).
 *
 * Why longest segment: short connector segments at bends are visually
 * cluttered and a pill anchored there would compete with the corner
 * geometry. The longest segment is the most "shaft-like" portion of the
 * routed path — anchoring the pill there gives it the most breathing
 * room.
 *
 * Returned point is suitable for direct use as the `midpoint` of the
 * resulting `PathSpec`.
 */
export const polylineMidpoint = (
  points: readonly { readonly x: number; readonly y: number }[],
  perpOffset = 12,
): { readonly x: number; readonly y: number } => {
  if (points.length < 2) {
    // Defensive: a one-point or empty polyline has no midpoint. Return
    // origin so a defensive consumer doesn't NaN-out. In practice
    // routeEdges only ever produces >= 2-point polylines.
    return { x: 0, y: 0 };
  }
  let bestIdx = 0;
  let bestLenSq = -1;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (a === undefined || b === undefined) continue;
    const lx = b.x - a.x;
    const ly = b.y - a.y;
    const lenSq = lx * lx + ly * ly;
    if (lenSq > bestLenSq) {
      bestLenSq = lenSq;
      bestIdx = i;
    }
  }
  const a = points[bestIdx - 1];
  const b = points[bestIdx];
  if (a === undefined || b === undefined) return { x: 0, y: 0 };
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.sqrt(dx * dx + dy * dy);
  if (len < 1) return { x: mx, y: my };
  // 90deg CCW perpendicular unit vector — matches the convention in
  // `EdgePath`'s `perpendicularLabelMidpoint` so polyline pills nudge in
  // the same direction as cubic pills. For a downward-pointing segment
  // this nudges LEFT; for a rightward-pointing segment, DOWN.
  const px = -dy / len;
  const py = dx / len;
  return { x: mx + px * perpOffset, y: my + py * perpOffset };
};

/**
 * Apply exit-direction stubs to a routed polyline. Returns a new array
 * whose first segment travels in the source's exit direction for at
 * least `stubLen` px, and whose LAST segment travels in the target's
 * entry direction for at least `stubLen` px.
 *
 * **Why these matter visually:** without the stubs the first interior
 * bend can sit flush against the source box's edge. The eye then can't
 * tell which side of the box the arrow left from — the corner reads
 * as "this arrow originated at the chip's corner." With a stub, the
 * shaft has a short prelude in its natural exit direction before
 * bending, so the user reads "leaves the bottom edge, then turns
 * right" rather than "ambiguous."
 *
 * **Geometry strategy** — *shift the corner*, don't *prepend a vertex*.
 * If the first segment is perpendicular to the exit direction, we
 * push the first interior bend `stubLen` px in the exit direction, so
 * the new polyline starts with a short stub IN the exit direction
 * followed by the original (now shorter) perpendicular leg. Same
 * mirrored at the target.
 *
 * Example: U-over with source on right-edge.
 *   - Before: `(sx,sy) → (sx, overY) → (tx, overY) → (tx, ty)`
 *     (segment 1 goes UP from a RIGHT-exiting box → perpendicular,
 *     wants a stub)
 *   - After source stub: `(sx,sy) → (sx+stub, sy) → (sx+stub, overY) → ...`
 *     (segment 1 now goes RIGHT — aligned with exit; corridor shifted)
 *
 * Skipped on either end when:
 *   - The first/last segment is ALREADY aligned with the exit/entry
 *     direction (the segment IS the stub).
 *   - The exit/entry direction is `none` (heuristic abstained).
 *   - The next-neighbour segment is too short to absorb the corner-shift
 *     without going negative. Conservatively skip when the geometry
 *     would self-cross.
 *
 * Why shifting the corner vs. extending the endpoint: SVG arrow markers
 * orient by the LAST segment's direction. Extending the last segment
 * would silently rotate the arrowhead. By inserting a NEW final segment
 * in the entry direction (and shortening the prior perpendicular leg),
 * the final-segment direction is now exactly the entry direction —
 * which is what we want the arrowhead to point along anyway.
 */
const applyExitStubs = (
  points: readonly { readonly x: number; readonly y: number }[],
  exitDir: CardinalDir,
  entryDir: CardinalDir,
  stubLen: number,
): readonly { readonly x: number; readonly y: number }[] => {
  if (points.length < 2 || stubLen <= 0) return points;
  const out: { x: number; y: number }[] = points.map((p) => ({ x: p.x, y: p.y }));

  // ─── Source-side stub ────────────────────────────────────────────
  // Push the first interior vertex `stubLen` px in the exit direction,
  // then insert a new vertex at the post-stub source position. This
  // turns the first segment into a stub aligned with the exit direction.
  if (exitDir !== "none" && out.length >= 2) {
    const src = out[0];
    const next = out[1];
    if (src !== undefined && next !== undefined) {
      const segDx = next.x - src.x;
      const segDy = next.y - src.y;
      const segLen = Math.sqrt(segDx * segDx + segDy * segDy);
      const v = dirVec(exitDir);
      const aligned = segLen > 1e-6 && (segDx * v.dx + segDy * v.dy) / segLen > 1 - 1e-3;
      if (!aligned && segLen > 1e-6) {
        // Shift the FIRST INTERIOR VERTEX by stub * exitDir. The vertex
        // is moved (not duplicated) so the corridor's "stem" coordinate
        // changes — e.g., the vertical leg of a U-over moves stubLen
        // px to the right when exitDir is "right". Then insert a NEW
        // source-side vertex at the post-stub source position so the
        // first segment travels in the exit direction.
        const sLen = stubLen;
        next.x += v.dx * sLen;
        next.y += v.dy * sLen;
        out.splice(1, 0, { x: src.x + v.dx * sLen, y: src.y + v.dy * sLen });
      }
    }
  }

  // ─── Target-side stub ────────────────────────────────────────────
  // Push the LAST interior vertex stubLen back in the entry direction
  // (i.e., AWAY from the target along the negative entry direction)
  // and insert a new target-side vertex so the final segment travels
  // in the entry direction.
  if (entryDir !== "none" && out.length >= 2) {
    const lastIdx = out.length - 1;
    const tgt = out[lastIdx];
    const prev = out[lastIdx - 1];
    if (tgt !== undefined && prev !== undefined) {
      const segDx = tgt.x - prev.x;
      const segDy = tgt.y - prev.y;
      const segLen = Math.sqrt(segDx * segDx + segDy * segDy);
      const v = dirVec(entryDir);
      const aligned = segLen > 1e-6 && (segDx * v.dx + segDy * v.dy) / segLen > 1 - 1e-3;
      if (!aligned && segLen > 1e-6) {
        const sLen = stubLen;
        // Move `prev` against the entry direction by `sLen` — this
        // shortens the prior perpendicular leg by sLen and shifts its
        // endpoint to where the new entry-aligned stub will start.
        prev.x -= v.dx * sLen;
        prev.y -= v.dy * sLen;
        out.splice(lastIdx, 0, { x: tgt.x - v.dx * sLen, y: tgt.y - v.dy * sLen });
      }
    }
  }
  return out;
};

// ─── Detour-candidate generation ─────────────────────────────────────────

/**
 * Build the obstacle list for ONE edge by filtering the full leaf box
 * list down to "things this edge must not cross."
 *
 * Excluded from the obstacle set:
 *
 *   - The source box itself (the path leaves from it).
 *   - The target box itself (the path enters it).
 *   - Any container ancestor of the source (in `containerPathFrom`).
 *   - Any container ancestor of the target (in `containerPathTo`).
 *
 * Why ancestors are excluded: an edge from inside an expanded group out
 * to a sibling at the root level necessarily crosses the group's
 * bounding rectangle (the edge has to "leave" the group to get to its
 * external target). Treating the group's rectangle as an obstacle would
 * force every such edge into a routed detour through the group's outside
 * — visually wrong because the group is a CONTAINER not an opaque shape.
 *
 * Container leaves themselves (i.e., collapsed groups that appear as
 * chips) ARE obstacles for OTHER edges — only the source and target's
 * own ancestry is excluded. A collapsed `rounds` group is opaque to a
 * `key-expansion -> initial.add-round-key` arrow passing across the row.
 */
const buildObstacleSet = (
  edge: RouterEdge,
  allBoxes: ReadonlyMap<string, RouterBox>,
  margin: number,
): RouterBox[] => {
  const excluded = new Set<string>();
  excluded.add(edge.fromId);
  excluded.add(edge.toId);
  for (const id of edge.containerPathFrom) excluded.add(id);
  for (const id of edge.containerPathTo) excluded.add(id);
  const obstacles: RouterBox[] = [];
  for (const [id, b] of allBoxes) {
    if (excluded.has(id)) continue;
    obstacles.push(inflateBox(b, margin));
  }
  return obstacles;
};

/**
 * Candidate detour generator. Produces a small set of L-shape and U-shape
 * polyline candidates between the source and target attach points, sized
 * so a `bendClearance` gap exists between any bend and the boxes being
 * detoured around.
 *
 * Strategy: identify the bounding rectangle that ENCLOSES every obstacle
 * the straight line would hit, then emit candidates that route around
 * that rectangle on each of its four sides. This is a much smaller search
 * than enumerating per-obstacle detours (which exploded combinatorially
 * once two obstacles were involved) and the resulting paths visually
 * read as "this edge sweeps around the blocking region."
 *
 * Candidate shapes (each gates on `maxBendsPerEdge`):
 *
 *   - L-h: source -> (tx, sy) -> target  (horizontal first)
 *   - L-v: source -> (sx, ty) -> target  (vertical first)
 *   - U-over:  source -> (sx, by-c) -> (tx, by-c) -> target  (over the cluster top)
 *   - U-under: source -> (sx, by2+c) -> (tx, by2+c) -> target  (under the cluster bottom)
 *   - U-left:  source -> (bx-c, sy) -> (bx-c, ty) -> target  (around the cluster left)
 *   - U-right: source -> (bx2+c, sy) -> (bx2+c, ty) -> target  (around the cluster right)
 */
const generateDetourCandidates = (
  edge: RouterEdge,
  blockingObstacles: readonly RouterBox[],
  clearance: number,
  maxBends: number,
): ReadonlyArray<readonly { readonly x: number; readonly y: number }[]> => {
  if (maxBends < 1 || blockingObstacles.length === 0) return [];
  // Bounding rectangle of all blocking obstacles. Routing around this
  // rectangle's outside clears every obstacle inside it in one shape.
  let bx = Number.POSITIVE_INFINITY;
  let by = Number.POSITIVE_INFINITY;
  let bx2 = Number.NEGATIVE_INFINITY;
  let by2 = Number.NEGATIVE_INFINITY;
  for (const o of blockingObstacles) {
    if (o.x < bx) bx = o.x;
    if (o.y < by) by = o.y;
    if (o.x + o.w > bx2) bx2 = o.x + o.w;
    if (o.y + o.h > by2) by2 = o.y + o.h;
  }

  const { sx, sy, tx, ty } = edge;
  const candidates: { readonly x: number; readonly y: number }[][] = [];

  if (maxBends >= 1) {
    // L-h: horizontal first. (sx, sy) -> (tx, sy) -> (tx, ty).
    candidates.push([
      { x: sx, y: sy },
      { x: tx, y: sy },
      { x: tx, y: ty },
    ]);
    // L-v: vertical first. (sx, sy) -> (sx, ty) -> (tx, ty).
    candidates.push([
      { x: sx, y: sy },
      { x: sx, y: ty },
      { x: tx, y: ty },
    ]);
  }

  if (maxBends >= 2) {
    // U-over: route OVER the cluster's top.
    const overY = by - clearance;
    candidates.push([
      { x: sx, y: sy },
      { x: sx, y: overY },
      { x: tx, y: overY },
      { x: tx, y: ty },
    ]);
    // U-under: route UNDER the cluster's bottom.
    const underY = by2 + clearance;
    candidates.push([
      { x: sx, y: sy },
      { x: sx, y: underY },
      { x: tx, y: underY },
      { x: tx, y: ty },
    ]);
    // U-left: route around the cluster's LEFT side.
    const leftX = bx - clearance;
    candidates.push([
      { x: sx, y: sy },
      { x: leftX, y: sy },
      { x: leftX, y: ty },
      { x: tx, y: ty },
    ]);
    // U-right: route around the cluster's RIGHT side.
    const rightX = bx2 + clearance;
    candidates.push([
      { x: sx, y: sy },
      { x: rightX, y: sy },
      { x: rightX, y: ty },
      { x: tx, y: ty },
    ]);
  }

  return candidates;
};

/**
 * Total Euclidean length of a polyline. Used as a tiebreaker between
 * candidate detours that both clear all obstacles: shorter is better
 * (the visual reads as "less wandering").
 */
const polylineLength = (points: readonly { readonly x: number; readonly y: number }[]): number => {
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    if (a === undefined || b === undefined) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    total += Math.sqrt(dx * dx + dy * dy);
  }
  return total;
};

/**
 * Route ONE edge — exported for unit testing in isolation. Pure function
 * `(edge, all boxes, options) -> PathSpec`.
 *
 * Strategy:
 *   1. Build the per-edge obstacle set (filter ancestors + endpoints out).
 *   2. Test the straight line. If clear, return `{ kind: "default" }`.
 *   3. Otherwise, generate detour candidates and pick the shortest one
 *      that clears every obstacle.
 *   4. If no candidate clears, return `{ kind: "default" }` as fallback.
 */
export const routeOneEdge = (
  edge: RouterEdge,
  allBoxes: ReadonlyMap<string, RouterBox>,
  options: RouterOptions = {},
): PathSpec => {
  const margin = options.obstacleMargin ?? DEFAULT_ROUTER_OPTIONS.obstacleMargin;
  const clearance = options.bendClearance ?? DEFAULT_ROUTER_OPTIONS.bendClearance;
  const maxBends = options.maxBendsPerEdge ?? DEFAULT_ROUTER_OPTIONS.maxBendsPerEdge;
  const stubLen = options.exitStubLength ?? DEFAULT_ROUTER_OPTIONS.exitStubLength;

  const obstacles = buildObstacleSet(edge, allBoxes, margin);

  // Step 1: clear line? Then the existing curve renders fine — emit the
  // sentinel so EdgePath's geom() runs unchanged.
  if (!segmentBlocked(edge.sx, edge.sy, edge.tx, edge.ty, obstacles)) {
    return { kind: "default" };
  }

  // Step 2: identify the obstacles the straight line actually hits
  // (subset of `obstacles`). Detour candidates only need to clear THESE;
  // we don't care about boxes the original line missed.
  const blocking: RouterBox[] = [];
  for (const o of obstacles) {
    if (segmentIntersectsRect(edge.sx, edge.sy, edge.tx, edge.ty, o.x, o.y, o.w, o.h)) {
      blocking.push(o);
    }
  }
  if (blocking.length === 0) return { kind: "default" };

  // Step 3: generate detour candidates and pick the best one that clears
  // ALL obstacles (not just blocking — a detour mustn't create NEW
  // crossings either).
  const candidates = generateDetourCandidates(edge, blocking, clearance, maxBends);
  let best: { readonly x: number; readonly y: number }[] | null = null;
  let bestLen = Number.POSITIVE_INFINITY;
  for (const c of candidates) {
    if (!polylineClear(c, obstacles)) continue;
    const len = polylineLength(c);
    if (len < bestLen) {
      bestLen = len;
      best = [...c];
    }
  }

  if (best === null) {
    // No candidate clears every obstacle. Give up and fall back to the
    // default geometry — overlapping today's curve is preferable to
    // shipping a routed polyline that ALSO intersects something.
    return { kind: "default" };
  }

  // Step 4: apply exit-direction stubs so the first segment travels
  // briefly in the source's natural exit direction (and symmetrically
  // for the target). This breaks the visual ambiguity at corners — the
  // user sees "leaves the box rightward, then bends down" instead of
  // "leaves the box at an unidentifiable corner." Stubs are skipped
  // when the first/last segment is already aligned with that direction
  // (no visual change to add); see `applyExitStubs`.
  //
  // Re-validate the stubbed polyline against obstacles. An 8 px stub
  // pointing AWAY from a box rarely re-introduces an obstacle, but a
  // pathologically tight obstacle right next to the source box could
  // catch it — fall back to the un-stubbed polyline rather than ship
  // a stubbed shape that crosses an obstacle.
  const sourceBox = allBoxes.get(edge.fromId);
  const targetBox = allBoxes.get(edge.toId);
  const exitDir = computeExitDir(sourceBox, edge.sx, edge.sy);
  const entryDir = computeEntryDir(targetBox, edge.tx, edge.ty);
  const stubbed = applyExitStubs(best, exitDir, entryDir, stubLen);
  const finalPoints = polylineClear(stubbed, obstacles) ? stubbed : best;

  return {
    kind: "polyline",
    points: finalPoints,
    midpoint: polylineMidpoint(finalPoints),
  };
};

// ─── Lane-assignment post-pass ───────────────────────────────────────────

/**
 * Identify the "primary corridor segment" of a routed polyline — the
 * longest interior segment that isn't a stub. This is the segment we'll
 * offset perpendicular when multiple edges share it.
 *
 * Returns null when the polyline is too short to have a meaningful
 * corridor (e.g. just source+target with one bend, no clearly-dominant
 * leg).
 */
type CorridorSegment = {
  /** Index of the START point of the segment in `points`. END is `+1`. */
  readonly idx: number;
  /** Cached orientation — H means y is constant, V means x is constant. */
  readonly orientation: "H" | "V";
  /** The constant axis coordinate (y for H, x for V). */
  readonly axis: number;
  /** Min / max along the other axis (the segment's extent). */
  readonly lo: number;
  readonly hi: number;
};

const findPrimaryCorridor = (
  points: readonly { readonly x: number; readonly y: number }[],
): CorridorSegment | null => {
  if (points.length < 3) return null;
  // Walk all interior segments; pick the longest one that's
  // axis-aligned (H or V). We require axis alignment because lane
  // offsets are perpendicular to the corridor — a slanted segment has
  // no well-defined lane direction. In practice every interior segment
  // the router produces is axis-aligned (L + U candidates only use
  // horizontal / vertical bends), so this is just a defensive guard.
  let best: CorridorSegment | null = null;
  let bestLen = -1;
  for (let i = 0; i < points.length - 1; i++) {
    const a = points[i];
    const b = points[i + 1];
    if (!a || !b) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    // Strict equality check on the OFF-axis ensures the segment is
    // axis-aligned. (Stubs may produce tiny fractional offsets but
    // only on the axis they travel on, never on the perpendicular.)
    const isH = dy === 0 && dx !== 0;
    const isV = dx === 0 && dy !== 0;
    if (!isH && !isV) continue;
    const len = Math.abs(isH ? dx : dy);
    if (len <= bestLen) continue;
    if (isH) {
      best = {
        idx: i,
        orientation: "H",
        axis: a.y,
        lo: Math.min(a.x, b.x),
        hi: Math.max(a.x, b.x),
      };
    } else {
      best = {
        idx: i,
        orientation: "V",
        axis: a.x,
        lo: Math.min(a.y, b.y),
        hi: Math.max(a.y, b.y),
      };
    }
    bestLen = len;
  }
  return best;
};

/**
 * Group corridors by `(orientation, rounded-axis)` so corridors at the
 * same H-y (or V-x) within a small tolerance share a bucket. Within a
 * bucket we then need to detect which edges actually OVERLAP along the
 * other axis (two H-corridors at the same y but disjoint x-ranges
 * don't visually pile up and don't need lane separation).
 *
 * Tolerance: round axis to nearest 4 px. The router produces corridors
 * at integer-ish coordinates; 4 px tolerance accommodates the stub-
 * length shifts (8 px shouldn't merge unrelated corridors but might
 * merge near-duplicates produced by slightly different blocking
 * clusters).
 */
const corridorBucketKey = (c: CorridorSegment, axisTolerance = 4): string => {
  const ax = Math.round(c.axis / axisTolerance) * axisTolerance;
  return `${c.orientation}:${ax}`;
};

/**
 * Assign each polyline-routed edge a lane index within its bucket.
 *
 * Algorithm:
 *   1. Compute the primary corridor for every polyline-routed edge.
 *   2. Group by bucket key.
 *   3. Within each bucket, sort overlapping edges by `lo` (ascending);
 *      tiebreak by edgeKey for stable lane assignment.
 *   4. Sweep along the secondary axis and assign each edge the lowest
 *      free lane index (interval-scheduling-style: an edge reuses a lane
 *      when the previous edge in that lane finishes before this one
 *      starts).
 *
 * Returns a `Map<edgeKey, laneIndex>`. Edges with no entry get lane 0
 * (no offset).
 *
 * Exported so the GraphView render path can compute lane indices at
 * the top level (where it sees all edges at once) and pass them down
 * to per-edge components — each EdgePath then applies its assigned
 * lane offset to its locally-routed polyline via `applyLaneOffset`.
 */
export const assignLanes = (
  routes: ReadonlyMap<string, PathSpec>,
): ReadonlyMap<string, number> => {
  // 1+2: build buckets.
  type Item = {
    edgeKey: string;
    corridor: CorridorSegment;
  };
  const buckets = new Map<string, Item[]>();
  for (const [edgeKey, spec] of routes) {
    if (spec.kind !== "polyline") continue;
    const corridor = findPrimaryCorridor(spec.points);
    if (corridor === null) continue;
    const key = corridorBucketKey(corridor);
    let arr = buckets.get(key);
    if (arr === undefined) {
      arr = [];
      buckets.set(key, arr);
    }
    arr.push({ edgeKey, corridor });
  }

  // 3+4: lane assignment within each bucket via interval scheduling.
  // Two edges share a lane only when their corridor extents don't
  // overlap on the other axis.
  const laneByEdgeKey = new Map<string, number>();
  for (const items of buckets.values()) {
    if (items.length <= 1) continue; // singleton bucket; lane 0 (no offset).
    // Stable sort by `lo`, tiebreak by edgeKey alphabetical.
    items.sort((a, b) => {
      const dl = a.corridor.lo - b.corridor.lo;
      if (dl !== 0) return dl;
      return a.edgeKey < b.edgeKey ? -1 : a.edgeKey > b.edgeKey ? 1 : 0;
    });
    // `lanes[i]` is the `hi` of the last edge currently in lane i.
    const laneHis: number[] = [];
    for (const item of items) {
      // Find the lowest lane whose tail (`hi`) is BEFORE this item's
      // `lo` — that lane is free to reuse. Otherwise allocate a new lane.
      let found = -1;
      for (let li = 0; li < laneHis.length; li++) {
        if ((laneHis[li] ?? 0) < item.corridor.lo) {
          found = li;
          break;
        }
      }
      if (found === -1) {
        found = laneHis.length;
        laneHis.push(item.corridor.hi);
      } else {
        laneHis[found] = item.corridor.hi;
      }
      // Only edges with a non-zero lane need an entry. Lane-0 edges
      // get the bucket's "natural" corridor — no offset — so we save
      // map space by leaving them absent (caller treats missing as 0).
      if (found !== 0) laneByEdgeKey.set(item.edgeKey, found);
    }
  }
  return laneByEdgeKey;
};

/**
 * Offset a polyline's primary corridor segment perpendicular by
 * `laneIndex * laneWidth` px. Returns a new polyline; the input is
 * untouched. Negative `laneIndex` would offset the opposite direction
 * (we don't generate those today — `assignLanes` always returns >= 0).
 *
 * The offset is applied to BOTH endpoints of the primary corridor
 * segment. Neighboring segments stay axis-aligned because they share
 * the corridor endpoints' UNSHIFTED secondary-axis coordinate (e.g.
 * an H corridor's endpoints are shifted in y, but the V neighbors
 * to either side share the same x, so they remain vertical, just
 * longer or shorter by `delta`).
 *
 * For an H corridor we offset perpendicular in the y direction
 * (negative y = up, since y grows downward on the canvas — lanes
 * stack ABOVE the natural corridor). For a V corridor we offset in
 * the x direction (positive x = right).
 */
const offsetCorridor = (
  points: readonly { readonly x: number; readonly y: number }[],
  laneIndex: number,
  laneWidth: number,
): readonly { readonly x: number; readonly y: number }[] => {
  if (laneIndex <= 0) return points;
  const corridor = findPrimaryCorridor(points);
  if (corridor === null) return points;
  const delta = laneIndex * laneWidth;
  const out: { x: number; y: number }[] = points.map((p) => ({ x: p.x, y: p.y }));
  const a = out[corridor.idx];
  const b = out[corridor.idx + 1];
  if (!a || !b) return out;
  if (corridor.orientation === "H") {
    // Stack lanes ABOVE the natural corridor (negative y direction).
    // Visually: lane 0 sits where the original corridor was, lane 1
    // sits laneWidth px above it, lane 2 sits 2*laneWidth above, etc.
    a.y -= delta;
    b.y -= delta;
  } else {
    // V corridor: stack lanes to the RIGHT of the natural corridor.
    a.x += delta;
    b.x += delta;
  }
  return out;
};

/**
 * Apply a lane offset to a single PathSpec. Returns a new PathSpec
 * with the primary corridor shifted by `laneIndex * laneWidth` px
 * perpendicular. Default-sentinel PathSpecs pass through unchanged
 * (a "default" edge uses today's curve geometry — no corridor to
 * offset).
 *
 * Exported as the per-edge counterpart to the batch lane assignment.
 * Callers that do their OWN per-edge `routeOneEdge` call (rather than
 * the batch `routeEdges`) can still get lane spreading by:
 *
 *   1. Calling a top-level `assignLanes(map_of_pre_routed_specs)` to
 *      get a `Map<edgeKey, laneIndex>`.
 *   2. Calling this helper per edge with the lane index from step 1.
 *
 * That's the path the Solid `GraphView` takes today — per-edge memos
 * compute the routed PathSpec inline (so the exact source/target
 * attach-y values from `geom()` flow into the polyline), and a
 * top-level memo computes the lane map using APPROXIMATE endpoints
 * (box-edge centers — accurate enough for the corridor-y bucketing
 * since blocking-cluster bounds are independent of the ±5 px
 * port-spreading offset). Each EdgePath then applies its lane
 * offset via this helper.
 */
export const applyLaneOffset = (
  spec: PathSpec,
  laneIndex: number,
  laneWidth: number,
): PathSpec => {
  if (spec.kind !== "polyline") return spec;
  if (laneIndex <= 0 || laneWidth <= 0) return spec;
  const offset = offsetCorridor(spec.points, laneIndex, laneWidth);
  return {
    kind: "polyline",
    points: offset,
    midpoint: polylineMidpoint(offset),
  };
};

/**
 * Route every edge in a batch. Pure function — same inputs always
 * produce the same `Map`. Memoize this at the caller site.
 *
 * Two passes:
 *   1. Per-edge routing (independent — each call to `routeOneEdge`
 *      sees the full obstacle set, ignores other edges).
 *   2. Lane assignment (cross-edge — polyline-routed edges that share
 *      a long corridor get assigned distinct lane indices and their
 *      primary corridor is offset perpendicular by `laneIndex *
 *      laneWidth`). Without this, N edges all routing around the same
 *      blocking cluster would all sit on the same corridor and
 *      overlap into one smeared shaft.
 *
 * The map's keys are `RouterEdge.edgeKey` values; absent keys signal
 * "the renderer should fall through to `EdgePath`'s default geom" (the
 * same effect as a present `{ kind: "default" }` entry, but lets the
 * caller skip the lookup when no router pass ran at all — e.g. when
 * the router is feature-flagged off).
 *
 * Performance: O(E x O x B) for pass 1 where E = edges, O = obstacles
 * per edge, B = candidates per blocked edge (<= 6). Pass 2 is O(E log E)
 * for the bucket sort + linear sweep. For SHA-256 expanded (~200 edges,
 * ~80 leaves, with maybe 30% needing routing) this is well under 50k
 * ops — single-digit milliseconds in practice.
 */
export const routeEdges = (
  edges: readonly RouterEdge[],
  allBoxes: ReadonlyMap<string, RouterBox>,
  options: RouterOptions = {},
): ReadonlyMap<string, PathSpec> => {
  const result = new Map<string, PathSpec>();
  // Pass 1: independent per-edge routing.
  for (const edge of edges) {
    result.set(edge.edgeKey, routeOneEdge(edge, allBoxes, options));
  }
  // Pass 2: lane assignment over the polyline-routed subset.
  const laneWidth = options.laneWidth ?? DEFAULT_ROUTER_OPTIONS.laneWidth;
  if (laneWidth <= 0) return result; // disabled via toggle.
  const lanes = assignLanes(result);
  for (const [edgeKey, laneIndex] of lanes) {
    const spec = result.get(edgeKey);
    if (spec === undefined || spec.kind !== "polyline") continue;
    const offset = offsetCorridor(spec.points, laneIndex, laneWidth);
    result.set(edgeKey, {
      kind: "polyline",
      points: offset,
      midpoint: polylineMidpoint(offset),
    });
  }
  return result;
};
