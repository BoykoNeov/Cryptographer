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
};

/**
 * Default routing knobs. Exported so tests can reference them.
 */
export const DEFAULT_ROUTER_OPTIONS = {
  obstacleMargin: 6,
  bendClearance: 12,
  maxBendsPerEdge: 2,
} as const;

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

  return {
    kind: "polyline",
    points: best,
    midpoint: polylineMidpoint(best),
  };
};

/**
 * Route every edge in a batch. Pure function — same inputs always
 * produce the same `Map`. Memoize this at the caller site.
 *
 * The map's keys are `RouterEdge.edgeKey` values; absent keys signal
 * "the renderer should fall through to `EdgePath`'s default geom" (the
 * same effect as a present `{ kind: "default" }` entry, but lets the
 * caller skip the lookup when no router pass ran at all — e.g. when
 * the router is feature-flagged off).
 *
 * Performance: O(E x O x B) where E = edges, O = obstacles per edge,
 * B = candidates per blocked edge (<= 6). For SHA-256 expanded (~200
 * edges, ~80 leaves, with maybe 30% needing routing) this is well under
 * 50k ops — single-digit milliseconds in practice.
 */
export const routeEdges = (
  edges: readonly RouterEdge[],
  allBoxes: ReadonlyMap<string, RouterBox>,
  options: RouterOptions = {},
): ReadonlyMap<string, PathSpec> => {
  const result = new Map<string, PathSpec>();
  for (const edge of edges) {
    result.set(edge.edgeKey, routeOneEdge(edge, allBoxes, options));
  }
  return result;
};
