# Gradual obstacle-aware edge routing

A third take on graph-edge rendering, after the two parallel explore
branches (`explore/altitude-staggering`, `explore/edge-routing-router`)
landed on origin without merging to `main`. Both were probed empirically
on 2026-05-27; this plan picks up from their findings, locks the missing
design slot they didn't fill, and proposes how to ship it.

## Context

### What the explore branches established

| Branch | Obstacle-aware? | Sibling-aware? | Gradual turns? |
|---|---|---|---|
| `explore/altitude-staggering` (`54fea47`) | No | Yes (per-edge apex variation) | Yes (Bezier) |
| `explore/edge-routing-router` (`9b1cdda`) | Yes (single-bend L + U fallback) | Yes (lane assignment) | **No** (orthogonal + rounded corners ≠ gradual) |
| What this plan ships | **Yes** | **Yes (bundled)** | **Yes (Catmull-Rom)** |

The router branch already built the hard infrastructure: obstacle index,
interval-scheduling lane assignment, exit stubs, a `polylineMidpoint`
helper that keeps bundle ×N pills on-shaft, and a corner-smoothing
primitive (`polylineToRoundedPath` at `src/ui/graph/edge-router.ts:1116`).
The discriminated-union sentinel `PathSpec = { kind: "default" } |
{ kind: "polyline" }` lets clear edges keep their current geometry
byte-identically — only edges that would otherwise overlap pay for the
new path computation.

What's missing from both branches is **the third axis**: a curve that
(a) provably stays clear of non-incident leaves AND (b) reads as
"gradual" (no orthogonal corners) AND (c) merges sibling edges that
share a corridor instead of running N parallel lines.

### What this plan does

Replace the orthogonal polyline backbone with a **gradual-curve backbone
that bundles sibling edges sharing endpoint clusters**, while keeping
the router branch's obstacle/lane machinery. Compose with the altitude
branch (apex variation applied to the bundle midline, not individual
edges) on a separate slice so altitude's measurable SHA-256 geometry
effect (+69 % apex spread on the 8-edge fan-IN, per
`tests/graph-view-altitude-staggering-measure.test.tsx` on tip
`54fea47`) is preserved.

### User design decisions (2026-05-27, captured before slice 0)

Four picks lock the algorithm shape:

1. **Sibling behavior: endpoint-flare + midline-merge.** Holten-style
   hierarchical edge bundling. Each edge stays visually distinct near
   its source + target chip (≈30 px endpoint flares); bundles share
   midline along long shared corridors. Click on any edge in a bundle
   uses `selectedTarget` + the S2(m) focus-dim mechanism to surface it
   individually in the dense middle.
2. **Obstacle constraint: hard.** Curves NEVER cross a non-incident
   leaf's bbox. Required because soft constraints (force-directed or
   single-waypoint Bezier deformation) can still graze obstacles in
   pathological cases. Realized via: inflate leaf bboxes by an 8 px
   clearance margin BEFORE A*, then smooth — the inflation absorbs the
   smoothing bulge so the smoothed curve provably stays outside the
   un-inflated bboxes.
3. **Compose with altitude-staggering, on a new branch.** Stack both;
   they target disjoint geometric DOFs (altitude varies apex y;
   bundling varies midline x). Mathematically orthogonal — confirmed
   by advisor synthesis 2026-05-27. New plan doc + new branch family
   off `main` (NOT off either explore branch).
4. **Pedagogy preserved at endpoints.** S2(k)'s port-flow parallel-shift
   (`sourceYOffset` + `targetYOffset`) keeps working at endpoint flares
   — that's exactly where the bundling design leaves edges distinct.
   Becomes invisible inside the bundled midline, which is fine because
   the bundle's visual job there is "one stream, not N parallel lines."

### What was tried and rejected

- **Pure single-waypoint Bezier deformation** (option 1 in the advisor
  menu) — eliminated by pick 2. The smoothing bulge between control
  points can graze obstacles even when the control points themselves
  are clear.
- **Force-directed edge routing (Holten-Wong)** (option 3) — converges
  to a local minimum, not guaranteed clear. Soft constraint only.
  Also ~10× the compute of polyline-then-smooth, harder to debug.
- **Constraint optimization** (option 4) — overkill for this codebase.
- **Re-merging the existing branches** as-is — neither branch alone
  delivers all four user picks. Altitude has no obstacle awareness;
  the router has no gradual curves and no bundling. Stacking them
  doesn't close the gap because neither branch knows about clusters.
- **Manhattan grid A* (the router branch's first form, before L+U)** —
  produces stair-steps that visually clash with the curved aesthetic.
  Corner-rounding postprocess softens but doesn't eliminate the
  orthogonal feel.

## Goals and non-goals

### Goals

1. Every rendered edge that COULD be drawn as a clear gradual curve IS
   drawn as one. Hard constraint: zero pixel of any visible edge enters
   a non-incident leaf's un-inflated bbox.
2. Sibling edges sharing an endpoint cluster pair merge along a shared
   midline, with endpoint flares preserving the per-edge identity at
   source and target chips. Endpoint flares reach the same attach
   points the existing port-spreading machinery already computes (so
   S2(k) parallel-shift, replica source-x, S2(j2) per-consumer local
   row densification all continue to work at endpoints).
3. Clear edges remain byte-identical to today's `EdgePath` output. The
   `PathSpec` discriminated-union sentinel from the router branch is
   the precedent.
4. Click-disambiguation in dense bundles via S2(m)'s focus-dim. No new
   selection plumbing.
5. Composes with `explore/altitude-staggering` so apex variation applies
   to bundle midlines.
6. **Subsumes the `isFeedback` geom-branch special case** (currently at
   `EdgePath.geom()` lines 7276-7357). Feedback edges route through
   the same unified pipeline as everything else; their characteristic
   "over-the-top arc" emerges from A\* directional bias + obstacle-
   awareness rather than from a hardcoded `if`. `isFeedback` survives
   as a SEMANTIC flag (dashed styling, tooltip suffix, cycle-detection
   exclusion in `validateGraph`) but stops controlling geometry. This
   addresses the architectural smell flagged 2026-05-27 — the current
   arc is ad-hoc and doesn't scale to N feedbacks per iterate body
   (future stream ciphers) or multi-row iterate bodies.

### Non-goals (deferred or out of scope)

- **Topology-level fixes.** The 2026-05-27 AM smoke established that
  ~40 % of SHA-256 edges traverse narrow inter-column gutters even with
  the router branch active. That's a layout problem (column widths,
  msg-schedule body shape), not a routing problem. Filed for a separate
  plan if user-visible pain persists after this one ships.
- **Replica-edge routing.** The arrow between a replica chip and its
  consumer is NOT routed by this pipeline — it stays a short straight
  line with start-dot. (Replica chips and their arrow corridors ARE
  treated as obstacles by NON-replica edges; see Step 2's two-tier
  obstacle rule. Replica arrows colliding with neighboring replica
  blocks remains acceptable per user pick 2026-05-27 — color-coding
  + start-dot keep them visually parseable.)
- **Feedback-edge overhead arc.** Same as today (S2(h) / CBC feedback).
  Feedback edges already route over the top of the chip row and don't
  need obstacle avoidance.
- **Layout changes** (wider gutters, folded msg-schedule). Not in this
  plan's scope.
- **bundle-edge tooltip / inspector** that surfaces the N constituent
  edges of a bundle on hover. Possible polish slice if S2(m)
  click-disambiguation feels insufficient in smoke.

## Algorithm — "Option 2b"

Five steps in order. Pure functions throughout except the final wire-up.

### Step 1 — Edge clustering

Group edges by `(sourceParentId, targetParentId)` where `parentId` is
the immediately enclosing container in the spec tree (one level above
the leaf; root-level leaves get `null`). Edges sharing a cluster pair
share a midline. Singleton clusters (one edge) route individually —
trivial bundle of size 1, no midline merging visible.

**Why parent-level, not deeper.** Going deeper (grandparent, etc.)
over-merges across unrelated sub-systems. Going shallower (no clustering)
defeats the bundling goal. Parent-level captures the natural visual
hierarchy of the graph view — when you look at SHA-256, the 8 edges
from `final.split-wv → final.s_0..s_7` share parent `final` on both
ends and are exactly what the eye wants to see bundled.

**Cluster cardinality is THE load-bearing number.** Slice 0 probes
this. If ~50 clusters cover ~2,500 SHA-256 edges, bundling pays off
massively (avg cluster size ≈ 50). If ~1,000 clusters cover ~2,500
edges (avg cluster size ≈ 2-3), bundling helps weakly and this whole
plan is worth less than the slice cost. The probe runs before any
algorithm code commits.

### Step 2 — A* midline routing with inflated obstacles

For each cluster pair with ≥2 edges, compute ONE polyline midline from
the cluster's source-side aggregate position to the cluster's
target-side aggregate position:

- **Aggregate positions** = bbox enclosing all source attach points
  (resp. all target attach points) for edges in the cluster. The
  midline routes between the centroids of those bboxes.
- **Obstacle set** = every leaf bbox in the graph EXCEPT the cluster's
  source-and-target parent containers. Inflated by
  `CLEARANCE_MARGIN = 8 px` on all sides. The inflation absorbs the
  Step 4 smoothing bulge.
- **Replica handling (two-tier):**
  - **Hard obstacle** — every replica chip's bbox is in the obstacle
    set on equal footing with non-replica leaves. Non-incident
    routing never crosses a replica chip.
  - **Soft obstacle** — the corridor between each replica chip and
    its consumer (a rectangle covering the chip + the
    `REPLICA_LIFT_GAP` px gap below it, where the replica's own short
    arrow lives). A\* assigns a HIGH cell cost inside this corridor
    but does NOT mark cells impassable. Other arrows prefer to detour
    around the replica-arrow zone; if dense graphs leave no detour,
    crossing is allowed (replica arrows are short, color-coded by
    source, and start-dotted — collisions remain visually parseable,
    confirmed by user 2026-05-27).
  - **Replica's own arrow is NOT routed by this pipeline.** Replicas
    sit close enough to their consumer that the existing straight-line
    rendering (with start-dot) already produces a clear path. The
    `PathSpec = { kind: "default" }` sentinel keeps them unchanged.
- **A* on a 24 px grid.** Standard 8-directional moves; cell marked
  blocked if it intersects any inflated obstacle. Heuristic = octile
  distance. Cost ~5-10 ms per cluster on the SHA-256 worst case;
  cluster count caps total at ~500 ms.
- **Grid extends ABOVE the highest leaf into the canvas-margin
  region.** Required so feedback edges can route over-the-top
  naturally — the existing overhead arc lives in y ≈ 10..96 (between
  ARC_TOP_INSET and one CANVAS_MARGIN below). Without this extension,
  A\* hits the top of the grid and can't find any over-the-top path.
- **Iterate / group HEADERS are routable, not obstacles.** They're
  visible labels (not chips), and feedback arcs have historically
  routed THROUGH their y-range above the row. Marking them obstacles
  would block the natural feedback geometry.
- **Directional bias for `isFeedback` edges.** A\* heuristic gives a
  small cost reduction (≈ 30 % of cell cost) for cells ABOVE the
  source's y when the edge has `isFeedback=true`. Pushes A\* toward
  the "exit-top, arc-over" shape that today's hardcoded branch
  produces, generalizing to N feedbacks per iterate body via lane
  assignment in Step 4 (each feedback in a multi-feedback cluster
  gets its own lane in the overhead corridor). Non-feedback edges
  have zero northward bias — they route the shortest cleared path.
- **Fallback to straight line** if A* finds no path (the cluster's
  endpoints are inside the inflated zone of some leaf — degenerate but
  possible at low canvas zoom). Straight line may graze; logged for
  smoke review but doesn't block ship.

Singleton clusters (one-edge "bundles") use the same routing on their
single edge's endpoints.

### Step 3 — Catmull-Rom smoothing

Convert each polyline (sequence of A* waypoints) into a smooth curve
via Catmull-Rom interpolation:

- **Standard CR tension** (0.5) at obtuse-angle bends.
- **Corridor-aware tension reduction** at sharp bends (angle delta
  > 90°). Reducing tension keeps the curve closer to the polyline,
  guaranteeing it stays inside the 8 px clearance corridor.
- **Property test** on synthetic obstacle layouts: 32 sample points
  along each smoothed curve all sit outside un-inflated obstacle
  bboxes. This is the hard-constraint guarantee.

The corner-rounding primitive `polylineToRoundedPath` at
`src/ui/graph/edge-router.ts:1116` is the precedent — but Catmull-Rom
gives smoother curves than the quadratic-Bezier corner rounding the
router branch ships. The polyline-aware midpoint helper
(`polylineMidpoint`, exported, used for bundle ×N pills) carries
over byte-identically.

### Step 4 — Endpoint flares + per-edge lane offsets

Each edge in a cluster picks a lane slot via the router branch's
existing `assignLanes` machinery:

- **Lane width** = 6 px (matches router branch default).
- **Lane assignment** = interval-scheduling on the cluster's shared
  midline so disjoint edge endpoint pairs can share lane 0 (memory-
  efficient).

For each edge:

1. Compute the EXISTING `EdgePath.geom()` source and target attach
   points (so port-spreading, replica source-x, all of S2(k)'s
   parallel-shift continues working unchanged at endpoints).
2. **Endpoint flare** = a short Bezier segment (≈30 px or 20 % of the
   total edge length, whichever is smaller) from the endpoint attach
   point to where the edge joins the bundle midline. The flare uses
   the existing `sourceYOffset` / `targetYOffset` so port-flow edges
   stay distinct at endpoints — exactly the S2(k) pedagogy.
3. **Midline segment** = the bundle's smoothed Catmull-Rom curve,
   shifted perpendicular by `lane * laneWidth`.
4. **Compose** flare-in + midline + flare-out into one SVG `<path>`.

For singleton clusters (one edge in the bundle), the lane offset is 0
and the midline IS the edge's path. The flares become a no-op
(continuous with the midline).

### Step 5 — Wire into GraphView with diagnostic hatch

Replace `EdgePath.geom()`'s default return with the routed path, gated
by a `?no-bundle=1` URL diagnostic for A/B smoke. Same pattern as the
router branch's `?no-router=1` hatch. The hatch is TEMPORARY — removed
in the slice that closes the plan.

## What survives from existing branches

### From `explore/edge-routing-router` (`9b1cdda`)

Reused verbatim (cherry-picked into the new branch):

- `src/ui/graph/edge-router.ts` types: `RouterBox`, `RouterEdge`,
  `PathSpec`. The `PathSpec = { kind: "default" } | { kind: "polyline" }`
  discriminated union extends with `{ kind: "smooth"; midline: ...;
  flares: ... }` for this plan.
- Obstacle index construction (`buildObstacleSet`, lines 647-664).
- Lane assignment (`assignLanes`, lines 980-1040) and `applyLaneOffset`.
- `polylineMidpoint` for bundle ×N pill anchor.
- Diagnostic URL hatch pattern.

Replaced or extended:

- `routeOneEdge` (L+U detour search) → `routeClusterMidline` (A* on
  inflated obstacles).
- `polylineToRoundedPath` (quadratic-Bezier corner rounding) →
  Catmull-Rom smoothing.
- Per-edge routing → per-cluster midline + per-edge flares.

### From `explore/altitude-staggering` (`54fea47`)

Composed in via the optional slice (Slice 4 of this plan):

- `EdgePath` props `pullSlot` / `pullSlotTotal` and the
  `PULL_STAGGER_STEP = 0.18` constant.
- Apex variation applied to the BUNDLE midline (the smoothed
  Catmull-Rom curve at Step 3), not to individual edges.
- The port-flow scope predicate
  (`kind === "state" && auxKey === PORT_FLOW_AUX_KEY`) at
  `GraphView.tsx:4766` carries over unchanged.

### From shipped main (`45c903e`)

- S2(m) focus-dim (selection-only). The dim predicate already
  expands selection to include replicas; extending it to "dim every
  edge in the same bundle as the selected one EXCEPT the selected one"
  is a small predicate widening — covered in Slice 4.
- S2(k) port-flow parallel-shift via `sourceYOffset` / `targetYOffset`.
  Continues to work at endpoint flares.
- S2(j2) per-consumer local row densification (replica placement).
  Independent of routing — affects where chips sit, not how arrows
  travel between them.

## Tuning surface

Every numeric constant in the algorithm above is a knob with a
**plausible-but-not-obvious** default. The router branch ran into this
empirically — 30 lines of comment-debate over whether `CLEARANCE_MARGIN`
should be 6, 8, or 10 px, with no way to tell except code-edit + reload.
This plan front-loads a small UI surface so the user can tune in-browser
during smoke and iterate fast.

### Architecture

A new per-spec store `src/ui/stores/routing-tuning.ts`. Pattern follows
`src/ui/stores/layout.ts` — per-spec values keyed by `spec.id`, persisted
to localStorage, with a reset-to-defaults helper. Each knob is a
`createSignal<number>` (or `createSignal<number>` with `Infinity`
encoded as `null` for class costs) exported alongside its setter.

**Reactivity architecture (locked):** routing functions take a
`TuningSnapshot` object parameter — a plain frozen record of current
values — NOT direct signal reads. Snapshot construction lives in a
single `createMemo` at the GraphView level that reads every relevant
signal and emits a fresh frozen object whenever any input changes.
Routing modules (`edge-bundling.ts`, future helpers) stay pure: same
snapshot in → same path out, deterministic, unit-testable without
Solid runtime. The render layer is the only place where the
reactive-to-pure boundary lives. This pinning replaces the earlier
"parameter OR signals" phrasing.

**Per-spec scope** is the user's pick: SHA-256's density may need
different knobs than DES's sparser graph. Two tiers only: per-spec
entry in localStorage if present, plan defaults otherwise. No
cipher-family inheritance — keep the lookup mechanism simple.

**Pedagogical bonus** of shipping the panel to all users (the user's
explicit pick over dev-only): readers can experiment with the algorithm
the same way they experiment with cipher parameters today. Drag
`CLEARANCE_MARGIN` from 8 to 24 and watch the routing detour around
chips by a wider arc — the constraint visibility is the lesson.

### Knob inventory

| Knob | Default | Slider range | Notes |
|---|---|---|---|
| `CLEARANCE_MARGIN` | 8 px | 0–32 | Obstacle bbox inflation before A\*. |
| `GRID_CELL_SIZE` | 24 px | 8–48 | A\* grid resolution. Coarser = faster, blockier. |
| `LANE_WIDTH` | 6 px | 2–16 | Per-edge perpendicular offset in bundle. |
| `FLARE_LENGTH_PX` | 30 px | 0–80 | Endpoint flare length cap. |
| `FLARE_LENGTH_FRAC` | 0.2 | 0–0.5 | Endpoint flare as fraction of edge length (min applies). |
| `CR_TENSION_DEFAULT` | 0.5 | 0–1 | Catmull-Rom tension at obtuse bends. |
| `CR_TENSION_SHARP` | 0.25 | 0–1 | Catmull-Rom tension at sharp bends. |
| `SHARP_BEND_ANGLE` | 90° | 30–135 | Threshold for switching to sharp tension. |
| `PULL_NORTHWARD_BIAS` | 0.30 | 0–1 | A\* feedback-edge northward heuristic strength. |
| `PULL_STAGGER_STEP` | 0.18 | 0–0.5 | Altitude apex variation per slot (Slice 4). |
| `MIN_CLUSTER_SIZE` | 2 | 1–8 | Singleton-bundle cutoff (1 = bundle everything). |
| `BUNDLE_PILL_T` | 0.25 | 0–1 | Position of ×N pill along midline. |

### Per-class obstacle costs

Generalizes the current "hard / soft" two-tier rule into a slider per
obstacle class. Each class has a cost-multiplier slider with the max
position rendered as `∞` (truly impassable, today's hard behavior);
finite positions become A\* cell-cost multipliers.

| Class | Default | Slider range | Today's plan behavior |
|---|---|---|---|
| Non-incident leaf chip | ∞ (impassable) | 1.0–100, then `∞` | Hard. Slide down → A\* may cross chip bboxes if no detour exists. |
| Replica chip | ∞ (impassable) | 1.0–100, then `∞` | Hard. Slide down → routing may cross replica chips (replica's own arrow is unaffected). |
| Replica-arrow corridor | 10.0 | 1.0–100, then `∞` | Soft. Slider lets you push to ∞ ("treat replica arrows as inviolable") or down ("let other arrows cross freely"). |

The `∞` slot is the rightmost slider position with a visible "∞" label;
the next-rightmost position is `100` so the user can see the gradient
between "very expensive but possible" and "impassable". Internally,
`Infinity` triggers the obstacle-impassable code path; finite values
multiply the cell cost in A\*'s priority queue.

**Serialization:** localStorage stores cost values as `number | null`,
where `null` represents `Infinity`. Deserializer maps `null → Infinity`
on load; serializer maps `Infinity → null` on save. Keeps the field
type uniform (`number | null`) and avoids the validation overhead of
a custom object sentinel.

### Panel placement

A collapsible `<details>` block in the graph toolbar, labelled "Routing
tuning" with a wrench glyph. Collapsed by default (no surface impact
for users who don't touch it). Inside the panel: each knob is a
`<input type="range">` paired with a numeric `<input type="number">`
(matching the existing `ParamEditor` aesthetic). Per-class obstacle
costs render as the same range-input pattern with `∞` as the rightmost
labelled tick.

**Knob grouping** — flat lists at 15+ entries read as noise. Six
labelled sub-sections inside the panel, in this order:

1. **Routing** — `CLEARANCE_MARGIN`, `GRID_CELL_SIZE`, `LANE_WIDTH`
2. **Curve** — `CR_TENSION_DEFAULT`, `CR_TENSION_SHARP`,
   `SHARP_BEND_ANGLE`, `FLARE_LENGTH_PX`, `FLARE_LENGTH_FRAC`
3. **Bundling** — `MIN_CLUSTER_SIZE`, `BUNDLE_PILL_T`
4. **Feedback** — `PULL_NORTHWARD_BIAS`
5. **Obstacles** — `obstacleCostLeafChip`, `obstacleCostReplicaChip`,
   `obstacleCostReplicaCorridor`
6. **Altitude** — `PULL_STAGGER_STEP` (added Slice 4)

Each sub-section is itself a nested `<details>` (collapsed by default
inside the parent panel — drilling progressively reveals knobs the
user is actually interested in, instead of dumping all 15+ at once).

**Escape hatch:** `?tune=hidden` URL parameter forces the panel to not
render at all. Useful for demos, screenshots, or first-time-user runs
where the panel reads as overwhelming. Documented in
`docs/help/graph-view.md` after Slice 6 ships.

Two reset buttons at the panel footer:
- **Reset this spec** — clears the localStorage entry for the current
  `spec.id` and falls back to plan defaults.
- **Reset all routing** — clears all per-spec entries; useful when
  the user wants to start fresh.

Tuning values are NOT bundled into the shareable URL or Save/Load
envelope — they're viewer prefs per
[[feedback_viewer_preference_pattern]]. (A Copy-as-JSON export
button was considered but deferred — see Slice 5b notes.)

### Diagnostic hatch × tuning interaction

`?no-bundle=1` (the A/B comparison hatch) **ignores tuning entirely**.
Under the hatch, every edge falls back to `{ kind: "default" }` —
today's `EdgePath.geom()` path — regardless of what the user has dialed
in the panel. Reason: the hatch's purpose is "what does shipped main
look like without this plan", so polluting it with tuned values
defeats the comparison. Hatched mode is effectively read-only against
the plan's machinery.

### What this changes in the slices

The slice list below stays largely the same, but:

- **Slice 1** introduces `CLEARANCE_MARGIN`, `GRID_CELL_SIZE`,
  `MIN_CLUSTER_SIZE` as signals in the new
  `src/ui/stores/routing-tuning.ts`, NOT as module-level constants in
  `edge-bundling.ts`. The routing functions accept a `tuning`
  parameter (or read signals directly).
- **Slice 2** adds `FLARE_LENGTH_PX`, `FLARE_LENGTH_FRAC`,
  `CR_TENSION_DEFAULT`, `CR_TENSION_SHARP`, `SHARP_BEND_ANGLE`,
  `BUNDLE_PILL_T` to the store.
- **Slice 3** mounts the panel UI as part of the wire-up; user-visible
  knobs work from this slice onward. Adds `PULL_NORTHWARD_BIAS` and
  the three per-class obstacle costs to the store.
- **Slice 4** adds `PULL_STAGGER_STEP` to the store when altitude
  composes in.
- A new **Slice 5b** (small, peer to current Slice 5) polishes the
  panel: per-class cost slider's `∞` tick rendering, Copy-as-JSON
  button, panel description tooltip, reset-button affordance polish,
  panel-collapsed-by-default invariant test.

### Tests added

- `tests/routing-tuning-store.test.ts`: per-spec persistence, default
  fallback, `Infinity` cost round-trip (`Infinity → null → Infinity`
  in localStorage), `TuningSnapshot` immutability (frozen object).
- `tests/routing-tuning-panel.test.tsx`: panel collapses by default,
  slider changes trigger memo recomputation, reset buttons restore
  defaults, Copy-as-JSON produces parseable blob.
- Each signal-driven knob gets a unit test in the relevant
  Slice 1/2/3/4 test file showing the routing function honors a
  non-default value.

## Slices

Six slices (was five — Slice 5b inserted for tuning panel polish).
Probes first (no code commits). Smoke gates each visible slice.

### Slice 0 — Probes

**No code commit.** Three numbers settle scope before any implementation.

#### 0a. Multi-leaf-crossing distribution

For each edge in SHA-256 expanded view, compute the straight-line
segment from source attach to target attach. Count how many
non-incident leaf bboxes it intersects. Histogram:

- 0 intersections (already clear): %
- 1 intersection (single-waypoint would have worked): %
- 2-5 intersections (medium-density): %
- 6+ intersections (deep corridor): %

**Decision rule:** if >70 % of bad edges (≥1 intersection) cross only
1 leaf, the single-waypoint approach the advisor mentioned as option 1
would have been viable. If >50 % cross ≥2 leaves, A* is the only
defensible choice. Either way, the plan stays — but the slice-cost
estimate updates.

#### 0b. Cluster cardinality

Count distinct `(sourceParentId, targetParentId)` pairs on SHA-256
expanded. Compute:

- Total cluster pairs: N
- Average cluster size: edges / N
- Max cluster size: max cluster size
- % of edges in singleton clusters (no merging benefit)

**Decision rule:** if average cluster size ≥10 OR max ≥30, bundling
pays off massively and this plan ships. If average ≤2 (singleton-
dominated), bundling is a wash and the plan downgrades to "obstacle-
aware gradual curves without bundling" — the algorithm simplifies
(no clustering pass, no flares).

#### 0c. Inflated-bbox A* feasibility

For each cluster pair on SHA-256, run A* on the inflated obstacle set
and record:

- % of cluster pairs where A* finds a path: should be ≥95 %.
- % where the inflated zone of source-or-target bbox blocks all
  starting cells: degenerate cases, get fallback handling.

**Decision rule:** if <90 % feasibility, the 8 px inflation margin is
too aggressive for SHA-256's narrow gutters. Drop to 6 px or 4 px and
re-run. The margin choice falls out of this probe.

#### 0d. Feedback-edge gap test

For CBC at current FLOW_GAP=36, run A\* between `cbc-snapshot.right`
and `cbc-xor.left` with the WHOLE iterate body's leaves as obstacles
(8 px inflated). Question: does A\* find a direct path through the
inter-leaf gap, or does it have to route over-the-top?

**Decision rule:**
- **Direct path found** → the unified routing replaces the overhead
  arc with a side curve in CBC by default; the `isFeedback` directional
  bias (Step 2's "prefer-northward" heuristic) becomes load-bearing
  for preserving CBC's existing visual. Without the bias, CBC's arc
  disappears on Slice 3.
- **Over-the-top found naturally (gap too narrow)** → bias is
  belt-and-suspenders; still ship it (future ciphers with wider gaps
  will need it).

Either way, this plan ships A-with-directional-bias. The probe just
confirms how load-bearing the bias is on today's specs.

**Implementation:** a one-shot test file
`tests/_probe-gradual-routing-feasibility.test.ts` (deleted after the
plan starts) that runs the three counts on the live SHA-256 spec via
the existing `deriveAuxGraph`. Prints to console; the user reads the
numbers and we proceed.

### Slice 1 — Clustering + midline A* (pure functions, no rendering)

**Pure derivation slice.** Renders unchanged at user-facing level; all
new code lives in `src/ui/graph/`.

- New module `src/ui/graph/edge-bundling.ts`:
  - `clusterEdges(edges, spec): Map<ClusterKey, RouterEdge[]>`
  - `routeClusterMidline(cluster, obstacles, tuning): Polyline | null`
    (null = A* infeasible; caller falls back to straight line)
- Reuse `RouterBox`, `RouterEdge`, `buildObstacleSet` from existing
  `edge-router.ts`.
- New store `src/ui/stores/routing-tuning.ts` (per-spec, localStorage
  persisted — see **Tuning surface** section above for full
  architecture). Initial signals exposed in this slice:
  - `CLEARANCE_MARGIN` (default 8 px, or whatever 0c probe settles on)
  - `GRID_CELL_SIZE` (default 24 px)
  - `MIN_CLUSTER_SIZE` (default 2 — singleton clusters skip bundling)
- The routing functions accept a `tuning` parameter (a snapshot of
  current signal values) so they remain pure for unit testing.

**Tests:**
- Synthetic: 3 edges sharing a cluster pair produce one shared midline
  polyline.
- Synthetic: 1 edge alone produces a polyline equivalent to the direct
  A* path.
- SHA-256 cluster cardinality matches the 0b probe number.
- AES-128 ECB: cluster count is small (state spine + key-expansion
  fan-out only) and routing matches existing geometry within ε on
  clear cases.

**Counts target:** +1 module (~200 LOC), +1 test file (~150 LOC,
~15 tests). Bundle target: +2 KB raw / +0.5 KB gzipped.

### Slice 2 — Catmull-Rom smoothing + endpoint flares (pure geometry)

**Pure geometry slice.** Still no rendering wired.

- Extend `edge-bundling.ts`:
  - `smoothPolyline(polyline, corridor, tuning): SmoothPath` —
    Catmull-Rom with corridor-aware tension at sharp bends.
  - `composeEdgePath(edge, midline, lane, tuning): SVGPath` — builds
    the flare-in + midline + flare-out composite SVG path.
- New signals in `routing-tuning.ts`:
  - `FLARE_LENGTH_PX` (default 30 px; cap on flare absolute length)
  - `FLARE_LENGTH_FRAC` (default 0.2; flare as fraction of edge length,
    min applies)
  - `SHARP_BEND_ANGLE` (default 90°; threshold for tension reduction)
  - `CR_TENSION_DEFAULT` (default 0.5)
  - `CR_TENSION_SHARP` (default 0.25)
  - `BUNDLE_PILL_T` (default 0.25; position of ×N pill along midline)
- `LANE_WIDTH` signal added (default 6 px) — referenced by Slice 4
  when lanes start applying per-edge offsets in rendered output.

**Property tests:**
- Smoothed curve stays inside inflated corridor on 32 sample points
  across 10 synthetic obstacle layouts.
- Endpoint flares reach the actual `geom()` attach points within 0.5 px.
- Single-edge cluster: flare is degenerate (zero-length) — curve is
  continuous with the midline.

**Counts target:** +150 LOC in `edge-bundling.ts`, +200 LOC of tests
(~20 tests). Bundle target: +1 KB raw / +0.3 KB gzipped.

### Slice 3 — Wire into GraphView + diagnostic hatch + smoke

**The user-visible flip.** This is where the new geometry replaces the
old in the actual rendered DOM.

- New `PathSpec` variant: `{ kind: "bundled"; flareIn: string;
  midline: string; flareOut: string; lane: number }`.
- `EdgePath.geom()` checks an injected `routedPath` prop (cluster
  routing computed once at the GraphView level, cached per graph).
- **Remove the `if (props.isFeedback)` geom branch** (lines 7276-7357)
  from `EdgePath.geom()`. Feedback edges now route through the
  unified pipeline; `isFeedback` survives ONLY as input to the A\*
  directional-bias heuristic + the dashed-stroke CSS class + the
  cycle-detection exclusion in `validateGraph`. Update
  `tests/graph-view-feedback-edge-overhead.test.tsx` rationale to
  reflect that the over-the-top shape now emerges from the unified
  algorithm rather than the hardcoded branch (assertions should
  remain — same shape, different derivation).
- Diagnostic URL hatch `?no-bundle=1` — forces every edge to
  `{ kind: "default" }`. Same pattern as the router branch's
  `?no-router=1`. **Note:** under `?no-bundle=1` the `isFeedback`
  geom branch should TEMPORARILY come back so CBC's arc still
  renders during A/B. Two ways to do this: (i) keep the branch
  guarded behind `isNoBundle()` for the lifetime of Slice 3, then
  remove with the hatch in Slice 6; (ii) duplicate the geometry
  computation behind the hatch. Pick (i) — cleaner removal path.
- `bundle-by-default` localStorage flag — default ON for SHA-256,
  default OFF for AES/Speck/Serpent/DES (legacy ciphers; user can
  flip the global toggle in the graph toolbar). Settled after smoke.
- **Mount the Routing-tuning panel** in the graph toolbar (the
  collapsed `<details>` block described in the **Tuning surface**
  section). Panel ships in this slice so the user can A/B knob values
  in-browser during smoke. New signals added in this slice:
  - `PULL_NORTHWARD_BIAS` (default 0.30; A\* feedback-edge bias)
  - **Per-class obstacle costs** — three signals:
    - `obstacleCostLeafChip` (default `Infinity`)
    - `obstacleCostReplicaChip` (default `Infinity`)
    - `obstacleCostReplicaCorridor` (default `10.0`)
  - The A\* core reads these costs from the tuning snapshot per cell;
    `Infinity` triggers the impassable code path verbatim, finite
    values multiply cell cost in the priority queue. Test that the
    finite-cost branch produces a path that DOES cross the obstacle
    when no detour exists, and the `Infinity` branch produces `null`
    in the same scenario.

**Smoke checklist (manual, ~5 minutes):**

1. SHA-256 expanded: bundles read as gradual curves, endpoints flare
   to per-port positions, no edge enters a non-incident leaf bbox at
   default zoom.
2. SHA-256 collapsed: msg-schedule chip has its outgoing arrow (the
   S2(h) fix continues to show).
3. AES-128 ECB: key-expansion fan-out edges look as before (clusters
   are small; bundling effectively no-op). Spine intact.
4. AES-CBC: feedback edge still routes overhead (Slice 5's wire-up
   doesn't touch the `isFeedback` branch in `EdgePath.geom()`).
5. Speck/Serpent/DES: byte-identical or visually-indistinguishable from
   pre-slice rendering (small clusters, mostly singleton).
6. `?no-bundle=1` confirms A/B comparison — all edges revert to
   pre-slice geometry.
7. Click an edge inside a SHA-256 bundle: S2(m) focus-dim should
   isolate it visually within the bundle.

**Counts target:** +100 LOC GraphView wire-up, +50 LOC tests
(~5 integration tests). Bundle target: +2 KB raw / +0.5 KB gzipped.

### Slice 4 — Compose with altitude-staggering

**Cherry-pick + extend.** Takes the altitude branch's `pullSlot` props
and wires them to apply at the BUNDLE MIDLINE level rather than the
individual-edge level.

- Cherry-pick `EdgePath`'s `pullSlot` / `pullSlotTotal` props (~30 LOC).
- Add `PULL_STAGGER_STEP` (default 0.18) signal to `routing-tuning.ts`
  store. Slider lets the user dial altitude variation from 0 (flat
  bundle) to 0.5 (extreme apex spread).
- In `composeEdgePath` (from Slice 2), apply the apex variation to the
  Catmull-Rom midline's control points proportionally to `pullSlot`.
  Endpoint flares are unaffected.
- For singleton clusters, behavior matches the altitude branch's
  current per-edge staggering byte-identically.
- For multi-edge bundles, the lane offset (perpendicular shift) and
  apex variation (parallel shift along the midline's vertical) compose
  cleanly — they vary along different axes.

**Tests:**
- Synthetic 8-edge bundle: each edge's smoothed curve has a measurably
  distinct apex altitude based on `pullSlot`.
- Singleton edges in port-flow regime get the same altitude variation
  as the altitude branch's tip.
- Non-port-flow edges (AES key fan-out): `pullSlot` undefined,
  multiplier short-circuits to 1.0, byte-identical to Slice 3 output.

**Counts target:** +50 LOC in `edge-bundling.ts` + GraphView wiring,
+100 LOC of tests (~8 tests). Bundle target: +0.5 KB / +0.2 KB.

### Slice 5 — Click-to-disambiguate via focus-dim widening

**Small slice; mostly predicate widening + testing.**

- Extend the S2(m) `focusDimActive` / `dimmedEdges` memo in GraphView
  to:
  - When a single edge in a multi-edge bundle is selected, dim all
    OTHER edges in the same bundle.
  - When a node is selected (existing S2(m) behavior), incident edges
    that are part of a bundle: dim the rest of the bundle so the
    incident edge pops within it.
- Pre-existing focus-dim CSS class (`graph-edge-dimmed`, opacity
  0.18, 0.12s transition) carries over unchanged.

**Tests:**
- Selecting `final.s_0 → final.assemble` (one edge in the 8-edge
  bundle) dims the other 7.
- Selecting `final.assemble` (the node, S2(m) behavior): the 8
  incident edges stay vivid; non-incident dim. Unchanged from S2(m).
- Selecting a singleton-cluster edge: no bundle-mates to dim, behaves
  identically to S2(m).

**Counts target:** +30 LOC predicate widening, +50 LOC of tests
(~5 tests). Bundle target: essentially flat.

### Slice 5b — Tuning panel polish

**Small UI slice; runs in parallel with Slices 4 / 5.** The panel was
mounted minimally in Slice 3 so the user could tune during smoke; this
slice polishes it for shipping.

- **`∞` slider tick** rendering for per-class obstacle costs. The
  rightmost slider position renders the literal label `∞`; the
  next-rightmost is `100`. Internally the `∞` position serializes
  to `null` in localStorage (load: `null → Infinity`, save:
  `Infinity → null`).
- **Sub-section grouping** lands in this slice (see the panel-placement
  table). Each group is a nested collapsed `<details>`.
- **`?tune=hidden` URL parameter** — forces the panel to not render at
  all. Escape hatch for demos / screenshots / first-time users.
- **Panel description tooltip** — each knob's label has a `<title>`
  attribute describing what the knob does (the rightmost column from
  the **Knob inventory** table). Hover-to-see-effect tooltip pattern.
- **Reset-button affordance polish** — `Reset this spec` button is
  disabled when the current spec is already at defaults (avoids
  user clicking a no-op button); `Reset all routing` always enabled.
- **Panel-collapsed-by-default invariant test** —
  `tests/routing-tuning-panel.test.tsx` confirms first paint has the
  outer `<details>` element closed AND every sub-section `<details>`
  closed, so the toolbar baseline footprint doesn't grow.

**Deferred (NOT in this slice):** Copy-as-JSON export button. If smoke
shows users want to share or back up tuned configs, add as a follow-up.

**Counts target:** +80 LOC panel polish, +60 LOC tests (~6 tests).
Bundle target: +1 KB raw / +0.3 KB gzipped.

### Slice 6 — Remove diagnostic hatch + close plan

After all five slices ship and smoke green:

- Remove `?no-bundle=1` URL hatch and related diagnostic code.
- Update `CLAUDE.md` "Graph view + persistence" section to mention
  bundling (single sentence).
- Update `docs/help/graph-view.md` with the bundling visual + the
  click-to-disambiguate UX.
- Memory pointer to this plan as "shipped, all 6 slices done".

## Order

Slice 0 first (probes). Slices 1-3 in strict order (each depends on
the previous). Slices 4 and 5 are independent of each other and can
ship in either order after Slice 3 lands.

The plan can pause-and-evaluate after Slice 3: if the smoke shows
bundling is enough on its own, Slices 4 and 5 become optional polish.

Slice 5b (tuning panel polish) is independent of 4 and 5 — it polishes
the panel mounted in Slice 3. Can ship any time after Slice 3 lands.

## Smoke watchpoints

Three known interactions that need eyeball confirmation, not test
verification:

1. **S2(k) port-flow parallel-shift becomes invisible inside bundles.**
   The advisor flagged this as "probably fine pedagogically — the
   parallel-shift's job WAS endpoint disambiguation, which bundle
   flares now handle." Smoke confirms.
2. **Curve aesthetic match.** Catmull-Rom curves vs. the existing
   cubic Bezier in clear cases. They should look visually similar
   enough that a user doesn't notice the regime switch. If they
   don't, switch clear cases back to cubic-Bezier (the `PathSpec =
   { kind: "default" }` sentinel preserves this option).
3. **Bundle behavior at zoom-in.** When the user pans/zooms in on a
   dense bundle, the flares' relationship to the midline should
   remain visually correct. If the midline "drifts" relative to the
   flare anchor points at extreme zoom, the flare-length formula
   needs `0.2 * edgeLength` rather than the fixed 30 px.
4. **CBC feedback arc visual continuity.** Slice 3 removes the
   hardcoded overhead arc; the new geometry comes from A\* +
   `isFeedback` directional bias. The shape SHOULD look essentially
   the same as today's arc (exit-top, peak around y=10, enter-top),
   but the path will be Catmull-Rom smoothed through A\* waypoints
   rather than a single cubic Bezier. Eyeball test: open AES-CBC,
   confirm the `cbc-snapshot → cbc-xor` feedback arrow still reads
   as a clear overhead loop with no visible regression. If the new
   shape diverges meaningfully (e.g. A\* picks an asymmetric path or
   a side route), the directional-bias strength needs tuning. **Now
   trivial via the Tuning panel** — drag `PULL_NORTHWARD_BIAS` from
   0.30 up toward 0.5, watch the arc re-route in real-time. The
   "fallback constant bump" of the original plan turns into an
   in-browser slider drag.

## What this plan does NOT cover

- **Topology-level fixes** (wider gutters, msg-schedule body folding).
  Filed for separate plan if the 40 %-residual-hits topology problem
  surfaces as user-visible pain after this ships.
- **Replica edges.** Continue to use straight-line / start-dot
  rendering. Replicas don't traverse obstacles by construction (they
  sit immediately next to consumers).
- **Cross-iteration data-dependency visibility (e.g. SHA-256's
  W_{t-2/7/15/16} recurrences).** Today's graph only synthesizes the
  seed-window edges (`inferHistorySeedEdges`, Slice S2(l), iterations
  0..15). The W_t → W_{t+k} cross-iteration edges aren't in the graph
  at all — runtime auto-publishes `aux["prior-N"]` silently, no
  TraceFrame records the handoff. **This is a graph-derivation gap,
  not a routing gap** — you can't route edges that don't exist.
  Belongs in the universal-port-dataflow plan family (extend
  `inferHistorySeedEdges` to synthesize ~128 cross-iteration edges
  for the expanded msg-schedule body). Once those edges exist, THIS
  plan's routing renders them as bundles automatically.
- **A LIBRARY-grade router.** This plan ships a small focused
  algorithm (~500 LOC total across slices) that handles the
  Cryptographer's graph density. A future scale-up to libavoid-style
  routing is out of scope.
- **Bundle inspector / tooltip** that surfaces the N constituent edges
  of a bundle. Possible polish if Slice 5's click-disambiguate feels
  insufficient.
- **Performance optimization beyond the obvious.** A* with spatial
  index caching is fast enough at SHA-256's density. If a future
  spec (large SHA-512? AES-256 with all rounds expanded?) pushes
  render time past 200 ms, a separate perf slice can revisit.

## Memory pointers

- [[project_sha_256_density_polish_plan]] — direct predecessor; the
  S2(j)/(k)/(m) slices established that crowding has three distinct
  geometric causes (fan-IN slot collapse, midline convergence,
  steady-state shared corridor) and that interactive solutions
  (S2(m) focus-dim) only address one of them.
- [[feedback_iterative_slice_review]] — multi-phase plan; re-consult
  the advisor before each new slice in light of what's been built.
- [[project_hash_future]] — hash density was what surfaced the
  routing limits. Future SHA-512 / SHA-3 will have the same shape.
- [[project_universal_port_dataflow_proposal]] — port-flow edges are
  the dense case; the bundling target is precisely the (cluster
  → cluster) shape that port-flow specs produce.
- [[feedback_advisor_visibility]] — preserve advisor responses
  visibly across all slice reviews.
- [[feedback_check_remote_before_work]] — Slice 0 runs from a clean
  `git fetch` baseline.

## Pointers in this repo

- `src/ui/graph/edge-router.ts` (router branch) — obstacle index +
  lane assignment + corner rounding. Cherry-picked / reused.
- `src/ui/components/GraphView.tsx::EdgePath` — the rendering entry
  point. Lines ~6916-7418.
- `src/ui/components/GraphView.tsx::geom()` — the per-edge path
  computation. Three regimes (vertical, feedback, horizontal); this
  plan adds a fourth (`bundled`).
- `tests/graph-view-altitude-staggering-measure.test.tsx` (altitude
  branch) — pattern for measuring rendered SVG geometry.
- `tests/edge-router.test.ts` (router branch) — pattern for pure-
  function routing tests.
- `docs/plans/sha-256-density-polish.md` — direct predecessor;
  S2-next section captures the explore-branch outcome that triggered
  this plan.
