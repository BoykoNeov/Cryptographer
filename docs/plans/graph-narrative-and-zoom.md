# Graph narrative + zoom + drop-gutters — multi-slice plan

Captured 2026-05-15. Successor to `graph-readability-polish.md`. Picks up
where that plan ran out: the user did a manual pass on the post-CBC graph
view and surfaced seven items in one go. This plan splits them into seven
slices so future sessions can pick up any one of them without re-deriving
the design decisions.

## Context

The graph view (`src/ui/components/GraphView.tsx`) currently shows leaves
+ containers + state/aux edges with replication + collapse + drag + a
collapsible replication-overrides panel. After three polish sessions on
the same plan it's still missing a "where does the cipher start / end"
frame (pedagogical gap), a way to inspect the data flowing through any
specific edge at the current scrubber position (replaces the obstructed
edge-tooltip), zoom (legibility on wide ECB), a "before-first" drop
position (drag flow gap), and several visual fit-and-finish items the
polish plan already enumerated.

Two design questions answered up-front via `AskUserQuestion` (2026-05-15
session):

1. **Drop "before-first" convention:** thin highlighted **gutters**
   between leaves and at start/end of container bodies, visible only
   during a palette drag. Preserves the existing "drop on container
   header = after the container in its parent" Slice 8 semantic. (The
   other options — per-leaf quadrants, container-header-as-at-start —
   were rejected: the first is invisible; the second breaks learned
   behavior.)

2. **Plaintext/ciphertext nodes on decrypt:** **labels swap, layout
   stays left-to-right.** The decrypt spec already runs in decrypt order
   so the input pill is labelled "ciphertext" and the output pill
   "plaintext" — no graph mirroring. Avoids breaking the established
   "time flows rightward" convention.

One design question still **OPEN** — not in any slice, requires user
input before code:

3. **State-edge replication policy** — today the state spine is sacred
   (never replicated; only aux edges fan out). When a source is set to
   "always", the original sits at its spine seat AND a replica sprouts
   next to the consumer — visually three copies of one chip. The two
   coherent fixes are (a) keep current policy and HIDE the original
   when ALL its outgoing edges are replicated (preserves spine, loses
   visual clutter), or (b) replicate state edges too (spine becomes a
   fan, pedagogically muddier). Surface both with sketches before
   committing.

## Critical files

- `src/core/graph.ts` — synthetic endpoint nodes (Slice 1), collapsed-
  iterate block-chip transform (Slice 6), edge value lookup helpers
  (Slice 4).
- `src/ui/components/GraphView.tsx` — pill rendering for endpoints,
  iterate-replica anchor fix, zoom wrapper, edge-inspector hover wiring,
  drop-gutter SVG strips, block-chip layout.
- `src/ui/stores/layout.ts` — add `viewZoom` per-spec.id; persist to
  localStorage alongside pins + collapsed sets.
- `src/ui/stores/view-edge-inspector.ts` — NEW. Hovered edge signal +
  expanded/collapsed state, session-only.
- `src/ui/stores/spec.ts` — `insertStepBefore` mutation (Slice 5) and
  optional `insertStepAtStartOfContainer`.
- `src/core/spec-mutations.ts` — backing pure function for the above.
- `src/core/format.ts` — reused by Slice 4 for value rendering; may need
  a "first-N-then-…" variant for big `MatrixState[]` arrays.
- `src/ui/app.css` — gutter styles, zoom-button styles, pill node
  styles, inspector panel.

## Sequencing

Slices are independent except where noted. Suggested order: 1 → 2 → 3 →
4 → 5 → 6 → (7 design pass when user is ready). Each slice ships in its
own commit so any can be reordered or skipped.

---

## Slice 1 — Plaintext/ciphertext synthetic endpoint nodes

**Goal:** Make the graph self-evidently "this is the cipher's I/O."
Today a new viewer sees `key-expansion` and `split-blocks` on the left
of the canvas and has no signal that plaintext enters there.

**Approach:**

- Add synthetic `__cipher_input__` and `__cipher_output__` node ids
  with `kind: "endpoint"` (new node-kind) — they're NOT in the spec,
  so don't try to round-trip them through save/load.
- Inject in `deriveAuxGraph` AFTER the spec-walk pass, BEFORE
  `replicateHighFanoutSources`. One state-kind edge from input-pill →
  first `rootIds[0]`; one from `rootIds[last]` → output-pill.
- Label by mode: encrypt → `"plaintext"` / `"ciphertext"`; decrypt →
  swap. Read mode from `App.tsx` via existing signal; thread to
  `deriveAuxGraph` as a parameter (it already takes the spec; add a
  second `{ inputLabel, outputLabel }` arg).
- Render as a **rounded pill** (`rx={LEAF_H / 2}`) in
  `GraphView.tsx` — visually distinct from rectangular leaves, with a
  separate CSS class `graph-endpoint-pill`. Fill = subtle accent
  color, NOT one of the leaf/container colors.
- **Not deletable, not drop-anchor, not click-scrubbable.** Drop
  `data-drop-anchor` on the wrapping `<g>`; set `tabindex` undefined;
  hide the delete glyph; skip the click-to-scrub `onClick` because
  there's no trace frame to land on.
- **Exclude from `buildIterateFeedbackPredicate`:** any edge touching
  `__cipher_input__` or `__cipher_output__` must NOT be classified as
  feedback. Add an early-return in the predicate (`if (from.startsWith
  ("__cipher_") || to.startsWith("__cipher_")) return false`).
- **Exclude from `validateGraph`:** synthetic nodes shouldn't surface
  orphaned-read warnings. Add the same id-prefix check.

**Tests:**

- `tests/graph-derivation.test.ts` (or extend existing) — assert two
  new nodes appear at the canvas extremes, with the expected labels
  in encrypt vs decrypt mode.
- Snapshot test that AES-128 ECB graph has exactly one edge from input
  pill → `split-blocks` (i.e. the first root step).
- Regression: collapsing the entire iterate body and the input-pill is
  still visible (it's a root sibling, not a child of the iterate).

**Files:** `src/core/graph.ts`, `src/ui/components/GraphView.tsx`,
`src/ui/app.css`, `tests/`.

---

## Slice 2 — Iterate-replica anchor fix (polish-plan #1)

**Goal:** Stop the long sweeping arrow from collapsed-fan-out replicas
to the top-center of a wide iterate.

**Approach:**

- When a replica's consumer is an iterate container, anchor the
  replica at `(consumer.childIds[0]'s x, consumer.y - LEAF_H -
  STACK_GAP)` — directly above the iterate body's first leaf, where
  the aux is semantically read.
- Special-case in `layoutRoot`'s replica-placement loop. Existing
  replica placement for leaf consumers stays unchanged.
- Edge routing already targets the consumer's top edge — the move
  shortens the visual arrow significantly without touching `EdgePath`.

**Tests:**

- `tests/graph-view-layout.test.ts` — fixture with
  `compute-block-count → ecb-blocks (iterate, w=400px)`. Assert
  replica x equals iterate's first-child x ± half a leaf width.

**Files:** `src/ui/components/GraphView.tsx`, `tests/`.

---

## Slice 3 — Mouse-wheel + button zoom

**Goal:** Legibility on wide canvases (AES-128 with 10 rounds visible
spans ~1800px today). Users can zoom out to see structure, in to read
labels.

**Approach:**

- New `viewZoom: number` per `spec.id` in `src/ui/stores/layout.ts`.
  Default 1.0; range [0.5, 2.0]; step 0.1 for buttons, finer for wheel.
- Apply via SVG `viewBox`: keep canvas dimensions in DOM as
  `canvasW * zoom × canvasH * zoom`, viewBox stays `0 0 canvasW
  canvasH`. The browser scales the rendered SVG accordingly.
- Wrap the canvas in a scrolling div (already exists); listen to
  `wheel` on that wrapper. On `ctrlKey || metaKey` modifier, treat
  as zoom (matches OS conventions); else default scroll. Always
  `preventDefault()` on zoom events.
- Toolbar additions to the graph header: `[−] 100% [+] [reset]`.
  Reset returns to 1.0 AND clears horizontal scroll.
- Center-on-cursor zoom is nice-to-have; ship center-on-canvas first
  (cheaper: just changes the SVG dimensions).
- Persist to localStorage via the existing layout `Map<spec.id,
  LayoutSpec>` mechanism. `LayoutSpec` gets one new optional field
  `viewZoom?: number`.

**Tests:**

- Unit: `setViewZoom`/`useViewZoom` round-trip, clamp at min/max.
- Component: clicking `+` button increments zoom; clicking reset
  returns to 1.0.
- Skip mouse-wheel test in jsdom — the wheel handler depends on
  layout dimensions jsdom doesn't compute. Defer to manual browser
  check.

**Files:** `src/ui/stores/layout.ts`, `src/ui/components/GraphView.tsx`,
`src/ui/app.css`, `tests/`.

---

## Slice 4 — Edge inspector panel (replaces tooltip) — SHIPPED 2026-05-15

**Status:** shipped. Pure value-lookup helper in
`src/core/edge-value-lookup.ts`; view store in
`src/ui/stores/view-edge-inspector.ts`; rendering + hover/click wiring
in `GraphView.tsx`; CSS in `app.css`; help paragraph in
`docs/help/graph-view.md`. Pin-on-click stays in v1 (the killer demo is
"pin an edge, scrub the trace, watch the value change frame-to-frame").
Pin clears on spec.id change via a `createEffect(on(() => spec().id))`
so a stale pin from a prior spec can't render against ids that no
longer exist. 23 new tests (15 lookup unit + 8 panel component); suite
at 958 across 79 files.

**Goal:** Show the data flowing through any specific edge at the
current scrubber position. Replaces the existing `<title>` tooltip
which is obstructed by oversize mouse cursors.

**Approach:**

- New store `src/ui/stores/view-edge-inspector.ts`: signals for
  `hoveredEdgeKey`, `pinnedEdgeKey` (click to pin so the value stays
  visible while moving the cursor), `inspectorPanelOpen`.
- Edge key = `${from}|${to}|${auxKey}|${kind}` — uniquely identifies
  an edge in the post-replication graph.
- In `GraphView.tsx`, attach `onMouseEnter` / `onMouseLeave` to each
  `<path>` in the `EdgePath` component. On enter, set hovered key; on
  leave, clear it (unless pinned).
- Render a collapsible panel BELOW the replication-overrides panel,
  using the same chevron-toggle pattern shipped in
  `view-replication.ts`. Title bar shows the hovered/pinned edge's
  short id; body shows:
  - **kind** badge (state / aux / feedback)
  - **auxKey** (for aux edges) or "state output"
  - **value at current scrubber's frame and blockIndex** —
    - aux edges: `consumer.frame.auxRead.get(auxKey)` — typically a
      bytes/matrix value.
    - state edges: predecessor's `frame.state` (the value that flows
      out of the source into the consumer).
  - For `MatrixState[]` (e.g. `output-blocks` after the iterate),
    show first 6 blocks + "… N more" with a click-to-expand toggle.
- Reuse `src/core/format.ts` formatters for hex/decimal/ascii toggle
  — the panel respects the App-level byte format.
- Pin-on-click: clicking an edge toggles pinning. Pinned edge gets a
  visual halo so the user knows it stays selected.

**Edge cases:**

- Synthetic endpoint pills' edges (Slice 1) have no consumer frame
  with `auxRead` — fall back to "input plaintext" / "output
  ciphertext" literal display.
- Feedback edges' aux value at iteration 0 is whatever the iterate's
  initial IV was; at iteration N it's iteration N−1's output. Handle
  in the lookup helper.

**Tests:**

- Unit: edge value lookup for both kinds against a canned trace.
- Component: hover an edge → panel shows expected value; pin → panel
  stays after mouse leaves; change scrubber → panel re-renders.

**Files:** new `src/ui/stores/view-edge-inspector.ts`,
`src/ui/components/GraphView.tsx`, `src/ui/app.css`, `tests/`.

---

## Slice 5 — Drop gutters for "before-first" position

**Goal:** Let users drop a palette step at the FIRST position inside a
container, today impossible because the only `data-drop-anchor`s are
leaves (which insert AFTER) and container outers (which insert AFTER
THE CONTAINER IN ITS PARENT, per Slice 8 semantic).

**Approach:**

- New spec mutation: `insertStepBefore(spec, anchorId, leaf)` in
  `src/core/spec-mutations.ts`; expose via
  `insertStepIntoSpec(stepType, { kind: "before", stepId })` in
  `src/ui/stores/spec.ts`. (Keeping the existing `{ kind: "after" }`
  and `{ kind: "root-append" }` branches untouched.)
- Optionally also `{ kind: "at-start", containerId }` — useful for
  "drop into an empty container" if any ever become empty. Defer
  until Slice 6 lands and creates such a case.
- In `GraphView.tsx`, during a palette drag (signal already exists
  via `useActiveDragStepType`), render thin SVG `<rect>` strips:
  - Between consecutive siblings inside each container body
    (horizontal strip at the gap's mid-y, full container width
    minus padding).
  - At the start of each container body (top of the first child).
  - At the end of each container body (bottom of the last child) —
    redundant with the existing per-leaf "after" anchor but matches
    user expectation that gutters exist symmetrically.
- Each strip carries `data-drop-gutter="before:${nextSiblingId}"` or
  `"after:${prevSiblingId}"`. Drop handler reads it BEFORE walking
  to `data-drop-anchor` (gutter wins over anchor; without this the
  gutter falls through to the parent container's anchor).
- Strips are `pointer-events: all` during drag, `none` otherwise.
- Hover style: subtle accent fill + 2px outline so the user sees
  exactly where the drop will land.

**Tests:**

- Unit: `insertStepBefore` produces expected spec, throws on stale id.
- Component: drag a palette item, hover a gutter, drop → new step
  lands at the gutter's position. Three cases: between siblings,
  at start of container, at end of container.
- Pin: drop at start of `round.1` (today impossible) puts the new
  step before `round.1.sub-bytes`. Update
  `tests/built-from-palette-roundtrip.test.tsx` with a "drop at
  first position" assertion.

**Files:** `src/core/spec-mutations.ts`, `src/ui/stores/spec.ts`,
`src/ui/components/GraphView.tsx`, `src/ui/app.css`, `tests/`.

---

## Slice 6 — Collapsed iterate → N parallel block-chips (polish-plan #5)

**Goal:** Collapsing the ECB iterate doesn't lose the "N parallel AES
copies" story. Today it becomes one chip with a `×N` badge — the
narrative collapses to a number.

**Approach:**

- New transform `expandCollapsedIterates(graph, collapsedIds):
  CipherGraph` in `src/core/graph.ts`. Runs AFTER `collapseGraph`,
  BEFORE `replicateHighFanoutSources`.
- For each collapsed iterate with `blockSpan = N`:
  - Replace the single chip with `min(N, 6)` chips horizontally.
  - If `N > 6`, render an ellipsis chip after the 5th with title
    `"+${N - 5} more blocks"`.
  - Each chip's id = `${iterateId}@block{i}`; `replicaOf: iterateId`
    so the existing click-scrub-to-source logic Just Works.
  - Each chip's label = `"block ${i + 1}"`.
- For every edge `(?, iterateId, ...)`, produce N (capped) edges,
  one per chip.
- For every edge `(iterateId, ?, ...)`, same fanning.
- Composition with replication (Slice 1 doesn't apply here; this is
  an iterate-specific transform): `key-expansion` set to `always`
  with this transform on produces N tiny key-expansion replicas, one
  per block-chip. Pedagogically excellent.

**Cap:**

- 6 visible + ellipsis. Configurable via a future "expand all" toggle
  if anyone hits a use case.
- For pathological N (1000+ blocks under a 16KB file), defer entirely
  — the user has bigger things to do at that scale.

**Tests:**

- Unit: `expandCollapsedIterates` produces correct node + edge counts
  for N=1 (no-op), N=2, N=5, N=10 (capped), N=100 (capped).
- Component: collapse the ECB iterate → see 6 chips + ellipsis;
  expand → back to one container.

**Files:** `src/core/graph.ts`, `src/ui/components/GraphView.tsx`,
`tests/`.

---

## Slice 7 — Replication chip-crowding + state-edge policy

**User decision (2026-05-15):** **c → b sequencing.** The chip-crowding
fix (placement-only, no policy change) is shipped first as **Slice 7c**;
the state-edge replication policy change is shipped second as **Slice
7b**. Feistel is the motivator for landing (b) before the next big
cipher pass — its branching state will demand a fan-able spine — so
(b) is no longer "design-blocked," just sequenced after (c).

Original options (a) and (b) for reference:

- ~~**(a) Keep current policy, hide the original when fully replicated.**~~
  Rejected. (b) is structurally cleaner and aligns with Feistel-future.
- **(b) Replicate state edges too.** Drop the `kind === "aux"` filter
  in `replicateHighFanoutSources`. State spine fans into N parallel
  paths through the replicas. Original is removed entirely from the
  graph when fully replicated. Now Slice 7b below.

---

## Slice 7c — Replica placement (chip-crowding fix, kind-agnostic)

**Goal:** Replace today's encounter-order horizontal scatter (per-
consumer index counter that just steps replicas RIGHT by `LEAF_W +
FLOW_GAP`) with **by-source columns above each consumer**: every
replica from source A occupies the SAME row index above every consumer
it touches (globally-stable rows), source B occupies the next row up,
etc. Eye-trackable across the canonical bad case
(N collapsed-iterate chips × M replicated sources) where today the
replicas form a tangled lift-row mush.

Written **kind-agnostic** so Slice 7b drops in additively — placement
keys off `node.replicaOf !== undefined` only, never off the source's
outgoing edge kinds.

**Approach:**

- Extend `buildReplicaPlacement` (`GraphView.tsx:298`) return shape
  from `{ isReplica, consumerOf }` to `{ isReplica, consumerOf,
  sourceOf, rowOfSource }`:
  - `sourceOf: Map<replicaId, sourceId>` — read directly from
    `node.replicaOf` during the existing single-pass walk.
  - `rowOfSource: Map<sourceId, number>` — assign in deterministic
    order (encounter order over `graph.nodes`, which is itself a
    deterministic walk from `deriveAuxGraph`). Globally stable: source
    A is always row 0 across every consumer it touches, even if some
    consumers have no source-A replica (those consumers' row-0 slot
    sits empty; row 1 / row 2 stack above).
- Each placement branch (group `layoutNode`, iterate-body `layoutNode`,
  root `layoutRoot`) reads `row = rowOfSource.get(sourceOf.get(rid))`
  and computes `replicaY = baseY - row * (LEAF_H + STACK_GAP)` instead
  of stepping x by the per-consumer index counter. The horizontal
  position is the consumer's center-x (one chip wide above the
  consumer, stacked vertically). Drop the per-consumer x-step counter
  entirely.
- **Container/root height adjustment:** today's replica lift adds one
  `LEAF_H + STACK_GAP`. New formula: `(maxRowInThisContainer + 1) *
  (LEAF_H + STACK_GAP)` where `maxRowInThisContainer` is the maximum
  `rowOfSource` value among replicas placed in that container's body.
  Containers without replicas keep the old single-row lift = 0.
- **Invariant comment** at the top of `buildReplicaPlacement`: "the
  zone above each consumer hosts ONLY replicas; non-replicated aux
  sources route via long edges from their canvas position, regardless
  of consumer." This is already true today; the comment makes it
  explicit so future readers don't try to "improve" by routing
  non-replicated short edges through the same zone.

**Open micro-decision PINNED (user-confirmed 2026-05-15):**

- **Globally-stable rows over per-consumer compaction.** Costs
  vertical space when sources have non-overlapping consumer sets;
  pays in scannability ("source A's replicas live at row 0 EVERYWHERE
  source A appears"). For AES today (1 main `always`-source) the
  difference is invisible; for the future N-source case (Speck/Serpent
  + Feistel + chains) the stability becomes load-bearing.
- **Threshold for new placement kicks in: always.** No "≥3 replicas
  per consumer" cutoff. Even with 1 replica per consumer the
  by-source row positioning is correct (row 0 above its consumer).
  Removes a special case.

**Tests (kind-agnostic verification — advisor's #1 sharpening point):**

- New `tests/graph-view-replica-placement.test.tsx`:
  1. **Aux-only baseline regression** — fixture matching today's
     AES-128 ECB + `key-expansion → always` graph; assert per-replica
     `(x, y)` matches a snapshot. Ensures the refactor doesn't shift
     existing layout under no-state-replica conditions.
  2. **Multi-source row stability** — synthetic graph with two
     `always` sources A, B both fanning to 3 common consumers and
     1 disjoint consumer. Assert source A's replicas all share one
     y; source B's replicas all share a y one row above; the disjoint
     consumer's row 0 sits empty (vertical gap, source B sits at row
     1). Pins globally-stable rows.
  3. **Synthetic state-kind replicas** — hand-build a graph with
     `replicaOf` set on STATE-kind replica nodes (today
     `replicateHighFanoutSources` won't produce these; we construct
     them by hand to pre-verify Slice 7b's terrain). Assert
     placement is identical to the aux case at the same shape. This
     converts "kind-agnostic" from a claim to a fact and means 7b
     can drop the filter without surprise placement bugs.
  4. **Chip-crowding fixture** — collapsed iterate with `blockSpan
     = 4` (Slice 6 produces 4 block-chips) × 2 `always` sources.
     Assert each block-chip has exactly 2 replicas above it, source
     A on row 0 and source B on row 1, all 4 source-A replicas
     share y, all 4 source-B replicas share y. This is the
     canonical bad case.
- `tests/graph-view-layout.test.ts` — extend Slice 2's iterate-
  replica-anchor test to verify the anchor still works with the
  new row-based placement (anchor x stays at iterate's
  first-non-replica-child x; only y changes by row).
- Snapshot regression on `graph.test.ts` shouldn't fire because
  graph derivation is unchanged; only `GraphView.tsx` placement
  shifts.

**Files:** `src/ui/components/GraphView.tsx` (extend
`buildReplicaPlacement`, refactor three placement loops, add height
formula update), `tests/graph-view-replica-placement.test.tsx` (NEW),
`tests/graph-view-layout.test.ts` (touch up Slice 2 test).

**Out of scope for 7c (deferred to 7b or later):**

- State-edge replication itself (that's 7b).
- Click-to-drag a replica to manually pin its position (today
  pinning is per-stepId; replicas have synthetic ids that change
  across reruns. Probably never want this — would conflict with
  the layout pins decision below).
- "Show original on hover any replica" (the (a) option's affordance;
  rejected with (a) itself).

---

## Slice 7b — Replicate state edges too

**Goal:** Drop the `kind === "aux"` filter at `src/core/graph.ts:967`
inside `replicateHighFanoutSources`. State spine becomes fan-capable;
the original chip is removed entirely from the graph when fully
replicated. Slice 7c's by-source columns absorb the new state replicas
identically to aux replicas.

**Approach:**

- **Edge filter:** delete `if (e.kind !== "aux") continue;` at line
  967 of `src/core/graph.ts`. Now ALL outgoing edges (state + aux +
  feedback) of a qualifying source get replica routing.
- **Eligibility unchanged.** Sources still qualify by aux fanout ≥
  threshold (or `always` override); state edges don't enter
  eligibility. Rationale: state edges are 1:1 today (one outgoing
  per source), so including them in eligibility is a no-op for
  current graphs and a meaningless threshold for any future cipher.
  When Feistel lands and a step has 2 outgoing state edges (L and R),
  it'll typically also have aux fanout high enough to qualify
  independently; if not, the user can flip its `always` override.
- **Original-chip removal:** today line 1082 keeps the source in
  `nodes`: `nodes: [...graph.nodes, ...replicas.values()]`. Change
  to filter out fully-replicated sources:
  `nodes: [...graph.nodes.filter(n => !fullyReplicated.has(n.stepId)),
  ...replicas.values()]`, where `fullyReplicated` is the set of
  source ids whose every outgoing edge was rerouted. Today (and
  post-7b) every qualifying source IS fully replicated by
  construction — `replicateHighFanoutSources` replicates ALL
  outgoing edges of qualifying sources, no partial — so the set
  equals "all qualifying source ids."
- **Incoming-edge handling for the removed source:** the original's
  INCOMING edges (e.g. `aes-encrypt-key → key-expansion`'s state
  edge) have a `to: <originalId>` that no longer exists. Two
  options; pick **redirect to first replica** (matches the spine-
  fan visual — the `aes-encrypt-key`'s state arrow now lands on the
  first replica chip, which IS the canonical spine entry for that
  data flow). Implementation: in the same edge-rewriting pass,
  rewrite `e.to` if `e.to in fullyReplicated` to the replica
  generated for the consumer that follows in the spine
  (`firstReplica = replicaKey(originalId, originalSpineSuccessorId)`).
  Concretely: pick the original's first state-output edge's
  destination as the "spine successor"; its replica is the canonical
  spine entry.

**Open micro-decision PINNED (user-confirmed 2026-05-15):**

- **Original removed entirely** (advisor confirmed: linear-list
  sidebar still finds the source via the trace, not the graph; click-
  to-scrub via `replicaOf` on any replica still works — both already
  shipped affordances).

**Layout-pin orphan handling (advisor's #3 sharpening point):**

- Today `src/ui/stores/layout.ts` stores `pinnedNodes:
  Map<stepId, {x, y}>` per `spec.id`. After 7b, a pin on `key-
  expansion` is orphaned because that id no longer appears in the
  graph.
- **Decision: silently drop orphan pins on load** (advisor option 1).
  Implementation: in the `layoutSpec → effective pin map` resolver
  inside `layoutNode`/`layoutRoot`, ignore pins whose stepId isn't
  in the post-replication graph. Add a one-time `console.debug` per
  orphan id during dev (gated by `import.meta.env.DEV`) so users
  who flip 7b on don't get console spam in prod.
- **Migrate to first-replica id?** Rejected: replica ids are
  synthetic and change shape across reruns
  (`${src}@->${consumer}` — if the consumer is renamed or the
  graph reshapes, the migration target moves too). Cleanest is to
  drop and let the user re-pin if needed.

**Tests:**

- `tests/graph-replication.test.ts` — extend with:
  1. **State-edge replication** — fixture with a source having 1
     state outgoing + 7 aux outgoing (above default threshold 6).
     Assert post-replication graph has 8 replica nodes (one per
     edge), original source is GONE from `nodes`, source's
     incoming edges redirected to the first replica.
  2. **Spine continuity** — same fixture; assert there's a
     reachable path from `rootIds[0]` to the last root step
     traversing replicas (the spine fans through the replica row,
     no longer through a single original chip).
  3. **No-replicate baseline** — when the source is below
     threshold and has no `always` override, the kind filter being
     gone has no observable effect (no replicas, original stays).
- `tests/graph-view-layout.test.ts` — orphaned-pin handling: pin
  `key-expansion`, set its replication to `always`, assert no
  `[pinnedNodes].get("key-expansion")` reads land in the layout
  output.
- `tests/built-from-palette-roundtrip.test.tsx` — sanity round-
  trip check: with `key-expansion → always` set, the spec saves +
  loads cleanly (replication state lives in `LayoutSpec`, not the
  spec; orphan-pin drop on load shouldn't affect spec round-trip).

**Files:** `src/core/graph.ts` (drop filter, filter out fully-
replicated sources, redirect incoming edges),
`src/ui/components/GraphView.tsx` (orphan-pin filter in the
pin resolver), `tests/graph-replication.test.ts`,
`tests/graph-view-layout.test.ts`,
`tests/built-from-palette-roundtrip.test.tsx`.

**Post-7b retuning budget:** ~one afternoon of layout polish
expected. With state replicas in the lift row, the `endpointLabels`
memo (Slice 1's pill anchors) and the iterate's first-non-replica-
child anchor (Slice 2's fix) may need their "skip past replicas"
walks revisited. Retune in a follow-up commit if the test pass
flags shifted positions. **Option C interaction (2026-05-16):**
when a state-fan terminates on a collapsed iterate that has been
expanded into a chip row with a box-with-header wrapper, the two
existing chip-row detection sites (`layoutRoot` anchor +
`visualEdgeTargetId` retarget — see `feedback_collapsed_iterate_design.md`
memory) may need a third sibling to route fanned state edges onto
individual chips rather than the iterate's box header. Discover
during implementation; not worth pre-designing.

---

## Slice 7 ship sequence

Two separate commits (per commit-cadence preference + advisor's #5):

1. **Commit A — Slice 7c.** Placement refactor + kind-agnostic
   tests. Pure additive; no graph derivation change; no policy
   change. Should ship clean through `npm run check` with no
   pin-data migration concerns.
2. **Commit B — Slice 7b.** Filter drop + original removal +
   incoming-edge redirect + orphan-pin handling. The post-7b
   retuning, if needed, lands in a third "Slice 7b polish"
   commit on the same day.

After both ship: update `MEMORY.md` to flip
`project_graph_narrative_zoom_plan.md`'s "Slice 7 design-blocked"
marker to "Slice 7c+7b shipped." Then the user is unblocked to
plan Feistel.

---

## Cross-references

- Predecessor plan (closed): `graph-readability-polish.md`. Items 2, 3,
  6 shipped 2026-05-14; items 1, 4, 5 carried forward into this plan
  (Slices 2, 7, 6 respectively).
- Memory: `project_graph_narrative_zoom_plan.md` (per-slice progress
  tracker), `feedback_graph_design_decisions.md` (drop-gutter +
  decrypt-label-swap decisions from 2026-05-15).
- Critical-files inventory: `docs/key-files.md`.
- User-facing help: `docs/help/graph-view.md` — needs an update after
  Slices 1, 3, 5 ship (new pill nodes, zoom controls, drop gutters).
