# Graph framework spikes — xyflow + solid-flow

> **Status:**
>   1. **solid-flow** (1.0.4): **Abandoned at typing survey.** Missing
>      subflow nesting, custom edge types, drop handler. No code
>      written. See [solid-flow result](#result).
>   2. **xyflow (`@xyflow/react` 12.10.2 via React-in-Solid interop):**
>      **Phase 1 shipped.** Adapter + Solid wrapper + view-mode tab
>      built. Render works for AES-128 and AES-128-ECB including
>      3-level nesting and both edge kinds. **Bundle: +121.68 KB
>      gzipped over the 76 KB baseline (197.68 KB total).** See
>      [xyflow Phase 1 result](#xyflow-phase-1-result).
>
> The branch's narrative shifted: when the spike started, the question
> was "which graph framework hosts Slice 8?" That was answered in the
> parallel session by shipping Slice 8 hand-rolled on `main`. The new
> question this branch answers is more open-ended — "if we wanted a
> graph framework as a future-option, what would it cost and how does
> it feel?" Phase 1 of the original plan (build the adapter, render,
> measure) maps to that question directly; Phases 2–5 (palette drop,
> Slice 8 mechanic decision) no longer apply.

A timeboxed evaluation of [`solid-flow`](https://www.npmjs.com/package/solid-flow)
as the rendering + drag-and-drop substrate for Slice 8 of the 2D editor
plan (palette-driven step insertion).

## Context

**Why a spike, not a direct implementation.** Slice 8 needs three
primitives the current hand-rolled SVG `GraphView.tsx` does not have:
clean drag-and-drop from a palette, hit-testing against an arbitrary
canvas position, and a stable "anchor to nearest node" lookup. The
question is whether to grow those into the existing SVG or adopt a
framework whose API already encodes them. Decision quality depends on
running both side-by-side against the same trace.

**Why solid-flow specifically.** Initial direction was the React
xyflow port, but `@xyflow/solid` doesn't exist on npm — only
`@xyflow/react@12` and `@xyflow/svelte@1`. Running xyflow's React
build inside Solid via `react-dom/client.createRoot` interop was
considered and rejected: React 19 + ReactDOM 19 + `@xyflow/react`
would have added ~80 KB gzipped before our adapter code, against a
~72 KB gzipped baseline. `solid-flow@1.0.4` is pure Solid (single dep
on `solid-js`, ~114 KB unpacked), so the bundle math is much friendlier.
The tradeoff: solid-flow is a single-maintainer 1.0.x library, no
significant community footprint. **Maturity is the main question this
spike answers.**

**Coexistence strategy.** Don't replace `GraphView.tsx`. Add a fourth
view mode (`view-mode.ts` currently has `linear` / `graph` / `json` —
add `solid-flow`) so the two implementations render the same trace and
can be flipped between in real time. Run the existing dev on 5173 and
the spike branch on 5174 for true side-by-side.

## Phase 1 — Render AES-128 in solid-flow (2–3h)

Build the adapter, no editing yet.

- **New file**: `src/ui/graph/cipher-to-solid-flow.ts` —
  `cipherGraphToSolidFlow(graph: CipherGraph): { nodes: Node[]; edges: Edge[] }`.
  Containers become solid-flow group/parent nodes; leaves get
  `parentId` set to their containing group; iterates also become
  groups. Two edge kinds → two custom-edge components (aux = curved
  gray, state = animated blue, same semantics as today).
- **New file**: `src/ui/components/SolidFlowGraphView.tsx` — wraps
  solid-flow's `<SolidFlow>` (or whatever root component the library
  exports) with our adapter and a layout pass.
- **Modified**: `src/ui/stores/view-mode.ts` adds `"solid-flow"`;
  `App.tsx` renders accordingly.

**Decision gate.** Open AES-128 and AES-128-ECB side-by-side (5173 vs
5174). Does solid-flow render the 3-level nesting (root → iterate →
round-group → leaves) cleanly? Are both edge kinds visually
distinguishable? If subflow nesting breaks or perf is bad at 41 leaves
+ 10 containers, **abandon here**.

## Phase 2 — Palette + drop (1–2h)

The actual Slice 8 mechanic.

- **New file**: `src/ui/components/StepPalette.tsx` — flat list of
  ~10 step types from `registry.types()`. HTML5 draggable with
  `dataTransfer.setData("application/x-step-type", type)`.
- In `SolidFlowGraphView.tsx`: wire `onDrop` (solid-flow's surface
  must forward the native event with canvas-relative coords; if it
  doesn't, this is a finding). On drop:
  1. Find the nearest existing node by Euclidean distance (the simple
     version of "anchor to a node").
  2. Build a new `StepLeaf` (auto-generated id `<type>-<n>`,
     `params: {}`).
  3. Call `insertStepAfter` from `core/spec-mutations.ts` (Slice 4,
     already shipped).
  4. Push through the spec store; existing 200 ms debounce re-runs.

**Decision gate.** Drag `aes.sub-bytes@1` from the palette, drop it on
the AES-128 canvas mid-round. Does it land in the spec? Does the trace
re-run? Does the new node appear? If yes and the code is small,
solid-flow is winning.

## Phase 3 — Existing stores integration (1h, optional)

Test whether solid-flow's state model coexists with our singleton
stores.

- Wire `onNodeDragStop` → existing
  `layout.ts::setNodePosition` (per-spec.id position store).
- Wire group expand/collapse → existing `layout.ts::toggleCollapse`.
- Skip density + replication overrides for the spike — note in the
  writeup whether they'd map naturally to solid-flow features (zoom
  for density, edge routing for replication) or need parallel
  implementations.

**Decision gate.** Does drag-to-pin still persist into localStorage
and survive a reload? Or does solid-flow fight our store?

## Phase 4 — Measurements (15 min)

- `npm run build` — record gzipped JS delta vs. today's ~76 KB
  baseline (after Slice 7).
- Time `cipherGraphToSolidFlow` + initial render for AES-128 and
  AES-128-ECB. Today's SVG is sub-millisecond; solid-flow with its
  internal layout should still be < 50 ms but worth verifying.
- Run existing test suite (`npm test`): confirm nothing else broke.
  Spike-specific tests come with the writeup; don't migrate the
  existing `graph-view.test.tsx` / `graph-view-drag.test.tsx` — those
  keep pinning the SVG view that ships from `main`.

**Bundle budget**: hard cap at **+50 KB gzipped** (so total stays
under ~125 KB gzipped). solid-flow being pure-Solid should land well
under this; if it doesn't, that's already a finding.

## Phase 5 — Writeup (15 min)

Append a **Result** section to this file before declaring done. One
page:

- What was built (the four files above).
- What worked, with screenshots if helpful.
- What broke or felt awkward, with specifics.
- Bundle delta, perf delta.
- One of three recommendations:
  - **Migrate** — solid-flow becomes the `GraphView` for Slice 8+.
    Phases 1+2 worked, bundle delta under budget, subflow nesting is
    clean, no significant API friction.
  - **Partial** — keep SVG rendering, use solid-flow's DnD primitives
    standalone for the palette layer only. Useful if rendering
    integration was painful but drop-handling was good.
  - **Abandon** — Slice 8 via HTML5 DnD on the existing SVG. Reasons
    specified. Roll back `solid-flow` from `package.json`.

## Risks to flag during the spike

1. **solid-flow maturity.** Single-maintainer 1.0.x library. Could be
   missing features we'd want (custom edges, subflow nesting, drop
   coords). Phases 1 and 2 are the tests; if either gate fails on
   library limitations, abandon.
2. **Subflow nesting at depth 3** (root → iterate → round-group →
   leaf). xyflow's React side reportedly gets flaky here; verify on
   AES-128-ECB specifically since iterate-with-nested-round-groups is
   the deepest realistic case.
3. **Two custom edge kinds.** Need one Solid component per kind for
   marker + class semantics. Routine but non-zero work; check whether
   solid-flow's API supports it before committing to Phase 2.
4. **Bundle weight.** Pure-Solid library, so it's smaller than the
   React path would have been. Still set the hard +50 KB gzipped
   budget. Over that, the answer is "no" regardless of API quality.
5. **Test isolation.** Don't replace existing tests. New view → new
   tests; existing tests keep guarding the SVG implementation that
   ships from `main`.

## What this spike explicitly does NOT do

- Replace `GraphView.tsx`. Both views coexist.
- Implement Slices 9, 10, 11.
- Port replication overrides, density, label truncation — assess
  whether they'd port; don't actually port.
- Polish anything. Ugly palette, approximate drop anchoring — fine
  for a spike.
- Touch the linear / JSON view tabs.

## Cross-links

- 2D editor master plan: `~/.claude/plans/peppy-knitting-fairy.md`
- Per-slice progress: memory `project_2d_editor_plan.md`
- Today's SVG implementation: `src/ui/components/GraphView.tsx`,
  `src/ui/stores/layout.ts`, `src/core/graph.ts`
- Slice 4 (already-shipped mutation surface):
  `src/core/spec-mutations.ts::insertStepAfter`

## Result

**Recommendation: Abandon.** Phase 1 stopped at the typing-survey
stage — `solid-flow@1.0.4`'s public API lacks three primitives that
the spike's Phase 1 and Phase 2 gates require. No adapter code was
written; abandon is grounded in primary-source reading of the
shipped `.d.ts` files plus the README's canonical example.

### Findings

The total exported surface is `<SolidFlow>` + two interfaces:

```ts
// node_modules/solid-flow/dist/components/index.d.ts
interface NodeProps {
  id: string;
  position: { x: number; y: number };
  data: { label?: string; content: any };
  inputs: number;
  outputs: number;
  actions?: { delete: boolean };
}

interface EdgeProps {
  id: string;
  sourceNode: string;
  targetNode: string;
  sourceOutput: number;
  targetInput: number;
}

interface Props {
  nodes: NodeProps[];
  edges: EdgeProps[];
  onNodesChange: (newNodes: NodeProps[]) => void;
  onEdgesChange: (newEdges: EdgeProps[]) => void;
}
```

Against the spike's gates:

1. **No subflow nesting.** `NodeProps` has no `parentId` or `type`.
   The 3-level nesting (root → iterate → round-group → leaves) the
   plan named as the Phase 1 acceptance criterion is not expressible.
   The only conceivable workaround — mount a nested `<SolidFlow>`
   inside a parent node's `data.content` — leaves cross-boundary
   edges, coordinate translation, and parent-drag-moves-children
   unsolved.

2. **No custom edge types.** `EdgeProps` has no `type`, `data`, or
   styling fields, and there is no custom-edge component registry.
   Two visually distinct edge kinds (aux = gray curved, state = blue
   animated) cannot be expressed. `data.content: any` customizes
   node *interiors*, not edges.

3. **No drop handler.** No `onDrop` prop on the component. The drag
   primitives that exist (`onMouseDownOutput` / `onMouseUpInput` in
   the internal `NodeComponent.d.ts`) are for drawing edges between
   existing port handles, not for dropping new nodes onto the canvas
   from a palette. This also forecloses the plan's "Partial" exit
   recommendation — there are no usable DnD primitives to keep.

The library is functional for the use case it advertises (flat node
graphs with port-connected straight-line edges). It is not the
right tool for visually structured cipher pipelines with
multi-level grouping and semantically distinguished edge classes.

### Why not push for a workaround

The plan budgets 2–3 h for Phase 1. Faking nesting via nested
`<SolidFlow>` inside `content`, faking edge classes via JSX
overlays, and faking drop via a separate event listener on the
component's outer `<div>` is potentially within that budget — but
the bundle and complexity tradeoff is then *much* worse than the
HTML5-on-SVG alternative. Every Phase 1 criterion would be
compromised before Phase 2 even started. Abandon now is cheaper
than abandon-after-hacking.

### Migration path

Slice 8 ships as **HTML5 DnD on the existing SVG `GraphView.tsx`**:

- `StepPalette.tsx` — flat list of step types from
  `registry.types()`. HTML5 `draggable` on each entry,
  `dataTransfer.setData("application/x-step-type", type)` on
  `dragstart`.
- `GraphView.tsx` — wire `dragover` (preventDefault) and `drop` on
  the root `<svg>`. On drop, convert `clientX/Y` to SVG-canvas
  coords via `getScreenCTM().inverse()` (standard pattern; see the
  existing drag handler for the precedent).
- Find the nearest existing node by Euclidean distance, build a new
  `StepLeaf`, call `core/spec-mutations.ts::insertStepAfter`
  (Slice 4, shipped) — same logic block that the solid-flow Phase 2
  would have run.
- Optional: install `@thisbeyond/solid-dnd@0.7.5` (~5 KB gzipped)
  only if the native event ergonomics feel rough during
  implementation. Defer that decision until we hit friction.

This direction was the third option presented at the start of the
spike. The spike's value is that it makes the choice *defensible*:
we now know solid-flow doesn't fit, by inspection of the actual
shipped types, and the answer is durable until the library has a
major-version API revision.

### Branch cleanup

- `solid-flow` uninstalled from `package.json`.
- `vite.config.ts` `server.port` / `strictPort` reverted; the
  side-by-side coexistence rationale is gone.
- This document remains as the durable writeup. Worth merging to
  `main` (or cherry-picking the doc + the CLAUDE.md / memory
  updates) so the abandon decision survives the eventual deletion
  of `explore/solid-flow`.

### Bundle / perf measurements

Not run — no implementation code was written, so the measurements
the plan called for would not have been meaningful. The abandon
decision rests on API capability, not on observed performance or
bundle weight.

## xyflow Phase 1 result

Picking the spike back up after the solid-flow abandon, with `xyflow`
as the alternate target. Same coexistence pattern — a fourth view
mode (`xyflow`) alongside the SVG `graph` view. Goal: see whether
xyflow can do what our SVG view does (3-level nesting, two edge
kinds), at what bundle cost.

### What shipped on this branch

Five files, ~250 lines of code + ~150 lines of tests:

- `src/ui/graph/cipher-to-xyflow.ts` — pure adapter
  `cipherGraphToXyflow(graph: CipherGraph) → { nodes, edges }`. DFS
  layout: every leaf is a fixed 180×56 box; containers are sized
  innermost-first to fit their children's bounding box plus padding
  (PAD_LEFT/RIGHT/TOP/BOTTOM constants). Two-stage relativization:
  children are placed in absolute coordinates while the parent's box
  is measured, then re-relativized to parent-local coordinates after
  the parent's origin is known. Iterates and groups both render as
  xyflow `type: "group"` nodes; iterates get a `×N` label suffix
  when their `blockSpan` is known.
- `src/ui/components/XyflowGraphView.tsx` — Solid wrapper. Owns a
  sized `<div ref>`, mounts a React root via
  `react-dom/client.createRoot` in `onMount`, re-renders via
  `createEffect(on([spec, traceVersion], render, { defer: true }))`,
  unmounts in `onCleanup`. Renders with `React.createElement` instead
  of JSX so vite-plugin-solid doesn't fight `@vitejs/plugin-react`
  for the `.tsx` extension; the plugin-conflict rabbit hole is
  avoided entirely.
- `src/ui/stores/view-mode.ts` — `ALL_VIEW_MODES` gains `"xyflow"`
  between `"graph"` and `"json"`; `VIEW_MODE_LABELS` gains the label.
- `src/ui/App.tsx` — one new `<Match>` case rendering
  `<XyflowGraphView />` when `viewMode() === "xyflow"`.
- `tests/cipher-to-xyflow.test.ts` — 8 jsdom-free unit tests pinning
  the adapter: node/edge counts, parentId chain for 3-level nesting,
  relative-vs-absolute positioning, iterate `×N` label, edge style
  hints differentiating aux from state, empty-trace fallback, and
  collapsed-container chip rendering. Suite is 596 tests / 48 files
  passing (was 587 before; +1 file, +8 tests, plus a test-renames
  update for the new four-tab tab bar).

### What worked

- **3-level nesting renders.** AES-128-ECB has the deepest realistic
  structure: top-level iterate `ecb-blocks` → group `round.1` →
  leaf `round.1.sub-bytes`. The adapter chains `parentId` correctly,
  containers get explicit width/height, and xyflow positions the
  leaf relative to the round group relative to the iterate
  correctly. The 3-level concern flagged in the original Phase 1
  risks list ("reported flaky on the React side at deep nesting")
  did not bite for our depth.
- **Two edge kinds without custom components.** State edges
  (`#1e293b`, 2.5px, no animation) and aux edges (`#94a3b8`,
  1.25px, animated dashed) are distinguishable via inline `style`
  + `animated` properties on the built-in `smoothstep` edge type.
  No React custom-edge components needed — keeps the bridge code
  tight.
- **Solid↔React interop is small.** The whole bridge is ~40 lines:
  one `createRoot`, one `render(createElement(...))`, one
  `unmount`. No state synchronization or two-way binding —
  Solid signals drive React re-renders, period.
- **Pre-run rendering.** Empty-frames trace produces a
  structure-only graph (containers + leaves + state edges, no aux
  edges). The view tab works before any Run, matching the SVG
  view's behavior. The empty-trace fallback shape mirrors the
  precedent in `GraphView.tsx`.
- **xyflow chrome out of the box.** Built-in `<Background>`,
  `<Controls>`, `<MiniMap>` add visual polish for free —
  navigation controls, zoom/fit/lock buttons, an inset map. The
  SVG view would need each of these hand-implemented.

### What didn't work / what surprised

- **Bundle weight is the headline cost.** Production build:
  197.68 KB gzipped JS (vs. 76 KB baseline) — **+121.68 KB**, a
  2.6× total bundle. React 19 + ReactDOM 19 + `@xyflow/react`
  itself make up most of this. For a learning tool that has to
  load on first paint, this is a meaningful regression — the
  cipher app's whole module surface (every cipher, every step
  type, the trace engine, ALL the UI views) is currently smaller
  than just the React+xyflow runtime would be. Slice 7 (URL
  sharing) added 4 KB; this would add 30× as much.
- **"use client" directive warning.** Rollup logs that the React
  Server Components directive at the top of
  `node_modules/@xyflow/react/dist/esm/index.js` is being
  ignored. Harmless (we're not using RSC), but it's a reminder
  that `@xyflow/react` is built for a meta-framework world and we
  carry that intent in the bundle even though we don't benefit.
- **Layout is naive.** The adapter does a DFS-cursor layout (a
  single horizontal row at each container level). The SVG
  `GraphView.tsx` has *much* more sophisticated routing —
  orthogonal-axis replicas, density rescale, sticky-header, drag
  clamping. Reaching parity would require either porting all that
  logic OR adopting `@dagrejs/dagre` / `elkjs` (more bundle).
  Phase 1 says "skip layout perfection," and the result reflects
  that — readable but flat-looking compared to the SVG view.
- **No replication / collapse integration.** The SVG view applies
  `replicateHighFanoutSources` (so AES's `key-expansion` doesn't
  drop 11 long lines across the canvas) and reads from the layout
  store for collapse + drag-pin state. The xyflow view runs raw
  `deriveAuxGraph` output. That's the spike's deliberate scope
  cut — Phase 2/3 work in the original plan — but it means the
  visual comparison isn't apples-to-apples.
- **Visual smoke confirmed (user, 2026-05-13):** zoomable chain of
  blocks with their internals visible; lines connect
  block-to-block AND within blocks (state spine AND aux edges
  both rendering). Logic correct. Aesthetics weak — "not very
  beautiful." This matches the spike's deliberate layout cut: the
  naive DFS-cursor layout produces a single horizontal row at each
  container level, which makes deeply nested AES round groups
  look cramped vs. the SVG view's mixed horizontal-and-vertical
  flow with orthogonal-axis replicas. Polish would mean reaching
  for dagre/elkjs (more bundle) or porting the SVG view's
  hand-tuned routing (more code on this branch).

### Bundle / perf measurements

```
                  before     after      delta
JS (gzipped)      76 KB      197.68 KB  +121.68 KB (+160%)
CSS (gzipped)    ~5 KB        6.40 KB     +1.4 KB
Modules            ~225       302         +77
Build time        ~1.0s       1.78s       +0.78s
```

Per-step adapter timing is sub-millisecond (not separately
measured; the unit tests run in 10 ms across 8 cases including
AES-128 and AES-128-ECB graph derivation each call, so the
adapter is well within budget).

### Recommendation

**Don't merge this branch into `main` as-is.** The bundle cost is
disqualifying for a learning tool that already ships a working SVG
graph view. Even if xyflow's chrome (MiniMap, Controls, Background)
is nicer than hand-rolled equivalents, the value isn't 121 KB
gzipped of value.

**Keep this branch as a working reference.** Two reasons to keep
it alive rather than delete:

1. If the project ever pivots toward a much larger scope where the
   bundle delta is amortized (e.g. a full visual-cipher-design IDE
   with persistence, real-time collaboration, complex editing
   gestures), xyflow becomes the right tool — and this branch is
   the existing integration to revive.
2. The adapter (`cipher-to-xyflow.ts`) is a useful pattern document
   even outside xyflow: it shows how `CipherGraph` maps to a
   parent/child node graph with sized containers, which any future
   framework (svelte-flow if we change UI stack, d3-dag, etc.)
   would need to do the same mapping for.

**If a future session does adopt xyflow**, the immediate next
steps would be:
- Port `replicateHighFanoutSources` into the adapter so high-fanout
  graphs don't drop long lines.
- Wire the layout store: `onNodeDragStop` → `setNodePosition`,
  group expand/collapse → `toggleCollapse`.
- Custom node component for leaves (Solid renders the leaf body via
  a portal, OR write a small React component that consumes step
  metadata from `data`).
- Investigate whether `@xyflow/react`'s edge routing can be tuned
  to handle the AES round-key fan-out as cleanly as the SVG view's
  hand-tuned routing.

### Files added (`explore/solid-flow` branch only — not on main)

- `src/ui/graph/cipher-to-xyflow.ts` (~200 lines)
- `src/ui/components/XyflowGraphView.tsx` (~120 lines)
- `tests/cipher-to-xyflow.test.ts` (~170 lines)

### Files modified

- `src/ui/stores/view-mode.ts` (+`"xyflow"` entry)
- `src/ui/App.tsx` (+import, +`<Match>` case)
- `tests/graph-view.test.tsx` (tab count assertion: 3 → 4)
- `package.json` / `package-lock.json` (+react, +react-dom,
  +@xyflow/react, +@types/react, +@types/react-dom)

## xyflow Phase 2 result — SVG view's readability tricks ported

Picking the spike up again after the "logic correct, aesthetics weak"
verdict on Phase 1. The user steered next-direction toward "Port SVG
view's tricks" — bring collapse, high-fanout replication, view
density, and drag-to-pin into the xyflow view so the side-by-side
comparison is apples-to-apples instead of comparing a feature-rich
SVG view against a feature-bare xyflow view.

### What shipped on this branch (Phase 2)

Two files modified, no new files, ~80 lines added:

- `src/ui/graph/cipher-to-xyflow.ts` —
  - `XyflowLayoutConstants` type + `BASE_XYFLOW_CONSTANTS` +
    `scaleXyflowConstants(scale)` exported alongside the adapter. The
    adapter accepts an optional `constants` field; defaults to the
    base 1.0× values so the existing 8 adapter tests still pin the
    same numbers byte-for-byte.
  - `XyflowAdapterOptions` adds `pinnedPositions` — a Map of
    root-level `nodeId → {x, y}`. Adapter overrides the just-emitted
    top-level node's `position` when a pin exists; cursor still
    advances by the un-pinned width so siblings don't reflow into the
    pinned node's vacated slot. Pins on non-root ids are silently
    ignored (matches SVG view's Slice 6 container-only-drag scope).
  - Every emitted node gets `draggable: isRoot`, so xyflow's drag
    model fires only on root-level siblings — nested children stay
    locked inside their parent's bounding box.
- `src/ui/components/XyflowGraphView.tsx` — wires four more stores:
  - `useLayoutMap` → pinnedPositions + collapsedGroups +
    replicationModes per active spec.
  - `useViewDensity` → multiplies BASE_XYFLOW_CONSTANTS through
    `scaleXyflowConstants(DENSITY_SCALE[density()])`.
  - `useReplicationEnabled` → gates `replicateHighFanoutSources` on
    top of `collapseGraph` before the adapter conversion.
  - `onNodeDragStop` → `setNodePosition(specId, nodeId, x, y)`. Why
    drag-STOP and not drag-IN-PROGRESS: xyflow handles in-drag
    visuals internally, so we can defer the localStorage write until
    the commit. (SVG view writes on every pointermove because it
    drives the visuals itself.)
  - `onNodeDoubleClick` → `toggleCollapse(specId, containerId)` when
    the target is a container. Why double-click (vs. SVG view's
    chevron): xyflow's default node component doesn't carry a
    chevron, and adding one would require a full custom node
    component (more bundle, more friction for a spike).

The createEffect dependency list grew from `[spec, traceVersion]` to
`[spec, traceVersion, layoutMap, density, replicationEnabled]`. Every
re-render path now reads the same five signals; no derived memos in
this file — render is cheap enough that recomputing the graph
pipeline on each effect tick is fine.

### What worked

- **All four trick categories landed.** Collapse: double-click any
  container, its children disappear and boundary-crossing edges
  terminate at the chip. Replication: flip the global toggle, AES's
  key-expansion stops dropping 11 long lines and instead seeds 11
  local chips next to each AddRoundKey consumer. Density: compact
  shrinks the canvas; spacious grows it; pinned positions rescale via
  the existing `rescaleAllPositions` boundary so dragged containers
  stay in their logical slot across density flips. Drag-to-pin:
  root-level containers + leaves drag freely; nested children stay
  put. Bonus: pinning round.5 doesn't shift round.6's auto-position
  (no visible reflow on pin — same property the SVG view enforces).
- **Same boundaries, no new state.** Phase 2 added zero new stores
  and zero new persistence keys. Every effect routes through the same
  `setNodePosition` / `toggleCollapse` / `setReplicationMode` setters
  that the SVG view uses, so a user who pins in the SVG view sees
  identical pin positions when they flip to the xyflow tab and vice
  versa. The layout sidecar carries through unchanged.
- **Bundle cost is essentially zero.** Production build:
  198.17 KB gzipped (was 197.68 KB before Phase 2; +0.49 KB). React +
  ReactDOM + xyflow's runtime were already paying rent; the new
  wiring is pure adapter code.
- **Test coverage extends cleanly.** 7 new adapter tests pin the
  Phase 2 properties (density scaling, pin override, non-root pin
  ignored, no-sibling-reflow, root-only draggable). Suite is 603
  tests / 48 files passing (+7 over Phase 1's 596).

### What didn't work / surprised

- **Layout is still naive.** Density scaling and replication apply on
  top of the same DFS-cursor layout, which still produces a single
  horizontal row at each container level. Compact + replication ON
  helps visibility a lot (the replicated key-expansion chips now sit
  near their consumers, and at 0.75× the whole pipeline fits in a
  ~1500px viewport), but the SVG view's mixed horizontal-and-vertical
  flow inside iterate bodies is still missing. That's the
  dagre/elkjs escalation the original Phase 1 writeup flagged.
- **No state-edge spine inside groups yet.** The SVG view also lays
  state edges vertically inside groups so AES round bodies read as
  top-to-bottom flows; xyflow renders state edges with the same
  `smoothstep` curve as aux, which works but doesn't visually
  separate the spine from the annotations as cleanly. Cosmetic only;
  fixable with a custom state-edge component if we ever revive this.
- **Pinned-position visual quirk after collapse.** When the user
  collapses a container, the chip lands at the auto-cursor x for the
  new layout, BUT if the user had pinned that container before
  collapsing, the pin position survives (correctly — same property
  the SVG view enforces). The interaction reads fine but it surprises
  on the first try: drag a round, then collapse it, the chip lands
  exactly where the round was. Not a bug.

### Bundle / perf measurements (Phase 2)

```
                  Phase 1     Phase 2     delta
JS (gzipped)      197.68 KB   198.17 KB   +0.49 KB
CSS (gzipped)     6.40 KB     6.40 KB     ±0
Modules           302         302         ±0
Build time        1.78s       2.39s       +0.61s
Tests             596         603         +7
```

The +0.49 KB delta is the per-spec layout lookup, the four extra
signal reads in the effect, and the seven new adapter exports. The
adapter's own pure logic stayed within the same DFS-cursor function;
nothing fundamentally larger.

### Recommendation (Phase 2)

**Don't change Phase 1's recommendation.** Phase 2 closed the
features-gap between the xyflow view and the SVG view for free
(+0.49 KB), but the headline +121.68 KB gzipped from carrying
React + ReactDOM + `@xyflow/react` is unchanged. The "this is a
parallel implementation worth maintaining" bar would need a UI
direction where xyflow's hooks (custom node components, edge
routing plugins, the surrounding ecosystem) are paying for
themselves — Slice 9+ of the 2D editor plan doesn't reach that
threshold.

What Phase 2 does change: this branch is now a more honest
reference point. If a future session adopts xyflow, they don't
need to re-port collapse / replication / density / drag — the
pipeline is already there, and the only remaining gap on the
"reach SVG view parity" axis is the layout aesthetics
(dagre/elkjs).

### Files modified (Phase 2)

- `src/ui/graph/cipher-to-xyflow.ts` (+~50 lines:
  XyflowLayoutConstants, scaleXyflowConstants, options threading,
  per-node draggable flag, root-pin override)
- `src/ui/components/XyflowGraphView.tsx` (+~40 lines: 4 new signal
  reads, transform pipeline wiring, drag-stop + double-click
  handlers, expanded effect dependency list)
- `tests/cipher-to-xyflow.test.ts` (+7 tests, ~80 lines)

