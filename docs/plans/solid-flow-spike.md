# solid-flow spike — Slice 8 mechanic decision

> **Status: in progress.** Branch `explore/solid-flow`, dev server bound
> to port 5174 so it coexists with `main` on 5173. Phase 0 done
> (dependency selected + installed); Phases 1–5 pending.

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

_(Pending — fill in at end of Phase 5.)_
