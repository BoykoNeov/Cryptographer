# Source color coding for graph-view arrows

**STATUS: SHIPPED 2026-05-19 (commit `f6edb7e`).** Memory entry
`[[project-source-color-coding]]` carries the gotchas + post-ship
notes. Plan body retained for historical context.

Captured 2026-05-19 after the Q1/Q2 graph polish work landed. User
wants per-source edge coloring as a pedagogical aid: every edge from a
canonical source that fans out to ≥ 2 consumers takes a distinct
color, so the eye can track "all these arrows are key-schedule
contributions" vs. "all these are block-count broadcasts" at a glance.

## Context

The graph view today colors edges by **kind** (state spine = white,
aux = grey-blue), with feedback edges dashed and pinned edges haloed.
That communicates "what flows here" but not "where this came from."
For high-fanout sources like `key-expansion` (11 round keys) or the
ECB `compute-block-count` / `split-blocks` aux pair, the user has to
trace each arrow back to its source to disambiguate. Color-by-source
short-circuits that trace.

**Decisions pinned via `AskUserQuestion` 2026-05-19:**

1. **Control surface**: NEW collapsible "sources & colors" panel
   alongside (not inside) the existing replication panel. Replication's
   panel filters on the global threshold; coloring uses fanout ≥ 2 —
   different source sets, so a shared panel would surprise.
2. **Persistence**: viewer-local per-spec, mirroring `view-zoom.ts`
   and `view-density.ts`. Auto-colors derive from graph structure
   (never persisted); manual overrides are the only thing that hits
   localStorage. Document Save/Share stays byte-stable.
3. **Default**: master toggle defaults **ON**. Toolbar checkbox
   `[✓] color by source` next to the existing density/zoom controls.
4. **Edge scope**: ALL edges from a multi-fanout source — aux AND
   state. Slice 7b put state-kind edges on replicas too, so the
   "source identity is primary" pedagogy needs to cover both.

## Goal

Ship one commit that adds:
- A `view-source-colors.ts` store (master toggle + per-spec manual
  overrides map).
- A pure `assignSourceColors(graph) → Map<canonicalSource, color>`
  helper in `core/source-colors.ts`. Deterministic palette walk over
  alphabetically-sorted multi-fanout sources.
- Edge-render integration: when coloring is ON and the canonical
  source has an assigned color, the edge's stroke + arrowhead + bundle
  ×N pill + replica start-dot all use that color. Single-fanout edges
  retain today's kind-based coloring.
- A new `<SourceColorsPanel />` component rendered above the canvas
  (sibling to the replication panel). Per-source row: color swatch +
  source label + edge-count. Swatch click opens a color picker;
  per-row "reset" button reverts that source to auto; panel-footer
  buttons `[clear all manual]` and `[autocolor now]` (functionally
  the same since clearing manual overrides reverts to auto, but the
  separate framing matches the user's mental model).

## Critical files

- **New:** `src/ui/stores/view-source-colors.ts` — mirrors
  `view-zoom.ts`'s per-spec map shape + `view-replication.ts`'s
  master-toggle pattern.
- **New:** `src/core/source-colors.ts` — `assignSourceColors`,
  `resolveCanonicalSource(edge, graph)`, palette constant
  (Okabe-Ito 8-color set, minus red).
- **New:** `src/ui/components/SourceColorsPanel.tsx`.
- **Edit:** `src/ui/components/GraphView.tsx` — wire the master
  toggle to the toolbar; thread `colorOf(canonicalSource)` into
  `EdgePath`, bundle pill, replica start-dot; render
  `<SourceColorsPanel />` above the canvas.
- **Edit:** `src/app.css` — drop the hard-coded `stroke` rule on
  `.graph-edge` paths in favor of an inline `style="stroke: <var>"`
  when colored mode applies; the kind classes remain as the
  fallback.

## Approach

### Canonical source resolution

```ts
// core/source-colors.ts
export const resolveCanonicalSource = (edge: GraphEdge, graph: CipherGraph): string => {
  const node = graph.nodes.find((n) => n.stepId === edge.from);
  // Replicas have a synthetic id; replicaOf points back to the canonical source.
  return node?.replicaOf ?? edge.from;
};
```

Edges whose `from` is a synthetic endpoint pill (plaintext / ciphertext
input) are NOT colorable — they have no "source" in the
multi-fanout sense. Pill edges retain today's styling unchanged.

### Multi-fanout detection

```ts
const sourceFanout = new Map<string, number>();
for (const edge of graph.edges) {
  if (isEndpointPill(edge.from)) continue;
  const canonical = resolveCanonicalSource(edge, graph);
  sourceFanout.set(canonical, (sourceFanout.get(canonical) ?? 0) + 1);
}
const multiFanout = [...sourceFanout.entries()]
  .filter(([, n]) => n >= 2)
  .map(([id]) => id)
  .sort(); // alphabetical → deterministic color assignment
```

### Palette

Curated base palette of 8 (Okabe-Ito with three substitutions —
minus pure red, reserved for warning glyphs; minus black, swapped
for magenta because it was indistinguishable from the default state
stroke; minus sky blue, swapped for sienna brown because sky blue
read the same as the canvas's `var(--accent)` for un-coloured aux
edges):
`#E69F00 #8C564B #009E73 #F0E442 #0072B2 #CC79A7 #999999 #CC00CC`.

When the number of multi-fanout sources **exceeds 8**, additional
distinct colors are generated algorithmically via golden-angle hue
stepping in HSL:
`hsl((i × 137.508) mod 360, 65%, 55%)` for i ≥ 8, where `i` is the
source's 0-based sorted index. The golden angle gives
maximally-distinct hues at any N, and the fixed S/L keeps every
generated color at similar luminance so the eye doesn't read one
source as "more important" because it happens to be brighter.

Trade-off: generated colors aren't guaranteed colorblind-safe past
i=8. The first 8 sources (the common case for shipped ciphers — AES
key-expansion + 2-3 boundary aux) stay on the curated set.

### Render-time integration

`<EdgePath>` (in `GraphView.tsx`) gains a `stroke?: string` prop. When
defined, the rendered `<path>` gets `style={`stroke: ${stroke}`}`
(inline beats CSS class specificity). Bundle ×N pill text fill matches.
Replica start-dot `fill` matches. The pinned-edge halo (drop-shadow)
needs no change — drop-shadow inherits the stroke color.

### Composition rules

| Existing signal | Behavior under colored mode |
|---|---|
| Kind (state white / aux grey) | Overridden by source color when one is assigned. Single-fanout edges keep kind colors. |
| Feedback dashing | Orthogonal — `stroke-dasharray` rides on top of any color. |
| Pinned halo | Orthogonal — drop-shadow uses the live stroke. |
| Warning glyphs (red dots) | Untouched — node-level overlay, not edge. |
| Endpoint pills | Untouched — not colorable. |

## UI sketch

```
[colors panel header]  sources & colors  [ ▾ ]
─────────────────────────────────────────────
[■ #E69F00] key-expansion        11 edges  [reset]
[■ #56B4E9] compute-block-count   2 edges  [reset]
[■ #009E73] split-blocks          2 edges  [reset]
─────────────────────────────────────────────
[clear all manual]  [autocolor now]
```

Color swatch click → native `<input type="color">` (inline above the
swatch). Per-row reset reverts ONE source to its auto-assigned color.
Panel footer's `[clear all manual]` empties the override map.
`[autocolor now]` is functionally identical (auto colors derive from
graph structure on every render) but matches the user's vocabulary.

Master toggle lives on the graph toolbar:
`density [normal▾] zoom [−][100%][+][reset]  [✓] color by source`.
Disabling hides the colors panel and reverts every edge to kind-based
styling.

## Persistence

`localStorage` blob keyed `cryptographer.viewSourceColors`:

```json
{
  "<specId>": {
    "manual": { "<canonicalSourceId>": "#RRGGBB", ... }
  }
}
```

Master toggle is global (one bool, like `replicationEnabled`) at
`cryptographer.viewSourceColoringEnabled`. Per-spec auto-color
deterministic from graph → never stored. Switching ciphers reloads
that spec's manual overrides; never bleeds across specs.

## Tests

- `tests/source-colors.test.ts` (pure helpers, node env):
  - `resolveCanonicalSource`: replica node → canonical via replicaOf;
    plain node → edge.from; endpoint pill → returns pill id (caller
    handles the early-out).
  - `assignSourceColors`: alphabetical determinism; ≥ 2 fanout only;
    palette cycling at 8+ sources.
- `tests/view-source-colors-store.test.ts` (jsdom, store):
  - Manual override survives master-toggle off → on.
  - Per-spec scoping: setting on spec A doesn't leak to spec B.
  - `clearAllOverrides` empties the map but leaves master toggle ON.
- `tests/graph-view-source-colors.test.tsx` (jsdom, component):
  - Default-ON: a high-fanout source's edges get the expected stroke.
  - Master toggle off: edges revert to kind-based styling.
  - Manual override: changing a swatch updates the rendered stroke
    on every matching edge live.
  - Bundle pill + replica start-dot pick up the color.

## Out of scope (v1)

- Per-edge override (vs per-source) — defer until evidence.
- Animated transitions on color change — visually jarring on every
  graph rerun, skip.
- On-canvas legend / minimap — the panel is the legend.
- Custom palette uploads / theming hooks.
- Exporting the colored canvas to PNG with the colors baked in
  (existing `[save…]` already serializes spec only).

## Position in time

Slot this after today's Q1/Q2 fixes, before the Feistel-plan. The
Feistel-plan benefits from the color-by-source pedagogy when the
branching state lands — two parallel L/R tracks will be easier to
read with their feed-sources colored.
