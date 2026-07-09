# Graph legibility: arrow styles, curated default layouts, undo/redo

## Context

The graph view's central pain point today is **arrow pile-up** — on
dense specs (SHA-256 worst, per the user) overlapping/near-coincident
arrows make it hard to tell which source feeds which consumer. The user
asked for three related capabilities to attack this:

1. **Per-source arrow *style* differentiation** (dotted / short-dash /
   long-dash / dash-dot …) so arrows are distinguishable even when they
   overlap or share a colour.
2. **Curated default *layouts* baked into the shipped ciphers/hashes** so
   the built-ins open pre-arranged (incl. inside default-collapsed
   blocks), instead of raw auto-layout. Plus a "reset to default vs.
   automatic" affordance.
3. **Undo/redo** for editor actions (spec edits + layout moves) — which
   does not exist today.

### What already exists (so we build *on* it, not beside it)

- **Layout already persists and travels.** Dragging containers/nodes
  writes `LayoutSpec` to localStorage (`cryptographer.layouts`, keyed by
  `spec.id`) AND rides Save/Share via the `layout` sidecar in
  `CipherDocument`. Inner nodes of collapsed blocks are already draggable
  (relative pins) and persist. So Ask 2's "export includes layout" is
  **already true** — the genuinely new work is *baking curated defaults
  into the built-ins*.
- **Per-source colour coding** (`core/source-colors.ts` +
  `view-source-colors.ts` + a `sourceColor` prop on `EdgePath`) is the
  exact template for arrow styles — but it is deliberately *viewer-local*
  (never saved). The user chose that arrow **styles should travel with
  the document** — so styles diverge from the colour precedent and live
  on `LayoutSpec`.
- **The SHA-256 pile-up has already been fought hard** (`docs/plans/
  sha-256-density-polish.md`): port-flow replication (S2i), density-aware
  slot caps (S2j), source-side parallel-shift (Case B). The *crossing* and
  *adjacent-convergence* cases are largely handled. The **remaining** hard
  cases are *coincident-corridor* pile-ups (`s_0→assemble` through the
  `s_1..s_7` corridor; Case C's 3 arrows converging at `round.0`) —
  explicitly deferred as hard. **Honest scope note:** dash-styles help
  *crossing* arrows and add a second disambiguation channel for arrows
  that run together, but they will NOT fully resolve corridor-convergence.
  Their strongest justification for SHA-256 specifically: SHA-256 has far
  more distinct sources than the 8-colour Okabe-Ito palette, so colours
  *repeat* — a per-source dash pattern is an orthogonal channel that lets
  the eye trace a source even when its colour collides, and helps
  colour-blind users.

### Sequencing (three independently-shippable parts)

Per the "match scope / don't build a mega-plan" discipline these ship as
three separate PRs, in ascending risk:

1. **Part A — per-source arrow styles** (self-contained, templated, low
   risk). First.
2. **Part B — curated default layouts + reset-to-default** (incremental
   on existing layout machinery). Second.
3. **Part C — unified undo/redo** (architectural, riskiest, its own
   design). Last.

No `schemaVersion` bump is required for any part (Part A adds an
*additive optional field* to `LayoutSpec` within schemaVersion 3,
consistent with how `relativePositions`/`expandedGroups` were added).

---

## Part A — Per-source arrow styles (travel with the document)

### Goal
A per-source stroke *style* — a **multi-channel composite** (dash pattern
× line-cap texture × weight tier × dash phase), auto-assigned to keep many
sources distinguishable and manually overridable, that **rides the
saved/shared document**. Complements the existing colour channel.

### Why multi-channel (not just a longer dash list)
A pure `stroke-dasharray` catalogue tops out around 6–8 patterns before
they stop being reliably tellable-apart in a thicket of thin overlapping
lines (`8 3 1 3` vs `8 3 1 3 1 3` blur together at canvas scale). But
dense specs blow past that: SHA-256 has far more distinct sources than any
readable dash catalogue *or* the 8-colour Okabe-Ito palette (colours
already repeat there). So a style is a **composite of orthogonal channels**
— each channel is individually weak past a point, but their product space
stays separable much longer, and it degrades gracefully (few sources → the
cleanest pure-dash entries; many → compound entries layer in weight/phase).

Four channels, all SVG-native and all composing with the existing
density-scaled width + hover-emphasis:

- **`stroke-dasharray`** — the primary channel (the dash pattern).
- **`stroke-linecap`** — `round` turns a `0 N` (or `1 N`) pattern into
  round *dots*; `butt` gives square *ticks*. A genuinely different texture
  from a near-identical pattern.
- **weight tier** — a *multiplier* (`1` / `1.75`) applied on top of the
  base computed stroke width (so it composes with density + emphasis, not
  an absolute). The single most separable channel at a glance.
- **`stroke-dashoffset`** — a phase shift; two identical patterns interleave
  instead of aligning. Weak alone, so used as the last tie-break tier.

### The style catalogue (ordered, graceful tiers)
One ordered `STROKE_STYLE_CATALOGUE` of *composite* entries. Auto-assign
walks it by canonical-source index, so the earliest (cleanest, pure-dash)
entries get used first and compound entries only appear once a spec has
many sources. Representative ordering (`—` = channel at its default):

| # | name | dasharray | linecap | weight | offset |
|---|---|---|---|---|---|
| 0 | `solid` | — | — | 1 | — |
| 1 | `round-dot` | `0 5` | round | 1 | — |
| 2 | `short-dash` | `4 3` | butt | 1 | — |
| 3 | `long-dash` | `10 4` | butt | 1 | — |
| 4 | `dash-dot` | `8 3 1 3` | butt | 1 | — |
| 5 | `sparse-dot` | `0 8` | round | 1 | — |
| 6 | `dash-dot-dot` | `8 3 1 3 1 3` | butt | 1 | — |
| 7 | `long-short` | `10 4 4 4` | butt | 1 | — |
| 8–15 | `*-heavy` | (re-walk 0–7) | — | **1.75** | — |
| 16+ | `*-phase` | (re-walk with) | — | — | **half-period** |

That's 8 pure-dash × 2 weight tiers × phase = ~24+ reliably distinct
styles before the eye gives out — comfortably past SHA-256's source count,
and every entry still composes with per-source *colour*. Patterns scale
with density like the existing dash usage (cf. `.graph-edge-feedback`
`stroke-dasharray: 4 3` in `app.css`). Keep the whole catalogue in one
pure module so auto-assignment and the picker share it.

### New pure module: `src/core/source-strokes.ts`
Mirror `src/core/source-colors.ts` exactly. The persisted/consumed value
stays a single opaque **name string** (so `LayoutSpec.strokeStyles` is a
plain `{ [sourceId]: string }` map and the picker is one `<select>`); the
catalogue is the one place that expands a name into its channel bundle:
- `type StrokeStyle = { name: string; dasharray: string | null; linecap:
  "butt" | "round"; widthMul: number; dashoffset?: number }`.
- `STROKE_STYLE_CATALOGUE: readonly StrokeStyle[]` — the ordered list above.
- `strokeStyleByName(name): StrokeStyle | undefined` — name → bundle
  (unknown/legacy names fall back to `solid`, so a document written by a
  future catalogue never hard-fails an older build).
- `resolveCanonicalSource(edge, graph)` — reuse/replicate the colour
  module's replica-collapsing logic (or import the shared one from
  `source-colors.ts` if already exported).
- `strokeForSourceIndex(index): StrokeStyle` — index 0 → `solid`
  (baseline, decided), 1+ cycle through the catalogue tail.
- `assignSourceStrokes(graph, threshold)` → `Map<canonicalSourceId,
  styleName>`, deterministic (sources sorted alphabetically, same as
  colours).

### Persistence — on `LayoutSpec` (the divergence from colours)
Because styles must travel with the document, add an optional field to
`LayoutSpec` keyed by canonical source id — modelled precisely on the
existing `replicationModes` per-source override (`layout.ts:470-504`):

```ts
readonly strokeStyles?: { readonly [sourceId: string]: string };
```

Touchpoints (the agent enumerated these — a `.strict()` schema means we
must add the field everywhere or parse rejects it):
1. **Type** — `src/core/document.ts` `LayoutSpec` (~line 152).
2. **Zod** — `src/core/document-schema.ts` `LayoutSpecSchema`
   (~450-468, `.strict()`). Add `strokeStyles: z.record(z.string()).optional()`.
3. **localStorage guard** — `isLayoutSpec` in `layout.ts:81-111` (loose
   object check, mirror `replicationModes`).
4. **Composer** — `buildLayoutSpec` in `layout.ts:193-217`. This is the
   unrolled 2×2×2 = 8-branch matrix; a 4th optional field makes it 2⁴=16.
   **Refactor** `buildLayoutSpec` to build `base` then conditionally
   spread each optional field (drop the unrolled matrix) rather than
   enumerate 16 branches — the monomorphism rationale in its docstring is
   outweighed by maintainability at 4 fields.
5. **`hasUserLayout`** — `layout.ts:605-625`: a non-empty `strokeStyles`
   counts as user customization.
6. **New setter** — `setSourceStroke(specId, sourceId, styleName | null)`
   mirroring `setReplicationMode` (drop-empty discipline: clearing the
   last style drops the map entry to stay byte-stable).
7. **`renameLayoutIds`** — `layout.ts:648-704`: styles key on canonical
   source ids (real step ids), so apply the rename map like
   `replicationModes`.

### Runtime plumbing (mirror `sourceColor`)
- **Session master toggle** in a small store (session/localStorage, like
  `view-source-colors.ts`'s `coloringEnabled`) — "style arrows by source"
  on/off, so the auto-assignment can be turned off without clearing the
  saved manual overrides. (The *manual overrides* live on `LayoutSpec`;
  the *auto-assign on/off* is a viewer pref — same split colours use.)
- **`effectiveSourceStrokes` memo** in `GraphView.tsx` (mirror
  `effectiveSourceColors` at ~3081-3089): merge auto-assigned styles with
  the `LayoutSpec.strokeStyles` manual overrides (overrides win).
- **`sourceStroke` prop on `EdgePath`** (declared ~7290, applied at the
  same `<path>`/arrowhead style-merge sites as `sourceColor`, ~7694).
  Carries the whole resolved `StrokeStyle` bundle (or the name), and the
  path applies **all four channels**: `stroke-dasharray` (omit for
  `solid`), `stroke-linecap`, `stroke-dashoffset`, and a `stroke-width`
  that **multiplies** the existing density/emphasis width by `widthMul`
  (do not overwrite it — the emphasis/dim and density math must still win
  their part). `solid` with `widthMul === 1` → all four omitted (no visual
  change from today).
- **Per-edge resolution** at the `sourceColor={...}` memo (~4906): add a
  sibling `sourceStroke={...}` that inlines the same canonical-source
  resolution (`node?.replicaOf ?? edge.from`) and looks the name up via
  `strokeStyleByName`.

### UI: the picker
Extend the existing per-source override panel (the colours panel /
replication panel neighbourhood in the graph toolbar) with a style
dropdown per source row — one small `<select>` of catalogue names beside
the existing colour swatch. Auto-assigned style shown as the default
option; picking one writes via `setSourceStroke`.

**SHIPPED (A3b, 2026-07-09).** The colours panel became a unified
**"source styling"** panel hosting BOTH channels per row: colour swatch +
dash `<select>`. Key decisions taken during the build (recorded so a later
reader doesn't re-litigate them):
- **Panel visibility** = `(colouring || styling) && rows > 0` — gating on
  colour alone would hide the dash dropdown from a strokes-only spec.
- **Row-id union** — `sourceColorRows` now unions manual *stroke* keys
  (`manualSourceStrokes().keys()`) into the id set, else a source with only
  a manual stroke + sub-threshold fanout vanishes (unreachable to reset).
  The auto stroke keys coincide with the auto colour keys (shared
  `multiFanoutSources`), so only the manual-stroke union was needed.
- **Per-channel disable** — the swatch disables when colouring is off, the
  `<select>` disables when styling is off; the greyed control still
  *advertises* the channel exists rather than vanishing.
- **"auto (name)" option** — the `<select>`'s first option (value `""`)
  maps to `setSourceStroke(id, null)` (clear override) and labels the
  currently auto-assigned style so the user sees the default without
  committing.
- **Shipped default = OFF everywhere EXCEPT SHA-256 (ON)** — user-decided.
  Strokes are the escalation channel for when a spec's source count blows
  past the 8-colour palette; SHA-256 is the only shipped spec that does, so
  it opens pre-styled and the rest stay clean. Implemented as a **per-spec**
  master toggle (`view-source-strokes.ts` reshaped from a single global bool
  to a `{ [specId]: boolean }` override map + `defaultStrokeStylingFor`
  prefix-matching `sha-256`), with drop-on-match persistence so "reset"
  returns to the shipped default. Verified in-browser
  (`e2e/exploratory-hash-and-edges.spec.ts` "A3b" block): SHA-256 opens
  dashed, and a manual override survives reload via the persisted LayoutSpec.

### Tests (same commit)
- `source-strokes.test.ts` — determinism of `assignSourceStrokes`,
  catalogue cycling, canonical-source collapsing (mirror
  `source-colors.test.ts`).
- `document`-roundtrip: a `LayoutSpec` with `strokeStyles` serializes +
  parses byte-stably; empty map omitted (byte-stability gate).
- jsdom: an edge from a styled source renders the expected
  `stroke-dasharray` / `stroke-linecap` / `stroke-dashoffset`, and its
  `stroke-width` is the base width **times** `widthMul` (not replaced —
  assert a non-1 tier stacks on the density width); toggling the master
  toggle off reverts every channel to the un-styled path.
- `strokeStyleByName` returns `solid` for an unknown/legacy name (forward-
  compat: a doc written by a future catalogue opens on an older build).
- `hasUserLayout` returns true when only `strokeStyles` is populated.

### Decided
- **Index 0 = `solid` baseline** (user-confirmed) — styles mark the *extra*
  sources; a single-source graph stays clean, matching how colours only
  fire above a fanout threshold.
- **Multi-channel composite** (user-confirmed) — expanded ~8-pattern dash
  catalogue × line-cap texture × weight tier × dash phase, per the
  catalogue table above. The persisted value stays a single style-name
  string, so the schema/persistence surface below is unchanged.

---

## Part B — Curated default layouts for the built-ins + reset-to-default

> **SHIPPED — B1 mechanism (2026-07-09).** The code deliverable landed
> behavior-neutral: `src/core/default-layouts.ts` (pure `curatedDefaultFor` +
> `mergeLayoutSpecs` + a `__setCuratedDefaultsForTests` seam) with an **empty**
> real catalogue, so `effectiveLayout() === userLayout()` for every shipped spec
> and nothing renders differently until later chunks author layouts. `GraphView`
> split `activeLayout()` → `userLayout()` (customization gates + the stroke
> reader) vs `effectiveLayout()` (all rendering readers: collapse, positions,
> relative pins, replication modes). The reset button splits into "reset to
> default" / "reset to automatic" **only when a curated default exists**
> (`hasCuratedDefault`), backed by a session-only `Set<specId>` suppress signal
> (`src/ui/stores/curated-layout-suppress.ts`). Tests:
> `tests/default-layouts.test.ts` (pure merge/catalogue) +
> `tests/graph-view-curated-layouts.test.tsx` (curated collapse + position reach
> render; per-node merge survives a user edit; persist-only-edited-key
> byte-stability; reset split + disabled logic + suppress round-trip). Full
> `npm run check` GREEN (219 files / 2514 pass / 2 skip).
>
> **KEY DIVERGENCE from the design below (user-decided 2026-07-09):**
> `effectiveLayout()` is a **per-node MERGE** (`mergeLayoutSpecs(curated, user)`,
> user wins per id), NOT the whole-object `userLayout() ?? curatedDefault` the
> "Apply seam" section specifies. Rationale: with the `??`, the *first* drag on a
> curated spec drops the whole curated arrangement back to auto-layout (only the
> dragged node stays pinned); the user chose curation-preserving merge instead —
> dragging one node persists only that node while the rest keep their curated
> spots. Byte-stability is unaffected: persistence baselines read the raw
> `layoutMap` entry (`setNodePosition` etc.), never the merge, so a drag persists
> exactly one key. `strokeStyles` is deliberately **excluded** from the merge —
> arrow styles are a viewer channel read off the USER layout (SHA-256's
> auto-assignment covers the only spec that needs them), so curated layouts carry
> none.
>
> **Forward note for the authoring chunks (B2+):** curated positions never enter
> `layoutMap`, so `rescaleAllPositions` (the density-flip rescale) will NOT
> rescale them — a curated position-bearing layout authored at one density sits
> at the wrong scale after a density flip. The authoring chunk needs either a
> canonical authoring density or a rescale-at-read strategy for curated pins.

### Goal
Ship the built-in ciphers/hashes with a hand-arranged layout (positions,
sensible collapses, and — for Part A — curated arrow styles) so they open
legible instead of raw auto-layout. The curated layout is the *default*;
user drags still override it and still persist/travel as today.

### Storage: a pure `specId → LayoutSpec` map
New pure module `src/core/default-layouts.ts` (no Solid/DOM), mapping the
stable built-in `spec.id`s (`"aes-128@1"`, `"sha-256@1"`, `"des@1"`,
`"serpent-128@1"`, `"speck-32-64-be@1"`, `"rsa@1"`, plus decrypt/mode
variants) → a curated `LayoutSpec`. Ids are stable string literals /
deterministic template builds (verified), so keying on them is safe.

Keeping it a standalone map (not a field on `CipherSpec`) avoids touching
the document format and keeps built-in specs canonical.

### Apply seam: read-time fallback (do NOT persist)
The single read seam is `activeLayout()` in `GraphView.tsx:2429-2432`
(`m[spec().id] ?? null`). Split into two concepts to resolve the tension
the exploration flagged:

- **`userLayout()`** = `layoutMap()[spec().id] ?? null` — ONLY the
  localStorage/user entry. Gates the reset button + `hasUserLayout`.
- **`effectiveLayout()`** = `userLayout() ?? curatedDefaultFor(spec().id)
  ?? null` — what actually drives rendering.

The curated default is a **pure read-time fallback**: never written to
localStorage, so Save/Share byte-stability is untouched (a user who
hasn't dragged anything still saves *no* layout sidecar; the recipient
re-derives the same curated default from the built-in id).

Every current reader of `activeLayout()` for *rendering* (collapsedSet,
positions ~2460, 2503, 2526, 2539) switches to `effectiveLayout()`.
Readers that gate *user customization* (reset-button disabled state)
stay on `userLayout()`.

### Reset semantics — two actions
Replace the single "reset layout" button (`GraphView.tsx:5154-5171`,
currently `setLayoutForSpec(id, null)`) with a small split:
- **"Reset to default"** — `setLayoutForSpec(id, null)`; effectiveLayout
  falls back to the curated default. Enabled when `userLayout()` is
  non-null (there's a user override to discard). For a built-in WITHOUT a
  curated default this is identical to today's "reset to automatic".
- **"Reset to automatic"** (only meaningful when a curated default
  exists) — clears to pure auto-layout, ignoring the curated default.
  Needs a per-spec "suppress curated default" flag (a viewer-local
  signal, not persisted — same class as zoom/density prefs). When set,
  `effectiveLayout()` skips the curated fallback for that spec.id until
  reset again.

**Decided (user-confirmed): the suppress flag is session-only.** "Reset to
automatic" needs it because we can't represent "explicitly empty" in
localStorage without a sentinel that breaks byte-stability. So it's a
session-only `Set<specId>` signal — reloading the page brings the curated
default back. This matches every other viewer-local pref (zoom, density,
replication toggle — none survive reload). Persisting "automatic" across
reloads is an explicit non-goal for v1 (it would reintroduce the sentinel
we're avoiding); it can be a clean follow-up if the need proves real.

### Authoring the curated layouts
The layouts themselves are content, produced by arranging each built-in
in the running app and capturing the resulting `LayoutSpec` (there's an
existing Save path that emits exactly this JSON). Start with the worst
offender (SHA-256), then AES, DES, Serpent, Speck, RSA. Include inner
positions for default-collapsed blocks so expanding shows the arrangement.
This is iterative and browser-driven; the *mechanism* (map + fallback +
reset) is the code deliverable, the *layouts* are data filled in per
cipher.

### Tests (same commit as the mechanism)
- `default-layouts.test.ts` — every curated `LayoutSpec` validates
  against `LayoutSpecSchema`; ids present in the map correspond to real
  built-in spec ids (cross-check against the `defaults`/`hashDefaults`
  tables).
- jsdom: with no user layout, a built-in that HAS a curated default
  renders from it; a user drag overrides it; "reset to default" restores
  the curated one; "reset to automatic" clears to pure auto (suppress
  flag).
- Byte-stability: a built-in with a curated default but no user drags
  still produces a layout-less Save (curated default never persisted).

---

## Part C — Unified undo/redo (spec edits + layout moves)

### Goal
`Ctrl+Z` / `Ctrl+Shift+Z` (+ `Ctrl+Y`) and toolbar buttons that undo/redo
**both** spec edits (param, rewire, palette/composite drop, delete,
duplicate-round, cross-mode mirrors) and layout moves (drag, collapse,
replication mode, reset) in one unified stack. Snapshot-based.

### Store: `src/ui/stores/edit-history.ts` (new, distinct from run `history.ts`)
Two snapshot stacks (ring buffer, `MAX_UNDO ≈ 50` — run-history's 5 is
too shallow for an editing session). Snapshot shape:

```ts
type EditSnapshot = {
  readonly specs: SpecsByMode;   // WHOLE dual encrypt+decrypt union, by reference
  readonly layoutMap: LayoutMap; // WHOLE map, all spec ids, by reference
  readonly mode: Mode;           // captured but NOT force-restored (view-stable undo)
};
```

Both are captured **by reference — O(1)**: the spec store rebuilds `specs`
with structural sharing (ref-equality early-return) and the layout store
replaces `layoutMap` wholesale on every setter; neither ever mutates in
place, so a captured reference stays valid forever.

**Two hard requirements (document so nobody "simplifies" them):**
- **Observe `useSpecsByMode()`, never `useSpec()`/`activeSpec()`.** Writes
  to the *counterpart* slot (`duplicateRoundInSpec`, the six `sync*`
  mirrors) don't change `activeSpec()`; and a bare mode flip changes
  `activeSpec()` but not `specs`. Observing `specs` captures the former
  and correctly ignores the latter.
- **Capture the whole `layoutMap`, not the active entry** —
  `duplicateRoundInSpec` migrates *both* mode's layout entries via
  `renameSpecLayoutIds`; only a whole-map snapshot reverts that atomically,
  and whole-map restore sidesteps the layout store's drop-empty-on-clear
  discipline.

### Capture: observer + gesture-suspend (Approach A)
One `createEffect(on([useSpecsByMode(), useLayoutMap()], …, { defer: true }))`
installed in App scope captures the *pre-change* snapshot (`on`'s `prev`)
for every mutation in ONE place — far lower risk than threading
`checkpoint()` into ~25 spec/layout mutators and missing one. The effect
must read **both** deps every run (a conditional dep read desyncs `on`'s
`prevInput` and corrupts the next entry).

- **Drag coalescing:** `beginLayoutGesture()` at the top of
  `GraphView.startNodeDrag` (~4287) records the pre-drag snapshot + sets a
  `layoutGestureActive` flag; the observer suppresses *pure-layout* changes
  (`curSpecs === prevSpecs`) while it's set; `endLayoutGesture()` in `onUp`
  (~4411) pushes the single pre-drag entry **iff** the map reference
  actually changed (sub-threshold click → no entry).
- **Multi-write atomic mutators:** wrap `duplicateRoundInSpec`'s three
  signal writes (spec.ts ~1124–1133: `setSpecs` + 2× `renameSpecLayoutIds`)
  in Solid `batch()` so the observer sees one transition = one entry.

### Re-entrancy: reference-identity dedup (NOT a boolean+microtask)
Because the capture effect is *deferred*, a boolean flag cleared
synchronously/microtask can clear before the effect fires → spurious
capture. Instead keep `lastApplied = { specs, layout }`; the apply path
sets it to the snapshot's refs before writing, and the observer's first
clause `if (curSpecs === lastApplied.specs && curLayout === lastApplied.layout) return;`
skips exactly the restore's own writes. Timing-immune; real edits always
mint new references so it never false-skips.

### Apply path — two small new setters
- `spec.ts::restoreSpecsForHistory(specs)` = lean `setSpecs(specs)` (NOT
  `setSpecFromDocument`, which juggles selector signals — those are
  invariant within a stack because we clear on any selector switch).
- `layout.ts::replaceLayoutMap(map)` = `setLayoutMapSignal(map); persist(map)`
  (whole-map authoritative — NOT a per-entry `setLayoutForSpec` loop, which
  hits the drop-empty branches and leaves stale entries).
- Both inside `batch()`. The 200ms debounced rerun fires once and
  regenerates the trace via `setTrace` (frame preserved by stepId) — never
  store traces in snapshots.

### Stack boundaries
**Rule: any selector-driven canonical rebuild clears both stacks; mode
flips keep them; edits accumulate.** The selector signals (cipher,
cipherMode, padding, category/hash/asymmetric) are NOT in the snapshot, so
undoing across a switch would desync spec vs. selectors.

| Event | Behavior |
|---|---|
| Load (`applyDocument` ~707), cipher/cipherMode/algorithm switch, padding switch | **Suppress the transition write, then `clearHistory()`.** (Clear-after alone fails — the deferred observer would repopulate one entry from the stale `prev`.) |
| encrypt/decrypt mode flip (`setMode`) | **Keep** — observer watches `specs`/`layoutMap`, not `mode`, so nothing captured, stack survives. |
| density flip (`rescaleAllPositions` via `setViewDensity`) | **Suppress, 0 entries** — tied to a density signal absent from the snapshot. |
| `toggleCollapse` / `setReplicationMode` | **Keep, 1 entry each** (persisted per-spec layout edits, undoable by design). |

Suppression = a single `suppressCapture` flag checked in the observer,
set/cleared around the guarded writes.

### UI surface
- **Buttons in the App top toolbar** (next to Save/Load/Run — undo spans
  spec+layout+doc, so document-level placement, not the graph toolbar).
  Disable via `useCanUndo()` / `useCanRedo()` depth accessors.
- **Dedicated `installEditHistoryShortcuts()`** (window keydown, mirrors
  `keyboard.ts`), NOT folded into the existing handler (which early-returns
  on `!trace`). **Reuse/lift `isEditableTarget` (keyboard.ts:20)** and bail
  first so `Ctrl+Z` inside plaintext/key/S-box/param inputs does *native
  text undo* — the intended split. Cross-platform: `ctrlKey||metaKey`.

### Tests (jsdom; same commit) — each pins a "which mutations capture" point
Param-edit undo (+ ref-equality on untouched branches survives restore),
redo, **drag-coalescing = exactly 1 entry** (+ sub-threshold click = 0),
**duplicate-round = 1 entry** reverting both specs + both layout entries,
palette drop = 1 entry, **density flip = 0**, **boundary clears with no
spurious post-switch entry** (the deferred-observer suppression test),
mode-flip = 0 entries / stack preserved, **re-entrancy no-loop** (post-undo
depth matches stack math), redo-invalidation on new edit, `isEditableTarget`
bail. Follow `tests/graph-view-nested-leaf-drag.test.tsx` (`resetAll()` +
`__resetEditHistoryForTests`, synthetic `pointerEvt`, flush effects inside
`render`/`createRoot`).

### Top landmines
Deferred-effect re-entrancy (use ref-dedup); boundary suppress-then-clear
(not clear-after); observe `specs` not `activeSpec`; `batch()` the
multi-write `duplicateRoundInSpec`; suppress density's `rescaleAllPositions`;
whole-map restore (not per-entry). Full list in the design notes.

---

## Verification (all parts)

- `npm run check` (biome + tsc + vitest + vite build) is the gate; the
  pre-commit hook runs it.
- **Browser smoke is mandatory for the visual parts** (project rule:
  visual features need browser smoke, not just property tests). Per part:
  - Part A: open SHA-256 graph, enable arrow styles, confirm distinct
    dash patterns per source and that they survive Save → reload / Share
    → open.
  - Part B: open each built-in, confirm it opens pre-arranged; drag →
    override persists; "reset to default" restores curated; "reset to
    automatic" clears.
  - Part C: param edit → Ctrl+Z reverts; drag → Ctrl+Z is ONE undo (not
    per-pixel); redo; typing in a param field is not hijacked by Ctrl+Z;
    cipher switch clears the stack.
- Optional: extend the dormant exploratory Playwright smoke
  (`e2e/exploratory-hash-and-edges.spec.ts`) reactively — do NOT add to
  `npm run check`.

## Critical files

- **Part A:** `src/core/source-strokes.ts` (new), `src/core/document.ts`,
  `src/core/document-schema.ts`, `src/ui/stores/layout.ts`,
  `src/ui/components/GraphView.tsx` (EdgePath + effective memo + picker),
  `src/ui/app.css`, a small session toggle store.
- **Part B:** `src/core/default-layouts.ts` (new),
  `src/ui/components/GraphView.tsx` (`activeLayout` split + reset split),
  a session suppress-flag signal.
- **Part C:** new `src/ui/stores/edit-history.ts` (distinct from run
  `history.ts`), `src/ui/App.tsx` (toolbar buttons + key handlers),
  `src/ui/components/GraphView.tsx` (`startNodeDrag` gesture boundaries),
  hooks into `src/ui/stores/spec.ts` + `src/ui/stores/layout.ts`.
