# Draggable replica chips + block chips

**Status: SHIPPED 2026-05-19 — CLOSED.** Delivered in `6faac0a` (the
`LayoutSpec.relativePositions` sidecar) and the slices that followed it, and
released in v0.5.0; the full delivery record is the `CHANGELOG.md` entry under
`[0.5.0] - 2026-05-19` ("Aux replica chips and block chips become draggable").
Pin model shipped as designed below — **relative** `{dx, dy}` deltas keyed by
synthetic id, anchored implicitly to the chip's graph relationship, so dragging
the anchor carries the chip along. Both reset surfaces shipped (the per-node ↺
glyph and the toolbar `[reset layout]`). Pinned by
`tests/draggable-replicas-layout.test.ts` + `tests/draggable-replicas-drag.test.tsx`.

**This file is the live design record for a shipped schema field**, not
historical background: `src/core/document-schema.ts`, `src/core/document.ts`,
`src/ui/stores/layout.ts` and seven sites in `src/ui/components/GraphView.tsx`
all point a reader here for the rationale behind `relativePositions`. Everything
in "Out of scope (deferred)" at the foot of the file is still deferred and still
accurate.

*(Header corrected 2026-08-09 — it had read "in flight, opened 2026-05-19" for
the ~3 months since the work landed, which is how this plan came to be
mis-triaged as unfinished during a backlog sweep.)*

## Context

Today GraphView pins only a narrow set of nodes:

- **Containers** (groups, iterates) — absolute `{x, y}` in
  `LayoutSpec.positions`, written by `setNodePosition` on container
  header drag.
- **Root-level non-replica leaves** (e.g. AES's top-level
  `key-expansion`, `initial.add-round-key`) — same shape, written by
  `startNodeDrag` on the leaf's `<g>`.

Three categories are deliberately not draggable, gated by
`isRootLevel && !isReplicaLike` in `GraphView.tsx`:

1. **Aux replicas** — synthetic ids `${source}@->${consumer}`, placed
   algorithmically *above their consumer* by `buildReplicaPlacement`'s
   second/third pass inside `layoutNode` (group branch) and the
   iterate-body branch.
2. **Block chips** — synthetic ids `${iterateId}@block${i}`, placed at
   the collapsed iterate's slot in the chip row.
3. **Endpoint pills** — `__cipher_input__` / `__cipher_output__`, fixed
   position encoding "data enters/exits here."
4. **Nested non-root leaves** — flow inside their parent container per
   auto-layout.

User asked (2026-05-19) to make "all immovable objects movable" with a
reset button. After triage with the advisor we narrowed the actual
motivation to category **(1) + (2)** — aux replicas and block chips.
Nested leaves and endpoint pills stay non-draggable.

## Why now / pedagogical motivation

When a source has many consumers, the auto-placed replica chips
sometimes overlap arrow bundles or hug the consumer header
uncomfortably. The user wants the ability to nudge them — local
adjustments to taste — without re-tuning the placement algorithm. The
existing per-source `replicationModes` knob is a coarse on/off; this
adds fine-grained positional override on top.

## Decisions taken (recorded before any code)

| Question | Answer |
|---|---|
| Categories to make draggable | Aux replicas + block chips only |
| Pin model | **Relative to anchor** — delta from auto position |
| Nested-leaf future edge policy | Clamp to parent bounds (for when nested leaves graduate) |
| Per-node reset affordance | Small × visible on hover when pinned |
| Hard-reset confirm dialog | Yes — `window.confirm` |
| Slicing | One slice, all in one PR |

## Risks (acknowledged)

- **Algorithmic placement was iteratively tuned** (see memory
  `feedback_same_scope_replica_merge_rejected.md` — prior attempt to
  fold replicas back into the spine row was abandoned because the
  resulting cross-spine arrows were worse than the duplicates they
  removed). User-positioned replicas may land in geometrically worse
  spots than the algorithm's choices; we accept this because the user
  is asking to take that risk.
- **Synthetic ids are layout-time-only.** They reference real step ids
  inside them. A spec edit that renames the consumer (today only the
  duplicate-round mutator does this, with a strict numeric shift)
  changes the synthetic id and orphans the pin. We follow the existing
  "no pruning of stale stepIds" policy (`layout.ts` header comment) —
  stale entries are invisible to the renderer. Future work could
  parse-and-remap synthetic ids in `renameLayoutIds`; deferred.
- **Block chips depend on iterate being collapsed.** Expanding the
  iterate makes the chip vanish; the pin orphans. Same policy.
- **Bundle geometry follows the chip.** Arrow bundles end at the
  chip's centre; if the chip is dragged far from its consumer, the
  `×N` bundle pill may end up in negative space. Acceptable footgun.

## Data model

Additive field on `LayoutSpec` in `src/core/document.ts`:

```ts
type LayoutSpec = {
  readonly positions: { readonly [stepId: string]: StepPosition };
  readonly collapsedGroups: readonly string[];
  readonly flowDirection: "ltr";
  readonly replicationModes?: { readonly [sourceId: string]: ReplicationMode };
  readonly relativePositions?: {
    readonly [syntheticId: string]: { readonly dx: number; readonly dy: number };
  };
};
```

No `anchorId` field on the value — the anchor is implicit in the
node's relationship to the rest of the graph (`replicaOf` → consumer;
`blockChipOf` → iterate). Layout re-derives anchor position each
pass, then adds `(dx, dy)`.

Byte stability: empty `relativePositions` field is omitted from
serialized output via the same `withReplicationModes`-style helper
pattern. `hasUserLayout` counts non-empty `relativePositions` so
spec-only saves stay byte-stable until the user actually drags a
chip.

## Layout engine change

`layoutNode` and `layoutRoot` take a second `relativePins` map alongside
the existing `pinned`. In each of the four placement spots that
currently writes a replica/chip box —

- `layoutNode` group branch, left-gutter replicas (GraphView.tsx:1044)
- `layoutNode` group branch, lifted replicas (~1069)
- `layoutNode` iterate branch, lifted replicas (~1169)
- `layoutRoot` second pass, root-level replicas (~1439)

— apply `(dx, dy) = relativePins.get(id) ?? (0, 0)` to the computed
`(x, y)` before `boxes.set(id, ...)`. Block-chip placement follows the
same pattern.

## Drag wire-up

`GraphView.tsx:4154` currently sets `dragProps` only when
`isRootLevel && !isReplicaLike`. Change to also set them when
`isReplicaLike`. `startNodeDrag` gains a relative-mode branch keyed
by whether the id is in `graph.nodes.replicaOf || .blockChipOf`:

- Drag start captures `startDelta = relativePins.get(id) ?? {dx:0, dy:0}`
  and the start cursor coords.
- On move: `newDelta = startDelta + (clientDx/zoom, clientDy/zoom)`,
  call `setRelativePosition(specId, id, dx, dy)`.

No clamp to (0,0) for relative mode — auto position may itself be deep
inside the canvas, and the user moving the chip back toward the upper
left is a legitimate gesture. Canvas extent tracking grows the SVG to
fit, same as today for absolute pins.

## Reset surfaces

### Per-node (`×` chip on hover)

When `relativePins.has(id)`, render a small × inside the chip's
top-right corner with `opacity: 0` default, `opacity: 1` on chip
hover. Click clears the pin via `clearRelativePosition(specId, id)`,
which removes the entry (and the layout's `relativePositions` field
entirely if now empty).

Styling mirrors `graph-source-colors-reset` (`app.css:2857`).

### Hard reset (toolbar button)

`reset layout` button next to `graph-view-zoom-reset` in the
GraphView toolbar. Click → `window.confirm("Reset graph layout?
This clears every pin, collapse, and replication override.")` → on
OK, `setLayoutForSpec(specId, null)`.

## Test plan

All in new file `tests/draggable-replicas.test.ts` (vitest, node env)
plus extensions to existing layout-engine tests.

Layout-engine pass (no DOM):
1. `setRelativePosition` round-trips through localStorage.
2. `hasUserLayout` returns true when only `relativePositions` is
   populated.
3. Empty `relativePositions` is omitted from the serialized document
   (byte-stability test).
4. `layoutRoot` with a relative pin on a replica id places its box at
   `auto + (dx, dy)`.
5. **Anchor-follows test** — drag the consumer (absolute pin on
   `add-round-key`), assert the replica's box follows by the same
   delta (because auto position of replica depends on consumer
   position).
6. Pin survival across density flip — `rescaleAllPositions` does NOT
   touch `relativePositions` (deltas are already in viewBox-relative
   units; density rescale targets absolute positions only).

GraphView pass (jsdom):
7. Pointerdown + drag on a replica chip writes `relativePositions`,
   not `positions`.
8. Per-node × click clears the entry.
9. Hard-reset toolbar click + confirm clears positions, relative
   positions, collapsed groups, replication modes.

## Critical files

- `src/core/document.ts` — `LayoutSpec` type
- `src/core/document-schema.ts` — Zod schema for the layout sidecar
- `src/ui/stores/layout.ts` — store getters/setters, persistence
- `src/ui/components/GraphView.tsx` — layout engine + drag handlers +
  reset affordances + toolbar button
- `src/ui/app.css` — × button + toolbar button styling
- `tests/draggable-replicas.test.ts` — new
- `tests/graph-view-replica-gutter.test.ts` — possibly extended

## Out of scope (deferred)

- Nested-leaf drag (data model above leaves room; gate would relax).
- Endpoint-pill drag (semantically weak motivation).
- `renameLayoutIds` remapping for synthetic ids (orphan-on-rename is
  acceptable).
- Replica-merge across same scope (already tried + rejected; see
  memory).
- Right-click context menu (the × affordance covers the per-node
  reset without introducing a new UI mechanic).
