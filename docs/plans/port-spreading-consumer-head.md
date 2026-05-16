# Port-spreading at consumer head

**Status:** Diagnosed 2026-05-16 (two mechanisms confirmed via `it.fails`
tests; one render-site mechanism deferred). Fix sketch agreed
kind-agnostic per the advisor's pushback against reversing the existing
design commitment. Implementation slice pending. **Position in time:**
next priority — bumped above Slice 7b after the Slice 7c manual smoke
pass surfaced fan-IN ambiguity at chip heads. Blocks Slice 7b →
Feistel-plan → first Feistel cipher → universal cipher-shape plan.

## Context

Source-side port-spreading shipped 2026-05-16 in commit `133676f`
("Graph — port-spreading + diagonal source stagger for stacked
replicas"). That commit introduced `replicaSlotPosition`,
`replicaLiftHeight`, `replicaTargetXOffset` helpers and
`REPLICA_ROW_X_STEP = 16`, plus `EdgePath.targetXOffset` distributing
incoming edges across a consumer's top edge as
`(row - (total - 1) / 2) * portGap`.

The 7c manual smoke afterward showed that **the consumer-head
distribution still produces fan-IN ambiguity when the consumer is a
collapsed-iterate chip** (post-Slice-6 chip-row, post-Option-C
box-with-header). Concretely: a single chip head receives incoming
edges from multiple distinct sources (state from the previous spine
leaf, aux from `key-expansion` replicas, aux from `input-blocks`, etc.).
The current `targetXOffset` math distributes by replica-row index of
the source, which assumes the consumer's incoming edges all come from
the same stacked-replica column. For a chip head with heterogeneous
sources, the math is the wrong distribution rule.

Memory entries:
- `project_graph_narrative_zoom_plan.md` — flags this as the priority
  ahead of 7b.
- `feedback_collapsed_iterate_design.md` — Option C box-with-header
  context; two existing chip-row detection sites.

## Diagnosis (2026-05-16 — confirmed via failing tests)

Advisor pushed back on the stub's original "pick 1 of 3 ordering options"
framing: the visible bug at chip heads isn't one mechanism, it's two
distinct mechanisms operating on the same `replicaTargetXOffset` helper.
Both pinned by `it.fails` tests in `tests/graph-view-port-spreading.test.ts`
under the `chip-head heterogeneous fan-in (REPRO — bug)` describe block.

- **Mechanism 1 — Collision at offset 0.** A non-replica edge (e.g. the
  state spine arrow from the previous leaf) returns `0` from
  `replicaTargetXOffset`. Independently, the source mapped to the middle
  global row — `(row - (total-1)/2) === 0`, which happens whenever
  `total` is odd — also returns `0`. Two distinct logical incoming edges
  land at the same x on the consumer's top. **Confirmed:** the test
  `mechanism 1: ... DISTINCT offsets` asserts `spineOffset !==
  bMiddleOffset` and fails (both are 0).
- **Mechanism 2 — Skipped-global-rows inflate the spread.** A consumer's
  local fan-in only hits a subset of the global rows. Adjacent local
  edges land farther apart than `portGap` because the global formula
  counts skipped rows. **Confirmed:** the test `mechanism 2: ... exactly
  portGap apart` constructs a 3-source canvas where consumer c1 sees
  only sources A (row 0) and C (row 2). Per-consumer spacing would be
  `portGap`; current code returns `2 * portGap`.
- **Mechanism 3 — Off-chip clamp.** `EdgePath` clamps `targetXOffset`
  to `LEAF_W/2 − 4` regardless of whether the consumer is a normal leaf
  (`LEAF_W` wide) or a collapsed-iterate chip-row entry (narrower than
  `LEAF_W`). Lives in the render site, not the helper — needs an
  integration-level test (jsdom + measured chip geometry) to pin, not
  a helper unit test. Logged but deferred to the implementation slice
  if visual smoke after the helper fix still shows arrows sliding off
  chip edges.

The original stub's claim — "the math is the wrong distribution rule for
heterogeneous sources" — wasn't quite right. The math distributes by
**global row index**, which is correct for the cross-canvas eye-tracking
property the existing code design-commits to (`GraphView.tsx` lines
1124–1149). It's wrong for the chip-head case specifically because two
side effects of the global formula — the offset-zero collision band and
the skipped-row inflation — produce visual ambiguity that the eye reads
as "these arrows are the same thing." The fix has to thread two needles:
preserve enough of the global property that the cross-canvas eye-tracking
survives, while preventing the two collision modes at the consumer.

## Approach — kind-agnostic per-consumer slot assignment

Direction agreed with user (2026-05-16) after the advisor flagged option 3
("order by edge kind") as a reversal of an explicit kind-agnostic design
commitment. Chosen path: **decide kind-awareness later, revisit at Slice
7b when state-edge replication actually lands and we can see whether
kind-agnostic + per-consumer fan-in reads cleanly on a real Feistel
canvas.** The immediate fix stays kind-agnostic.

Sketch — to be filled in during the implementation slice:

1. **Introduce a per-consumer port-slot index.** For each consumer `c`,
   compute the list of incoming edges (replica + non-replica), sort by
   a stable kind-agnostic key — first proposal **source canonical id**
   (lexicographic over `sourceOf.get(edge.from) ?? edge.from`, so
   non-replica edges sort by their own `from` id alongside replica
   sources). Tie-breaks: edge `from` id, then `auxKey`. Output is a
   `Map<edgeKey, slotIndex>` where `slotIndex` runs `0..localCount-1`.
2. **Replace the global-row formula with the local slot formula.**
   `replicaTargetXOffset` becomes `consumerPortOffset` (renamed since
   it no longer keys off replica rows alone), returning
   `(slotIndex - (localCount - 1) / 2) * portGap`. Same shape,
   different input → preserves the centered-spread property and the
   degenerate `localCount === 1 → offset 0` short-circuit.
3. **Cross-canvas eye-tracking is partially preserved.** A source that
   targets multiple consumers no longer lands at the same x on every
   consumer (because each consumer's slot index depends on its local
   fan-in). What's preserved: a source's slot at a consumer is stable
   under canvas-wide edits (adding an unrelated source elsewhere
   doesn't shift it). What's lost: "source A always lands HERE." User
   trades this for chip-head clarity — flag for visual smoke after
   the fix to confirm the trade reads as net-better.
4. **Preserve `replicaTargetXOffset`'s degenerate behavior** at the
   API boundary. The two existing call sites (`EdgePath.targetXOffset`
   + the `createMemo` at the render site) keep their shape; the
   internal computation swaps in the per-consumer logic.
5. **Slice 7b composability.** When state edges get replicated and
   start fanning into chip rows, they enter the same per-consumer
   slot bucket as aux edges. No kind-aware branch needed — the
   ordering is still kind-agnostic. Slice 7b's "drop the
   `kind === 'aux'` filter and machinery picks up state replicas for
   free" promise stays valid.
6. **Mechanism 3 (off-chip clamp) is OUT of scope for the helper fix.**
   If the helper fix doesn't visually resolve the chip-head ambiguity
   on the 7c manual smoke fixture, add a render-site change: detect
   chip-row consumers via the same anchor sites Option C uses
   (`layoutRoot` + `visualEdgeTargetId`) and clamp against chip width
   instead of `LEAF_W`. Flagged as the highest-likelihood follow-up.

## Critical files

- `src/ui/components/GraphView.tsx` — `EdgePath.targetXOffset`,
  `replicaTargetXOffset` helpers from commit `133676f`. Consumer-head
  logic lives here.
- `tests/graph-view-port-spreading.test.ts` — extend with chip-head
  fixtures (collapsed iterate, multiple distinct source kinds, mixed
  state + aux fan-in).
- `docs/help/graph-view.md` — no user-facing change expected unless
  the visual rule shifts noticeably.

## Open questions

- **Density-scale interaction.** `LEAF_W` is density-scaled; the per-port
  gap should be a fraction of width, not a fixed pixel — confirm
  `Math.max(6, LEAF_W / 10)` still holds for chip widths (chips are
  narrower than full leaves). Becomes more pressing if Mechanism 3
  (off-chip clamp) needs the render-site fix described in step 6 of the
  approach.
- **Chip-row anchor sites.** Per `feedback_collapsed_iterate_design.md`,
  Option C added 2 chip-row detection sites in `layoutRoot` +
  `visualEdgeTargetId`. The per-consumer port-slot computation doesn't
  need a new site (it keys off `edge.to`, which is already canonical),
  but the Mechanism 3 follow-up (clamp-against-chip-width) likely does.

## Resolved questions

- **Cipher-aware port assignment (edge.kind ordering)?** Resolved
  2026-05-16: defer to Slice 7b. Per the advisor's read, option 3 in
  the original stub ("order by edge kind: state first, aux, feedback")
  reverses an explicit kind-agnostic design commitment at
  `GraphView.tsx` lines 1145–1149. User picked "decide later" — make
  the immediate fix kind-agnostic and revisit when Slice 7b lands and
  Feistel state-edge replication is observable. Kept as a Slice 7b
  follow-up if kind-agnostic reads visually muddy on a Feistel canvas.

## Verification

- 7c manual smoke fixture (collapsed AES-128 ECB iterate with multiple
  `always` overrides) — fan-IN ambiguity resolved by eye.
- `npm run check` green; new port-spreading tests cover chip-head
  fixtures.
- Slice 7b can ship cleanly afterward without revisiting the consumer-
  side distribution math.

## Cross-references

- Commit `133676f` — source-side port-spreading + first consumer-side
  attempt.
- `docs/plans/graph-narrative-and-zoom.md` Slice 7c — the smoke pass
  that surfaced this gap.
- `docs/plans/graph-narrative-and-zoom.md` Slice 7b — blocked behind
  this plan.
