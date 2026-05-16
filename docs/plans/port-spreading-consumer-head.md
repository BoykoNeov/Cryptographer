# Port-spreading at consumer head

**Status:** Helper-level fix SHIPPED 2026-05-16 (mechanism 1 + mechanism 2;
diagnostic `it.fails` tests flipped to regression guards). Render-site
mechanism 3 (off-chip clamp against chip-vs-leaf width) deferred per the
plan unless visual smoke shows arrows still sliding off chip edges.
Browser-visual confirmation on the canonical AES-128 ECB + collapsed-iterate
fixture pending. **Position in time:** unblocks Slice 7b → Feistel-plan →
first Feistel cipher → universal cipher-shape plan.

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

## Approach — kind-agnostic per-consumer slot assignment (SHIPPED)

Direction agreed with user (2026-05-16) after the advisor flagged option 3
("order by edge kind") as a reversal of an explicit kind-agnostic design
commitment. Chosen path: **decide kind-awareness later, revisit at Slice
7b when state-edge replication actually lands and we can see whether
kind-agnostic + per-consumer fan-in reads cleanly on a real Feistel
canvas.** The immediate fix stayed kind-agnostic.

Implementation landed 2026-05-16 in a single commit. What shipped:

1. **`ConsumerPortAssignment` type + `buildConsumerPortAssignment(graph,
   replicas)`** (new exports in `src/ui/components/GraphView.tsx`).
   Walks edges once, buckets by `edge.to`, sorts each multi-incoming
   bucket by the comparator below, assigns slots `0..N-1`. Single-
   incoming consumers get a `localCountOf` entry of 1 but no slot
   entries → `consumerPortOffset` short-circuits via `slot === undefined
   → 0`. Empty for graphs with zero edges. O(E log E) overall.
2. **Comparator (kind-agnostic, lexicographic):**
   - `rowOfSource.get(canonicalSource)` ascending — replicas before
     non-replicas (non-replicas sort at `Number.POSITIVE_INFINITY`);
     among replicas, lower global row first.
   - `edge.from` ascending — deterministic tiebreak when two edges
     share a canonical source.
   - `edge.auxKey` ascending — tiebreak for state-vs-aux from the
     same from→to.
   - `edge.kind` ascending — final tiebreak ("aux" < "state"). Only
     matters when 1+2+3 all tie.
3. **`consumerPortOffset(edge, ports, portGap)`** (new export) returns
   `(slot - (localCount - 1) / 2) * portGap`. The OLD `replicaTargetXOffset`
   was DELETED (no consumers besides the render site and tests; the
   migration was a clean rename + arg-shape change).
4. **Source-side aligned by construction.** The slot comparator's
   primary key is row order, so at any consumer slot 0 is always the
   lowest-row source. `replicaSourceXOffset` still computes source-x
   from the global row index. Same direction at any consumer → no
   arrow crossovers within a consumer.
5. **Cross-canvas eye-tracking trade pinned in a test.** The new
   `per-consumer locality in asymmetric topology` test fixture in
   `tests/graph-view-port-spreading.test.ts` shows source A landing at
   offset 0 at one consumer (single-incoming) and at offset -5 at
   another consumer (multi-incoming). Under the old global formula
   A would have landed at -5 at both. The asymmetric tradeoff is
   intentional; this test makes it impossible to silently revert.
6. **Slice 7b composability preserved.** State replicas join the same
   slot pool as aux replicas, ordered by the same row-first comparator.
   The `kind-agnostic comparator` test pins the behavior.
7. **Render site changes:** `portAssignment = createMemo(() =>
   buildConsumerPortAssignment(graph(), replicaPlacement()))` added
   next to `replicaPlacement`. The one call site at `EdgePath`'s
   `targetXOffset` memo swapped from `replicaTargetXOffset(edge,
   replicaPlacement(), portGap)` → `consumerPortOffset(edge,
   portAssignment(), portGap)`. No other render-path changes.
8. **Tests:** 8 existing tests in `tests/graph-view-port-spreading.test.ts`
   migrated to the new API (function names + arg shapes; expected
   values unchanged in every case because the existing fixtures used
   symmetric topologies where per-consumer and global orderings
   coincide). 1 new test pins the asymmetric tradeoff. The 2 `it.fails`
   diagnostics flipped to plain `it` regression guards. All 11 tests
   pass. Full gate green (1100 tests across 95 files, ~19s; bundle
   107.39 KB gzipped, +0.36 KB from pre-fix).
9. **Mechanism 3 (off-chip clamp) NOT shipped in this slice.** Deferred
   per the plan unless visual smoke shows arrows still sliding off
   chip edges. Render-site clamp against chip width (instead of
   `LEAF_W`) is the follow-up, detected via the same anchor sites
   Option C uses (`layoutRoot` + `visualEdgeTargetId`).

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
