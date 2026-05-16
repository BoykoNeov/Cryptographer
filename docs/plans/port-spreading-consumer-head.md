# Port-spreading at consumer head

**Status:** Stub 2026-05-16. **Position in time:** next priority — bumped
above Slice 7b after the Slice 7c manual smoke pass surfaced fan-IN
ambiguity at chip heads. Blocks Slice 7b → Feistel-plan → first Feistel
cipher → universal cipher-shape plan.

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

## Approach (to flesh out)

Provisional sketch — confirm with user before code.

1. **Decouple consumer-head port assignment from replica-row index.**
   When the consumer is a chip-head (or generally any consumer with
   heterogeneous incoming sources), use a port-assignment scheme that
   orders distinct source ids stably and distributes them across the
   chip's top edge.
2. **Stable port ordering.** Options to weigh:
   - Order by canonical source id (lexicographic).
   - Order by source's canvas x-position (left-to-right).
   - Order by edge kind (state first, then aux, then feedback) — keeps
     the spine arrow at a predictable port.
3. **Preserve the existing math for leaf consumers** — only the chip-
   head case needs the new rule (chips are narrow; their incoming-edge
   count is higher than a normal leaf's).
4. **Composes with Slice 7b.** Once state edges fan into chip rows
   (7b's outcome), the chip head sees N state edges plus M aux edges.
   Whatever rule lands here must accommodate that without re-tuning.

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

- **Should port assignment be cipher-aware?** Future Feistel branching
  could produce 2 state-out edges that fan to different consumers; the
  consumer side might see "L state + R state" from one Feistel
  predecessor and "aux key" from another. Port ordering by edge-kind
  groups would keep both states adjacent — pedagogically clearer than
  interleaving with aux.
- **Density-scale interaction.** `LEAF_W` is density-scaled; the
  per-port gap should be a fraction of width, not a fixed pixel —
  confirm `Math.max(6, LEAF_W / 10)` still holds for chip widths
  (chips are narrower than full leaves).
- **Chip-row anchor sites.** Per `feedback_collapsed_iterate_design.md`,
  Option C added 2 chip-row detection sites in `layoutRoot` +
  `visualEdgeTargetId`. Port-spreading consumer-head logic may want a
  3rd site, OR the existing 2 may be enough if `targetXOffset` reads
  the chip's geometry through the same anchor.

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
