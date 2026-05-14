# Graph-readability polish — follow-ups after the editable threshold

Captured 2026-05-14, post-Phase-2-CBC session. The session that shipped the editable fanout threshold + single-edge replication panel rows (`5af14f0`) surfaced four follow-up gaps during manual browser verification. None blocks correctness; all are visual / UX polish.

## Status

| # | Item | Priority | Files likely touched |
|---|---|---|---|
| 1 | Long arrows from replica chip to wide iterate's center | medium — visual confusion | `src/ui/components/GraphView.tsx` (layout + edge routing) |
| 2 | Multiple replicas targeting the same consumer overlap | high — actively broken visual | `src/ui/components/GraphView.tsx` (layout placement passes) |
| 3 | Replication overrides panel always shows 4 rows, takes vertical space | low — easy collapse toggle | `src/ui/components/GraphView.tsx` + `src/ui/app.css` |
| 4 | State edges don't follow when a source is set to "always" replicate | open design question — NOT a bug | thinking required before code |
| 5 | Collapsed iterate renders as one `×N` chip; user wants N parallel block-chips | feature, not polish | `src/core/graph.ts` (new transform) + layout wiring |
| 6 | Edge hover tooltip with the value flowing through it at the current block | feature, not polish | `src/ui/components/GraphView.tsx` + reuse linear-view formatters |

## 1. Long arrow from replica chip to wide iterate's center

**Symptom:** User sets `compute-block-count` to `always` in the replication panel. A small replica chip appears at the **top-left** corner of the ECB iterate container; the chip's exit arrow curves across the iterate's top edge and terminates at the iterate's **horizontal center** above its top edge. On a 400-px-wide iterate, that's a ~200-px sweep — much longer than the replication mechanism is meant to produce.

**Root cause:** Two compounding factors in the current layout (`layoutRoot` and `layoutNode` in `src/ui/components/GraphView.tsx`):

1. **Placement** — root-level replicas are positioned at `(consumer.x, consumer.y - LEAF_H - STACK_GAP)`. Above the **left edge** of the consumer, not above where the arrow lands.
2. **Routing** — the `EdgePath` component's vertical regime targets `to.x + to.w / 2` (consumer's center top). For a wide iterate consumer, that's far from a replica anchored at `consumer.x`.

**Sketch of a fix (NOT yet implemented):**

- For replicas whose consumer is **wide enough** (`consumer.w > LEAF_W * K` for some K — maybe 2 or 3), shift the replica's x to `consumer.x + consumer.w / 2 - LEAF_W / 2` so it sits directly above the arrow-terminus column.
- *Or* — change edge routing: when source.cx differs significantly from to.center.x and both are vertically separated, target the consumer's **nearest-x edge** of the top side, not the center. This is a bigger change to `EdgePath` and affects every other edge too — be cautious.
- *Or* (the cleanest pedagogy) — for iterates specifically, anchor replicas to the **first body child** of the iterate (`container.childIds[0]`) so the arrow drops cleanly into "the start of the body, where the aux is read." This special-cases iterate consumers but matches the runtime semantics (the iterate reads aux at iteration entry, which conceptually feeds the first body step).

Pick one approach (likely the third — semantically clearest) and pin the resulting placement in `tests/graph-view-layout.test.ts` with a `compute-block-count → ecb-blocks` fixture.

## 2. Overlapping replicas to the same consumer

**Symptom:** Set `compute-block-count` to `always`. Now also set `split-blocks` to `always`. Both replicas land at exactly `(consumer.x, consumer.y - LEAF_H - STACK_GAP)` and overlap — only one is visible; clicks land on whichever is on top.

**Root cause:** Three layout passes (root, group, iterate) all use the same single-replica formula: `(consumer.x, consumer.y - LEAF_H - STACK_GAP)`. No counter-per-consumer.

**Sketch of a fix:**

```ts
// In layoutRoot, just before the replica-placement loop:
const replicaIndexByConsumer = new Map<string, number>();

for (const id of graph.rootIds) {
  if (!replicas.isReplica.has(id)) continue;
  const consumerId = replicas.consumerOf.get(id);
  if (consumerId === undefined) continue;
  const consumerBox = boxes.get(consumerId);
  if (!consumerBox) continue;

  const idx = replicaIndexByConsumer.get(consumerId) ?? 0;
  replicaIndexByConsumer.set(consumerId, idx + 1);

  boxes.set(id, {
    x: consumerBox.x + idx * (consts.LEAF_W + consts.FLOW_GAP),
    y: consumerBox.y - consts.LEAF_H - consts.STACK_GAP,
    w: consts.LEAF_W,
    h: consts.LEAF_H,
  });
}
```

Same pattern needed in the `group` and `iterate` branches of `layoutNode`. Add a regression test that two distinct sources targeting the same consumer get distinct x positions in the final layout boxes map.

If fixing #1 first, combine: stack horizontally around the consumer's center column rather than its left edge.

## 3. Collapsible replication overrides panel

**Symptom:** With the panel always visible, the four panel rows take ~140 px of vertical real estate above the canvas. Users tuning a one-time override don't want the panel pinned open afterward.

**Sketch of a fix:**

- Add a `replicationPanelOpen` signal (session-only) to `src/ui/stores/view-replication.ts`.
- Render the panel header as a clickable strip with a chevron glyph. Click → toggles the signal.
- Body of the panel (`<For each={replicationSources()}>`) goes inside a `<Show when={replicationPanelOpen()}>`.
- Default OPEN if any per-source override exists in the active spec's layout (so users see why their canvas looks customized) — else CLOSED.

This is a small, isolated change. Should be ~30 minutes including tests in the existing `tests/graph-view-replication-panel.test.tsx`.

## 4. State edges don't follow replication (open question)

**Symptom:** Setting `split-blocks` to `always` routes its aux edge (`input-blocks`) through a replica next to the ECB iterate. But the **white state edge** from `split-blocks → compute-block-count` (the spec-inferred state spine) stays anchored on the original `split-blocks`. The user sees one chip becoming three: the original (state-spine source), the replica next to the iterate (aux), and another replica wherever else.

**Why it's by-design today:** `replicateHighFanoutSources` only operates on `kind: "aux"` edges. State edges are 1-to-1 between consecutive same-parent leaves; replicating them would break the "this is the cipher's primary dataflow" visual story.

**Open questions** to think through before changing:

- If the original is **hidden** (when ALL its outgoing edges are replicated), how does the user click-scrub back to it? The original's trace frame still exists — needs a "click any replica to scrub to source" affordance (already exists via `replicaOf`).
- If state edges are **also replicated**, the spine becomes a fan of N parallel paths — pedagogically muddier ("which path is THE cipher's flow?").
- Maybe the right answer is to **relocate** the original closer to one of its consumers (the one with the most outgoing flow) instead of replicating. This preserves the 1-to-1 spine while shortening arrows.

**Recommendation:** Don't change this without a design pass. Track as an open design question; address it together with the long-arrow fix (#1) since both are about "where does this source live on the canvas."

## 5. Collapsed iterate → N parallel block-chips (feature, not polish)

Originally tagged as a feature in the 2026-05-14 session. User wants: when collapsing an iterate with `blockSpan > 1`, instead of rendering a single chip with the `×N` badge, render N small chips (one per block) with all incoming/outgoing edges fanning out to each chip. Pedagogically that's the "ECB = N parallel AES copies" story made literal.

**Sketch:**
- New transform `expandCollapsedIterates(graph, collapsedIds): CipherGraph` in `src/core/graph.ts`. Runs **after** `collapseGraph`, **before** `replicateHighFanoutSources`.
- For each collapsed iterate with `blockSpan = N`, replace the single collapsed chip with N chips in the same parent's `childIds` / `rootIds`. Each chip's stepId = `${iterateId}@block{i}`, `replicaOf: iterateId` (reuse the existing field so click-scrub navigates to the iterate's frame).
- For every edge `(?, iterateId, auxKey, kind)` produce N edges, one per chip.
- For every edge `(iterateId, ?, auxKey, kind)` produce N edges, one per chip.

Naturally composes with #2 (replica stacking) — `key-expansion` set to `always` would then get N tiny replicas, one next to each block-chip. Pedagogically excellent.

**Caps:** for huge `blockSpan` (e.g. 100+ blocks under a 1.5KB plaintext), capping at `~6 visible + …` may be needed. Defer until anyone hits it.

## 6. Edge hover tooltip with the value at current block (feature, not polish)

Originally tagged as a feature in the 2026-05-14 session. User wants: hover an edge → tooltip shows `auxKey + value flowing through it at the current scrubber's blockIndex`. Reuses byte-format toggle and matrix/bytes formatters from the linear view.

**Sketch:**
- Compute `frameByCanonicalStepId` memo keyed on `stripBlockSuffix(frame.stepId)` and `frame.blockIndex`.
- For each edge, look up the consumer's frame at the current scrubber's block; pull `frame.auxRead.get(edge.auxKey)` for aux edges, or the predecessor frame's `frame.state` for state edges.
- Render as a hover tooltip on the `<path>` (replace the current `<title>{auxKey}</title>` with a richer one).

## Suggested next-session sequencing

Recommended order if user picks this up later:

1. **Quick wins first:** #3 (collapsible panel) + #2 (stacking overlap) — both small, both pin obvious visual bugs.
2. **Design pass second:** think through #1 (long arrows) and #4 (state-edge behavior) together; they overlap on "where does this source live on the canvas?"
3. **Features last:** #5 (block-chips) and #6 (edge tooltip) — both genuinely add functionality, less urgent than the polish items above.

## Cross-references

- The session that shipped (a) and surfaced these gaps: commit `5af14f0` on `main`.
- Bigger-picture graph view backlog: [`memory/project_graph_view_ux_polish.md`](../../C:/Users/boiko/.claude/projects/M--claud-projects-Cryptographer/memory/project_graph_view_ux_polish.md) (drop-anchor highlight, feedback-edge style, aux-load label, canvas horizontal scroll). Independent items; not blocked by this plan.
- Replication infrastructure: `src/core/graph.ts::replicateHighFanoutSources`, `src/ui/stores/view-replication.ts`, `src/ui/components/GraphView.tsx::layoutRoot` + `layoutNode`.
