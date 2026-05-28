# High fan-in replication — experiment notes

**Status:** EXPERIMENT (not a shipped plan). Lives on the
`worktree-fanin-replication-experiment` branch, in the worktree at
`.claude/worktrees/fanin-replication-experiment`. Seeded 2026-05-28 from a
conversation that did the orientation + advisor consult below. Work continues
here.

**Origin:** User observation — "currently we do replication of high fan-out
sources (usually). I think however that we should also implement replication
of high fan-in sources." User then asked to spin this off into a separate
worktree/experiment, carrying the conversation-so-far as this seed doc.

---

## The task, restated precisely

The graph view already replicates **high fan-out sources** (one producer →
many consumers): `replicateHighFanoutSources` in `src/core/graph.ts`
(definition starts ~line 2325) splits a source into N small chips, one beside
each consumer, killing the long cross-canvas lines. Motivating case: AES-128
key-expansion's 11 roundKey lines.

The ask is the **dual**: do something equivalent for **high fan-in** — a
single node that receives many incoming edges from scattered producers
(N lines *converging* on one node).

### Reframing (important — the phrasing "high fan-in *sources*" is loose)

Fan-in is a property of the **consumer**, not a source. The geometric dual of
fan-out replication is **"replicate each *feeder* toward the shared
consumer"**, NOT "replicate the consumer."

Why not replicate the consumer: a high-fan-in node *combines N distinct
inputs* (e.g. `T1 = h + Σ1 + Ch + K_t + W_t`). You cannot compute a working
copy of `T1` at any single feeder's location — it needs all 5 inputs at once.
A "copy of T1 near each feeder" is a ghost label, shortens nothing, and risks
reading as 5 separate T1s. So the move that actually collapses the converging
lines is putting a small copy of *each feeder* next to the consumer.

---

## Key architectural fact: the dual is (mostly) already buildable

`replicateHighFanoutSources` already:
- Includes **single-fanout sources** (`fanout >= 1`, added 2026-05-19 per user
  ask) — so a feeder with only one consumer is eligible.
- Takes a per-source `modes: { [sourceId]: "always" | "never" }` override map.
- Counts **port-flow state edges** as fanout-eligible (Slice S2(i),
  2026-05-26) — `kind:"state"` + `auxKey === PORT_FLOW_AUX_KEY`.

So "replicate feeder F next to consumer C" is achievable **today** by setting
`modes[F] = "always"`. The existing splice/redirect/removal pipeline (DES
cross-scope anchoring, spine-entry redirect, container skip, per-(source,
consumer) dedup) executes it. The **only missing piece is an automatic
trigger**: "consumer C has high fan-in → mark C's eligible feeders 'always'."

**Therefore: do NOT build a parallel `replicateHighFanInConsumers` transform.**
Build a fan-in-aware *auto-selection* that feeds the existing transform via the
`modes` map. (Advisor concurred — see below.)

---

## Advisor verdict (full, 2026-05-28)

> Your framing is sound, and two of your instincts are exactly right.
>
> **What you have right:**
> 1. The geometric dual is "replicate each source toward the shared consumer,"
>    not "replicate the consumer." Replicating the consumer is a ghost label
>    (it combines N distinct inputs, can't be computed at any one source's
>    location), so it shortens nothing. You avoided the trap.
> 2. Reuse the existing transform via auto-selection — don't build a parallel
>    `replicateHighFanInConsumers`. Those ~300 lines handle DES cross-scope
>    anchoring, spine-entry redirect, container skip, per-(source,consumer)
>    dedup. Duplicating that would be a maintenance sink.
>
> **The sharpening that resolves the "fully removes the source" side effect:**
> Auto-select **only fanout-1 feeders.** Two independent reasons converge:
> - The `modes` API keys on `sourceId` alone — there's no per-(source,
>   consumer) targeting. A source feeding C *and* other nodes can't be aimed
>   at just C; marking it `"always"` replicates it toward everything. A
>   fanout-1 feeder has only C as a consumer, so "toward all" == "toward C" —
>   the API limitation evaporates.
> - "Fully remove" is correct for a pure feeder (it had one job) but yanks a
>   shared/spine node out of place. Fanout-1 feeders are pure by definition.
>
> So: detect consumers with incoming-count > threshold → add their fanout-1
> feeders to the `modes` map as `"always"` → existing pipeline executes. Zero
> new replication logic.
>
> **Deeper caveat:** even a fanout-1 feeder, if it's *itself a combine* with
> its own input network (Σ1, Ch), doesn't eliminate lines — relocating it next
> to T1 drags its rotation/input edges along, trading T1's fan-in for Σ1's.
> The pure win is **leaf-like feeders** (K_t, W_t, constants — no significant
> incoming network). Verify whether the real high-fan-in nodes are fed by
> leaves or combines.
>
> **Gate before building:** confirm the pain is *visual, not hypothetical*.
> The fan-out feature had a concrete driver (AES's 11 long lines). Confirm
> fan-in produces long *converging* lines in the actual SHA-256 graph — the
> feeders may already be laid out locally (same round body, just before T1),
> making the edges already short. Precedent: this session's Slice 3 routing
> revert (2026-05-28: ~60 green tests incl. clearance property tests, smoke
> revealed catastrophic shape failure). Open the graph, look, *then* decide
> which nodes the heuristic targets.

---

## Static analysis of SHA-256's high-fan-in nodes (done in this convo)

Source: `src/ciphers/sha-256.ts`. The `inputCount` > 2 nodes:

### `T1` (`add-mod-32@1`, inputCount 5) — sha-256.ts:1381
`T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t`. Feeders:
- `split.output7` (h) — slice off the working-var split (split is **multi-fanout**)
- `Sigma1.output` — **combine** (rotations XORed)
- `Ch.output` — **combine** (choice function)
- `K_t.output` — constant fetch → **leaf-like, clean win**
- `W_t.output` — schedule-word slice → **leaf-like, clean win**

→ **Mixed.** Of 5 feeders: 2 clean leaf wins (K_t, W_t), 2 combines that drag
their networks (Σ1, Ch), 1 slice off a multi-fanout source (h) that the
*existing* fan-out path already handles. This is the genuinely-unaddressed
fan-in case, and it's a **partial** win.

### `repack` (`concat@1`, inputCount 8) — sha-256.ts:1432
6 of 8 inputs are slices off the **same** `split` node
(`output0,1,2,4,5,6`), plus `new_a`/`new_e`. So `split` is itself a
**high-fan-out source** → likely already auto-replicated by the existing
mechanism, shortening 6 of repack's 8 lines for free. Not a fan-in problem.

### `final.repack` / final concat (`concat@1`, inputCount 8) — sha-256.ts:1511
Fed by `final.s0..s7`, fanout-1 combines whose own inputs
(`final.split-wv` / `final.split-H`) are exactly the documented S2(i)
high-fanout sources the existing code *already* replicates. Already local.

### Conclusion of static pass
**Much of SHA-256's apparent "fan-in" is the consumer side of high-fan-out
sources the existing mechanism already replicates** (`split`, `split-wv`,
`split-H`). The one genuinely-unaddressed node is **T1**, and even there the
clean win is only its leaf feeders (K_t, W_t). A fan-in auto-selection targets
a *narrower* set than first appears.

---

## Proposed approach (pending the visual gate)

1. **Auto-selection, not a new transform.** A pure function that, given the
   collapsed graph, returns a `modes` patch: for each consumer whose
   incoming-edge count (fanout-eligible kinds, mirroring the existing
   eligibility predicate) exceeds a threshold, mark each of its **fanout-1,
   leaf-like** feeders as `"always"`.
2. **"Leaf-like" filter** (the advisor's combine caveat): a feeder qualifies
   only if it has no significant incoming network of its own — i.e. its own
   in-degree of fanout-eligible edges is ~0 (constant fetches, aux loads,
   schedule slices). Combines like Σ1/Ch are excluded so we don't trade one
   node's fan-in for another's.
3. Merge this patch into the `modes` already passed to
   `replicateHighFanoutSources` in `GraphView.tsx` (the createMemo around
   line 2930). User per-source `"never"` overrides must still win.
4. **Toggle/threshold** parallel to the existing replication toggle — likely a
   second sub-toggle so fan-in auto-selection is independently switchable.

### Open design questions
- Threshold for "high fan-in"? (T1 = 5; the leaf wins there are only 2.)
- Does auto-selecting leaf feeders interact badly with the source-color
  coding or arrow-bundling features?
- Confirm the `modes` merge order vs. the existing auto/never logic.

---

## THE GATE (do this first, before building)

Open the SHA-256 graph in the browser and **look at whether T1's K_t / W_t /
Σ1 / Ch edges are actually long converging lines, or already laid out locally
in the round body** (they're all in the same round group, so the layout may
already place them adjacent → edges already short → feature targets nothing).
Per `feedback_visual_smoke_vs_property_tests` and the Slice 3 revert, property
tests will NOT catch "the lines were already short." This is a manual browser
pass.

Decision tree:
- Lines already short → feature is a no-op for SHA-256; reconsider whether any
  shipped cipher has the pain, or shelve.
- Lines long → build the leaf-feeder auto-selection (approach above), targeting
  the specific nodes the smoke identifies.

---

## Key files
- `src/core/graph.ts` — `replicateHighFanoutSources` (~2325); fanout
  eligibility predicate (~2363–2368, the `kind:"aux" || port-flow-state` test).
- `src/ui/components/GraphView.tsx` — replication memo (~2930); `replicationSources`
  memo (~3090); modes plumbing.
- `src/ui/stores/view-replication.ts` — the replication toggle/threshold store.
- `src/ciphers/sha-256.ts` — high-fan-in nodes at lines 1381 (T1), 1432
  (repack), 1511 (final concat).
- `tests/replicate-fanout.test.ts` — existing fanout transform tests (pattern
  to mirror for a fan-in auto-selection test).
- `tests/graph-view-replication-threshold.test.tsx` — threshold toggle tests.

## Conventions reminder (from CLAUDE.md / memory)
- Comment frequently (educational project); FIPS refs where relevant.
- New behavior ships with tests in the same commit.
- This worktree may hit the known Windows worktree `npm run check` friction
  (CRLF + jsdom setupFile path); `.gitattributes` LF pin should help. If the
  gate fails spuriously, see `feedback_gitattributes_lf_pin` /
  `project_agent_worktree_env_broken`.
- Property tests are NOT enough for visual features — browser smoke required
  (`feedback_visual_smoke_vs_property_tests`).
