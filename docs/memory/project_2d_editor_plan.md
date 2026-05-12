---
name: 2d-editor-plan
description: Approved plan for the 2D/DAG visual cipher editor + JSON document export. Lives at ~/.claude/plans/peppy-knitting-fairy.md. Slices 1, 2, and 3 shipped 2026-05-12; next session resumes at Slice 4 (mutation surface growth) or any unshipped slice.
metadata: 
  node_type: memory
  type: project
  originSessionId: bee780f0-1373-4dbc-809c-4ac1fcc3ac66
---

The 2D/DAG visual cipher editor + JSON document export feature is planned and approved as of 2026-05-12. Full plan: `~/.claude/plans/peppy-knitting-fairy.md`. Atomized into 11 slices, each independently shippable as one commit.

**Why:** User explicitly requested loose coupling but tight integration, work spanning many sessions and many commits. The slicing satisfies this — slices 1+3+4 are the dependency-free spine (pure data, no UI); slices 2/5/6/7/8/9/10 interleave freely after the spine; slice 11 is end-to-end integration.

**How to apply:** When the user returns to work on this feature, read `~/.claude/plans/peppy-knitting-fairy.md` first, check `git log` for which slices have already shipped, then pick the next one. Only skip to a different slice if the user names one.

## Slice progress

- ✅ **Slice 1 — aux-graph derivation** (commit `5840e93`, 2026-05-12). `src/core/graph.ts` exports `deriveAuxGraph(trace, spec) → CipherGraph` plus `GraphNode` / `ContainerNode` / `GraphEdge` types. 17 tests in `tests/aux-graph-derivation.test.ts`. Two non-obvious correctness pieces locked in by advisor feedback: `:b{i}` suffix collapse during edge dedup, and iterate-mediated edge synthesis (`split-blocks → iterate → concat-blocks` for ECB). Conscious plan deviation: `rootIds: string[]` (mixed leaves + container ids in spec order) instead of `rootContainers: ContainerNode[]` — top-level can mix leaves and containers, the plan's shape would have dropped the leaves.
- ✅ **Slice 2 — read-only graph view tab** (commit `3bf7f76`, 2026-05-12). `src/ui/components/GraphView.tsx` + `src/ui/stores/view-mode.ts`. Tab bar above `.trace-view` with three modes: `linear` (today's per-frame view), `graph`, `json` (raw spec). Hand-rolled SVG layout: top-level / iterate bodies flow LTR, groups stack vertically, iterates get a `×N` chip. Click leaf → setFrame. 9 tests in `tests/graph-view.test.tsx`. NO drag, NO edit yet — that's Slice 6 / 8.
- ✅ **Slice 3 — CipherDocument schema + (de)serialization** (2026-05-12). `src/core/document.ts` exports `CipherDocument` types + `serializeDocument` (stable alphabetical key order at every level; arrays preserve order) + `parseDocument` (returns `{ ok: true, doc } | { ok: false, error }`). `src/core/document-schema.ts` holds the Zod schemas: `.strict()` on wrapper layers (CipherDocument / LayoutSpec / SessionSnapshot / DocumentMetadata) so unknown fields force a schemaVersion bump, loose on CipherSpec / StepNode for forward-compat within v1. StepNode uses `z.discriminatedUnion` (better error paths) + recursion via `z.lazy(() => StepNodeSchema)` on the children fields (keeps each per-kind ZodObject's concrete type so `discriminatedUnion`'s per-option constraint is satisfied without casts). `schemaVersion` pre-check in `parseDocument` produces a friendly forward/back-compat error before the schema fires. 54 tests in `tests/document-roundtrip.test.ts` cover every shipped spec + sidecars + error paths + stable-key-order + enum coverage. **Two non-obvious correctness pieces** (would-be silent regressions if a future refactor breaks them): (1) hand-written TS types in `document.ts` because Zod's `.optional()` infers `T | undefined`, which doesn't satisfy `field?: T` under `exactOptionalPropertyTypes` — `result.data as unknown as CipherDocument` is the boundary cast. (2) `CIPHER_IDS` / `CIPHER_MODES` / `PADDING_SCHEMES` constants in document-schema.ts must stay synced with the union types in ui/stores — the `satisfies readonly Cipher[]` lower-bound + `Exclude<Cipher, typeof CIPHER_IDS[number]>` upper-bound `assertCipherCoverage` constant (exported to dodge `noUnusedLocals`) pins both directions at compile time. Adding a new cipher fails to typecheck if the list isn't updated.
- ⏳ **Slice 4 — spec mutation surface growth.** Extends `src/core/spec-mutations.ts` with `findStepAndParent`, `insertStepAfter/Before`, `removeStep`, `reorderStep`. Pure. Unblocks Slice 8 (palette insert). **The spine (1/3/4) is now two-thirds shipped — only Slice 4 remains before any of the UI slices (5/6/7/8/9/10) can land.**
- ⏳ Slices 5–11: see the plan for shape. Slice 5 (Save/Load UI) and Slice 7 (URL share) now have their data foundation (Slice 3); they're just blocked on UI work.

**Key user choices baked into the design** (locked in; don't re-litigate without asking):
- File scope: BOTH "spec + layout only" AND "full session (inputs+key+view-state)" variants, user picks per Save/Share action via toggle.
- Graph flow direction: LTR (left-to-right). Time flows rightward, aux lanes are horizontal stripes connecting to rounds via vertical drops.
- Iterate node visualization: collapsed by default with `×N` badge; user can double-click to unroll all N copies (unroll lands in a later slice — Slice 2 just shows the badge).
- Ambition: full — all 11 slices including aux operation primitives (lets the user compose CBC from scratch).

**Three architectural decisions to preserve** (advisor-derived; losing them risks regressing):
1. **The graph is derived from `TraceFrame.auxRead/auxWritten`, never stored in the spec.** Pure function `deriveAuxGraph(trace, spec)` is the spine. No new field on `StepDocumentation`. Pre-run shows nodes-only; 200ms after any edit, edges appear via the existing auto-rerun debounce. **Shipped in Slice 1.**
2. **`LayoutSpec` lives in a `CipherDocument` wrapper as a sidecar, NOT as fields on `StepNode`.** `src/core/types.ts` declares "saved JSON references these shapes forever" — view-only `{x, y}` data on `StepLeaf` would break that contract. Saved spec stays canonical; layout is gracefully optional. See plan's "CipherDocument schema" section for the full shape. **Lands in Slice 3 (schema) + Slice 6 (drag).**
3. **Iterate `:b{i}` suffix collapse owns multi-block consolidation.** AES-128-ECB's 164 frames collapse to 44 logical nodes by stripping the suffix during graph derivation and deduplicating identical `(from, to, auxKey)` triples. `blockSpan: N` on iterate-body nodes feeds the `×N` badge. **Shipped in Slice 1; renderer uses it in Slice 2.**

**Advisor-flagged correctness piece for any future graph work** (shipped in Slice 1, easy to break in a refactor): the runtime moves three aux values across the iterate boundary itself (`countFromAux` read, `blocksFromAux` read, `outBlocksAux` write at `runtime.ts:48/81/86`), NONE via a frame's `auxWrites`. A naive frame-walk would leave the `split-blocks → iterate → concat-blocks` edge dangling. `deriveAuxGraph` synthesizes those edges by detecting iterate entry/exit via `frame.path` deltas — keep that logic if you refactor edge derivation.

**Already-known reusable surface** (from Phase 1 exploration; some now consumed):
- `zod` 3.24 installed in `package.json:20`, consumed by `src/core/document-schema.ts` (Slice 3 ✓).
- localStorage pattern across 5 stores (`src/ui/stores/format.ts:18-48` is the template). Now also: `src/ui/stores/view-mode.ts` (Slice 2 ✓). Slice 6 will add `layout.ts`.
- `findStep` exists in `spec-mutations.ts`; Slice 4 extends with `findStepAndParent` + insert/remove/reorder.
- `RunSnapshot` already captures spec+trace+inputs+key+mode — `CipherDocument`'s `SessionSnapshot` mirrors it (Slice 3's session field is `{ mode, cipher, cipherMode, padding, byteFormat, inputBytes?, keyBytes? }`).

Cross-links: [[feedback-commit-cadence]] (one slice = one commit + push, push after each — pattern was followed for Slices 1 and 2), [[feedback-frame-preservation]] (graph view click-to-focus must route through stepId, not raw frame index — Slice 2 enforces this; universal invariant for future slices too).
