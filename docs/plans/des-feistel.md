# DES + branching primitive — first Feistel cipher

> **Status: Phases 1–6 shipped 2026-05-19 / 2026-05-21. Phase 6e
> manual walk COMPLETE 2026-05-22 (walks #1–#4 over 2026-05-21/22).
> All 7 checklist items (M1–M7) confirmed; the original closing
> batch of 5 fixes (Findings A/B/E/F/H) verified clean in real
> browser, plus 3 "not a bug" entries (C/D/G) re-confirmed as
> working-as-designed. Ten new UX findings captured during the
> walks for post-walk action (UX-A/B/C from walk #2, UX-D from
> walk #3, UX-E/F/G/H/I/J from walk #4) — none are regressions of
> the closing-batch fixes; all are pre-existing gaps the closing
> batch did not address. The universal-port-dataflow plan's
> "wait for DES Phase 6e" gate is now **satisfied** — that plan
> can begin Phase 0 (the ~3-day trace-shape spike) on user
> demand. The post-walk UX fix queue is ready for prioritised
> implementation; see "Fix-order update with UX-E…J added"
> below. The earlier Phase 6e closing
> batch (5 fixes shipped) remains valid; the new findings are
> pre-existing gaps the closing batch did not address. Universal-
> port-dataflow plan (`docs/plans/universal-port-dataflow.md`)
> remains unblocked — the new findings are UX polish/feature work,
> not regressions, and don't reopen Phase 6e's "wait for DES" gate
> for the universal-port plan.

> **Phase 6e partial walk #4 (2026-05-22, in progress).** Fourth
> manual session against the same 7-item checklist. M4 confirmed
> this session; three new UX findings surfaced during M4's cross-
> check; walk continuing with M5 next.
>
> **M4 — Rejoin crossover X arrows uncolored — ✅ CONFIRMED.** At
> round.1's rejoin, both X-crossover arrows (`new_L → next L`,
> `new_R → next R`) render in the default state-edge stroke, not in
> any source-coding palette colour. Confirms the
> `sourceFanoutMap`-excludes-rejoin-synthetics fix in
> `src/core/source-colors.ts:129-137`. Round 16 cross-check: the
> rejoin emits a single outgoing edge to `final-permutation`
> (feistel-no-swap, no X-crossover); also uncoloured as expected.
>
> **Three new UX findings (captured for post-walk-close action):**
>
> - **UX-E — Rejoin not user-opt-in colorable.** Today's exclusion
>   in `sourceFanoutMap` is pre-fanout-count, so the panel toggle
>   "include single-output sources" never sees the rejoin and the
>   user has no escape hatch to colour it. The opinionated default
>   ("two halves of the same combined state, not distinct sources")
>   is defensible for AUTO assignment, but a manual-override surface
>   is a fair ask — e.g. a per-instance overrides set keyed by stepId
>   that lets the user paint a rejoin manually without changing the
>   auto-assigned palette. Lowest-impact fix candidate: keep the
>   auto-exclusion, but plumb manual overrides through a separate
>   path that doesn't filter rejoins. Defer until a user actually
>   needs it.
>
> - **UX-F — L-passthrough drop is one-way / palette can't restore
>   it.** Dropping a palette step onto an empty Feistel-track's
>   passthrough chip replaces the chip (track becomes populated,
>   passthrough disappears) — pedagogically correct since
>   passthroughs are placeholders for empty tracks. But the palette
>   has no `feistel.passthrough` entry, because passthroughs are
>   runtime-synthetic placeholders, not real spec leaves. So once
>   populated, the only way to re-empty a track is `reset spec`,
>   which nukes everything the user has changed.
>
>   **Resolution: path (a) — generic per-leaf delete UX.** Advisor-
>   confirmed 2026-05-22 (verbatim reply preserved in session
>   transcript). Implementation shape:
>   - **Existing mutation:** `removeStep` in
>     `src/core/spec-mutations.ts:831` already works on any leaf id
>     by walking the parent-array. No new core mutation needed.
>   - **UI shape:** keyboard-first — select a leaf → Delete /
>     Backspace removes it. Piggyback on the graph view's existing
>     selection state (the same state that drives the inspector).
>     Visible affordance for discoverability — `×` glyph on hover,
>     or a context menu entry — so the gesture is reachable without
>     reading docs.
>   - **Scope guard for v1:** leaves only. Block delete on container
>     nodes (`feistel-round`, `iterate`, `group`); deleting a
>     populated container is a separate UX question with destructive
>     consequences and a different undo/confirmation story.
>   - **Test focus per advisor:** delete-on-leaf in an L-track →
>     confirm the passthrough chip re-renders → click passthrough
>     chip → inspector resolves L_in via
>     `lookupPassthroughBytes` (`edge-value-lookup.ts:757`). Bug 1
>     intersection (existing rejoin-frame-still-present invariant);
>     should pass cleanly but pin it.
>
>   **Paths rejected:** (b) Feistel-specific "clear track" button —
>   dead-on-arrival under the approved universal-port-dataflow plan
>   (`docs/plans/universal-port-dataflow.md`), which slates
>   `FeistelRoundGroup`/`BranchTrack`/`CombineKind` for Phase 5
>   deprecation; the button would have to be removed alongside the
>   types. (c) Palette entry that lowers to spec-time
>   `feistel.passthrough` — largest blast radius (touches
>   `runtime.ts:275`, `edge-value-lookup.ts:649-770`, graph
>   derivation, layout, inspector resolution) AND writes off badly
>   under the universal-port plan, where passthroughs become wires
>   (absence of a node between two port endpoints), not first-class
>   spec leaves.
>
>   **Status: ready for implementation post-walk.** TODO entry
>   added to the post-walk fix queue at the priority below.
>
> - **UX-G — Round 16 → final-permutation long arrow.** Round 16's
>   rejoin has a single outgoing state edge to `final-permutation`
>   (its next sibling in the spec tree). Visually the user reports
>   the arrow travels upward across all 16 rounds before terminating
>   at FP, which looks bad and obscures the actual sequence
>   (rounds → FP). Suggests the current layout places FP at a
>   position incompatible with the bottom-of-rounds-group exit —
>   either FP is positioned above the rounds group, or the rounds
>   group is laid out in a flow that puts round-16 not-at-bottom.
>   Investigation needed in `layoutRoot` / `layoutNode`'s sibling-
>   advance logic. Concretely: when the previous sibling is a tall
>   group with downward flow, the next sibling (FP) should anchor
>   below the group's max-y, not above. Worth checking whether the
>   existing `naturalY` fix from Finding H(ii) (Phase 6e closing
>   batch) covers this case or whether it's a separate cursor-
>   advance bug at the GROUP-EXIT boundary specifically.
>
> **M7 — L passthrough's outgoing arrow shows 4B — ✅ CONFIRMED.**
> The L-passthrough chip's outgoing arrow to rejoin resolves
> through `lookupRegularState`'s passthrough-source short-circuit
> at `edge-value-lookup.ts:800-808`, calling the shared
> `lookupPassthroughBytes` to slice `params.L_in` from the parent
> rejoin frame. Same value as M3's chip-click resolution
> (producer-side and chip-click share the helper). Confirms the
> Bug 13 fix.
>
> **M6 — Rejoin-source arrows show single-track bytes — ✅ CONFIRMED.**
> Round.5 rejoin's two outgoing arrows: L-track arrow shows 4B
> = `new_L`, R-track arrow shows 4B = `new_R`, values are
> distinct (no longer the combined 8B on both). Round.16 cross-
> check: the rejoin → final-permutation single outgoing arrow
> shows the full 8B `L_out||R_out` — `findConsumerTrackIdx`
> returns `null` for an out-of-feistel-round consumer, falling
> through to the default "full stateAfter" path in
> `edge-value-lookup.ts:843-849`. Confirms the Bug 10 fix.
>
> **M5 — Ciphertext placement in `.inputs` section — ✅ CONFIRMED**
> (with three new all-ciphers UX remarks; logged as UX-H/I/J).
> The result line renders inside `.inputs` as a `flex: 0 0 100%`
> row (label-inline `ciphertext (hex): <code>85e813540f0ab405</code>`),
> sandwiched between the input fields and the action button strip.
> Mode-flip to decrypt changes the label to `plaintext` per
> `outputLabel()` derivation from `mode()` in `App.tsx:1095-1099`.
>
> **Three new UX findings (all-ciphers, not DES-specific):**
>
> - **UX-H — Mode flip should auto-swap values.** Today, flipping
>   encrypt → decrypt re-runs the cipher on the still-present
>   plaintext, computing it AS ciphertext (so the user sees a
>   nonsensical result for the new mode until they manually paste
>   in the previous output). User-flagged 2026-05-22 walk #4:
>   the round-trip discoverability ask is "make the just-computed
>   result the new input." Symmetric — encrypt→decrypt copies
>   current `outputBytes` (ciphertext) into the ciphertext input;
>   decrypt→encrypt copies current `outputBytes` (plaintext) into
>   the plaintext input. Implementation point: mode-change handler
>   in the spec/inputs store; needs care around the IV / padding /
>   block-mode interactions (e.g. CBC IV: should it also flip?).
>   Out of scope for v1: probably leave IV alone, let user adjust.
>
> - **UX-I — Stack input / key / result vertically with input
>   first.** Today the inputs section is a wrapping flex row:
>   `[selects…] [input] [key] [IV?] [result-100%-row] [buttons]`.
>   The result row is forced full-width, so input + key sit
>   side-by-side ABOVE the result. User-flagged 2026-05-22 walk
>   #4: the visual sequence should be "thing-I-edit → key →
>   what-came-out" with each on its own row. Implementation point:
>   force `flex: 0 0 100%` on `<label>` wrappers around input,
>   key, IV — or restructure the section as a column flex below
>   the selects row. The selects (mode, cipher, mode-of-op,
>   padding, bytes-format) stay together as a horizontal settings
>   strip; the data fields (input/key/IV/result) become the
>   vertical stack below it.
>
> - **UX-J — Result label-above-value (match input field styling).**
>   Today the result row renders as inline-label
>   `ciphertext (hex): <code>85e813540f0ab405</code>`, whereas
>   plaintext + key fields use `<label>` wrapping a label above
>   their `<input>`. User-flagged 2026-05-22 walk #4: visual
>   inconsistency — the inputs and the result share a row neighbour-
>   hood but use different label conventions, which makes the
>   result look like a different KIND of thing (caption vs. field)
>   when it's pedagogically the third member of the same trio.
>   Fix: render the result as `<div class="result inputs-result">
>   <span class="result-label">…</span><code>…</code></div>` with
>   the label above the code block, mirroring the input-field
>   `<label>` stack layout. CSS in `app.css:221-231` needs a tweak
>   to switch from inline display to flex-column.
>
> **Fix-order update with UX-E…J added:** UX-B (real bug) →
> UX-D (pedagogy gap; every Feistel round) → UX-G (visual bug;
> visible the moment graph view is opened on DES) → UX-F (real UX
> gap; resolution locked to path (a) per-leaf delete) →
> **UX-H/I/J bundled** (all-ciphers inputs-row polish — one
> implementation pass touches the same section in `App.tsx` +
> `app.css`, so batch them; UX-H is the behavior change, UX-I/J
> are layout polish on the same surface) → UX-C (consistency
> feature) → UX-A (polish) → UX-E (opt-in surface; nice-to-have,
> defer until user-requested). UX-G promoted high because it's
> visible on the default DES graph view with no user interaction.
> UX-H/I/J bundled at single priority because they all live in the
> same code path; splitting them would mean editing the same file
> three times.
>
> **Future ideas — NOT in the post-walk queue:**
> - Drag-leaf-back-to-palette as a complementary deletion gesture
>   (path (e) from the UX-F advisor consult). Same `removeStep`
>   call, palette becomes a drop zone. Cheap, discoverable,
>   composes with the keyboard-first (a) resolution. Worth
>   revisiting once (a) is in users' hands and we see how
>   discoverable Delete/Backspace turns out to be.
> - Undo stack on the spec store (path (d) from the same consult).
>   Strictly more powerful than per-leaf delete — solves "I made a
>   change I want back" universally. Cost: real history-stack
>   abstraction in `stores/spec.ts` + URL-share serialization story
>   (does undo persist? does the shared link carry pre-edit
>   state?). Overkill for UX-F alone; only worth pursuing if a
>   broader "undo for spec edits" demand emerges. Memory entry:
>   [[project-future-ideas-spec-edit-undo-and-drag-back]].

> **Phase 6e partial walk #3 (2026-05-22, mid-walk pause).** Third
> manual session against the same 7-item checklist. Two items
> confirmed this session; walk paused after M3.
>
> **M2 — DnD into a feistel-round track gutter — ✅ CONFIRMED.**
> Dragged a palette leaf onto round.5's L-passthrough chip: chip
> lit up `.graph-drop-target-active` during hover, on release the
> passthrough was replaced by the new step (track populated), STEPS
> sidebar showed the step under L. Drop into the R-track gutter
> landed under R. Auto-rerun fired in both cases (ciphertext
> diverged from FIPS Appendix B `85e813540f0ab405`). Closes the
> manual half of Phase 6d-v + 6e finding B.
>
> **M3 — Click rejoin / passthrough chip → inspector — ✅ CONFIRMED
> (with design clarification).** Clicking a rejoin chip opens the
> inspector with the real rejoin frame (4-arg combine detail with
> track snapshots). Clicking a passthrough chip does NOT show a
> "frame" — by design, passthroughs emit zero runtime frames
> (`runtime.ts:275`); the inspector resolves the chip via
> `lookupPassthroughBytes` and surfaces the L_in/R_in bytes as a
> state value, not a frame envelope. User verified no "no frame
> found" surface anywhere, confirming the Bug 1 fix in
> `edge-value-lookup.ts` (canonicalize both sides) still holds.
>
> **UX-D — R_in → rejoin edge missing (new this walk).** Surfaced
> while reviewing M3's rejoin behaviour. In feistel-standard, the
> rejoin computes `new_L = R_in` AND `new_R = L_in ⊕ F(R_in, K_i)`.
> Today's rejoin chip has incoming arrows from the L passthrough
> (= L_in) and from the last F-stack step (= F(R_in, K_i)) — but no
> visible arrow shows `R_in` flowing into the rejoin to become
> `new_L`. The "swap" half of Feistel is therefore invisible in the
> graph; users have to read narrators or the abstract Feistel mini-
> diagram to learn it. Pedagogical cost is real — graph view should
> stand on its own. Fix candidates:
> (a) Synthesize a direct edge from the R-track's first leaf
>     (the leaf that consumes R_in — DES's `expand-R`) → rejoin,
>     labeled / typed so users read it as "the original R, bypassing
>     F." Cheapest visually; minor risk of arrow tangle with the
>     F-stack edge already terminating at rejoin.
> (b) Promote the R-track input to its own chip (mirror of the L
>     passthrough), so `R_in → passthrough → rejoin` is visible in
>     parallel with `L_in → passthrough → rejoin`. Symmetric and
>     analogous to UX-B's 6b-ii treatment, but adds a chip + a
>     re-route for every populated R track.
> (c) Re-shape the rejoin chip to expose `R_in` as a labelled
>     incoming port distinct from the F-stack output port. Most
>     pedagogically precise; biggest renderer change.
> Combine-kind awareness matters: under `feistel-no-swap` (DES
> round 16, possibly future variants), `new_L = L_in ⊕ F`, so
> R_in → rejoin isn't load-bearing there. The synthesis (any
> option) should gate on `combineKind` so round 16 stays clean.
>
> **Fix-order update with UX-D added:** UX-B (real bug) → UX-D
> (real pedagogy gap; visible the moment graph view is opened on
> DES) → UX-C (consistency feature) → UX-A (polish). UX-D promoted
> ahead of UX-C because it affects every Feistel round 1–15 every
> time the user opens graph view, whereas UX-C only matters when
> the user edits S-boxes.

> **Phase 6e partial walk #2 (2026-05-21, mid-walk pause).** Second
> manual session against the manual checklist of 7 items still
> uncovered by the Playwright self-smoke (see header of
> `e2e/des-phase-6e-self-smoke.spec.ts`). User chose to walk all 7
> in order. M1 completed and confirmed; M2 not yet started; walk to
> resume in a future session.
>
> **M1 — S-box edit narration update — ✅ CONFIRMED.** Edit S1[0][0]
> 0e → 0f via Graph view's ParamEditor, scrub back to round.1.s-boxes
> in Linear view: the S1 narration disclosure renders concrete
> `(row, col) → value` prose (`S1[0][12] = 5` for the FIPS Appendix
> B vector at round 1), no stale state, no broken byte references.
> Auto-rerun fires (Compare Runs surfaces "round.1.s-boxes: sboxes
> changed" delta line; new run id appears). The narrated value for
> S1 is unchanged pre/post-edit only because round.1's lookup hits
> S1 at (row 0, col 12), not (row 0, col 0) — narration reads the
> current params correctly, the edit cell just isn't queried in
> this frame.
>
> **Three new UX findings (captured for post-walk-close action):**
>
> - **UX-A — pane/disclosure labels missing.** Multiple panes in
>   linear and graph views lack their own header labels: (1) the
>   StepNarration pane has no own label; (2) its neighbour pane
>   (containing Round Entry / Right Now / Round Output sub-sections)
>   has internal sub-labels but no own label; (3) AES key-expansion's
>   `<details>` for the S-box has no header label outside the
>   summary text; compare with the labelled "Abstract Structure"
>   pane that does carry a header. Single UI polish slice to add
>   consistent labels across panes + disclosure-containing sections.
>
> - **UX-B — graph param editor `<details>` collapses on edit
>   (DES-local).** Editing a cell inside an expanded S_k disclosure
>   in `DesSBoxesBlock` causes that `<details>` to close, disrupting
>   the user's focus. Cross-check confirmed DES-local scope: AES
>   key-expansion's `<details>` (which wraps the 256-entry SboxEditor)
>   stays open across cell edits, so the `<Switch>`/`<Match>` re-
>   evaluation in `ParamEditor` is NOT re-mounting at the block
>   boundary. Root cause hypothesis: `DesSBoxesBlock` uses
>   `<For each={sboxes()}>` to map over the 8 S-boxes; each cell
>   edit produces a new sboxes array with all 8 items at new
>   references (rows + outer array are spread-copied), so Solid
>   `<For>`'s reference-equality reconciliation re-mounts all 8
>   `<details>` elements. Fix candidates: (a) switch `<For>` to
>   `<Index>` (reconciles by position, item identity becomes an
>   Accessor) — simplest, ~10 lines; (b) hoist `open` state to a
>   `(stepId, sboxIndex)`-keyed signal in a parent store. Try (a)
>   first unless Solid `<Index>` has gotchas with the nested
>   accessor pattern in this block.
>
> - **UX-C — DES S-box Repair button missing.** Inconsistency with
>   AES SubBytes + Serpent S_i, both of which ship a "Repair to
>   permutation" button next to the S-box editor. The existing
>   `DesSBoxesBlock` comment (`ParamEditor.tsx:~1006-1015`)
>   justifies the omission as "FIPS 46-3 tables ARE the canonical
>   state and the user can always hit Reset spec to recover" — but
>   that argument applies word-for-word to AES SubBytes (FIPS-197)
>   and Serpent S_i, both of which DO ship Repair. The justification
>   doesn't distinguish DES from its precedents. Right shape: a
>   per-S-box "Repair S_k to row-permutations" button at the top
>   of each `<details>`, scoped to that S-box's 4 rows. `repairToPermutation`
>   is already size-parameterized on `values.length` per the
>   existing comment, so calling it row-by-row on length-16 rows
>   works unchanged. Button disabled when no row has duplicates.
>
> **Process note:** advisor + Claude agreed mid-walk that the right
> move was to capture-and-continue rather than detour into fixes.
> User confirmed: build the fixes after the walk closes. Mid-walk
> pause was the user's own call, not an advisor recommendation —
> the walk simply spans more browser time than this session had
> capacity for. Fix priority (post-walk): UX-B (real bug) → UX-C
> (consistency feature) → UX-A (polish).

> **Phase 6e Playwright extension (2026-05-21, commits `e9ce34a` +
> `f44b362`).** Four new checkpoints added to
> `e2e/des-phase-6e-self-smoke.spec.ts` to pin regressions of the
> bug-fix batch + close item 5 of the original checklist:
> - **cp 10** — graph view hides `.trace-timeline` + `.step-list-pane`
>   from the DOM (Bug 12 regression).
> - **cp 11** — DES Rounds group container's header rect appears in
>   the DOM BEFORE every `round.N` header rect, asserting the
>   depth-ascending paint order from `containersInPaintOrder`
>   (Bug 3 regression).
> - **cp 12** — round.1's `key-schedule@->round.1.xor-K` replica
>   chip's bounding box falls inside the Rounds container's full
>   `<rect>` (Bug 14 regression on spine-replica same-parent rule).
>   Requires `cryptographer.replicationEnabled=true` in localStorage.
> - **cp 13** — clicking the round.1 s-boxes leaf in graph view
>   mounts `DesSBoxesBlock`; a real keyboard edit on S1[0][0] (0e →
>   0f) reaches the spec store, verified via the cell's reactively-
>   computed `title` attribute ("= 15 — duplicate value..."). Closes
>   the spec-mutation half of original checklist item 5; the
>   narration-update half stays on the manual list.
> Selector + driver lessons captured inline: container header
> `<rect>` carries `data-testid="graph-container-header-${id}"` (NOT
> the outer `<g>`), so header-rect DOM index proxies parent-`<g>`
> paint order; and Solid's `onInput` requires REAL keyboard input
> (`cell.type()`), not `evaluate(el => el.dispatchEvent(new
> Event("input")))`.

> **Phase 6e closing batch (2026-05-21).** User's manual browser
> walkthrough surfaced 8 findings; 5 were real bugs and got fixed,
> 3 were working-as-designed and got documented:
> - **Finding A (collapsed-round arrows not crossed):** `rejoinSwapSourceXSign`
>   extended to also fire when the source is a COLLAPSED feistel-round
>   container, not just the rejoin synthetic. `collapseGraph` clears
>   the rejoin's children and remaps outgoing edges to start from the
>   container id directly; the X-crossing pedagogy still applies
>   because the eye reads two outgoing edges to the next round's two
>   columns. 3 new regression tests in `tests/rejoin-swap-source-x.test.tsx`.
> - **Finding B (drop replaces L-passthrough):** NOT A BUG — the
>   passthrough's column IS the `into-track-start` gutter (Phase 6d-v
>   shipped this), and populating the empty track removes the
>   passthrough placeholder. The UX gap was no visual signal that the
>   chip is the drop target. Fix: `PassthroughChip` now takes
>   `isDropTargetActive` and lights up via the existing
>   `.graph-drop-target-active` CSS rule when the underlying gutter is
>   hovered. Tooltip updated to explain the replace semantic.
> - **Finding C (drop between L and R within a round does nothing):**
>   NOT A BUG — no inter-track drop zone exists inside a single round
>   body. The inter-track GAP drop is at the parent Rounds-group level
>   (Phase 6d-vii), not within a round body.
> - **Finding D (arrows from inserted step are colored):** NOT A BUG —
>   this is source-color-coding for a 2-consumer node (`docs/plans/
>   source-color-coding.md`). The inserted step's output feeds both
>   the next round's L-passthrough and expand-R, so both arrows share
>   the inserted node's hue.
> - **Finding E (S-box editor read-only):** Fixed. `DesSBoxesBlock` in
>   `ParamEditor.tsx` now renders each cell as a `ByteCellInput`
>   clamped to 0..15, with per-row duplicate detection (each row must
>   be a permutation of 0..15). Code comment had already flagged this
>   as a future polish slice.
> - **Finding F (load/share doesn't flip cipher selector for non-AES):**
>   Fixed. Added an optional top-level `cipher` hint to
>   `CipherDocument` (option (b) from the originally proposed fix
>   paths). `setSpecFromDocument` reads it; `applyDocument` additionally
>   smart-swaps the input/key fields when they match the OLD cipher's
>   canonical defaults — mirroring `changeCipher`'s manual-selector
>   policy. 13 new tests in `tests/document-roundtrip.test.ts`.
>   `e2e/des-phase-6e-self-smoke.spec.ts` checkpoint 9 re-baselined
>   from "bug reproduces" to "bug fixed."
> - **Finding G (load doesn't restore plaintext from spec-only save):**
>   NOT A BUG — spec-only save deliberately omits `inputBytes` /
>   `keyBytes` so a public URL share doesn't leak the user's
>   plaintext. Toggle "include session" before saving to include them.
> - **Finding H (rounds escape parent container + sibling drag):**
>   Fixed as two related changes:
>   - H(ii): group's child-layout loop captures `naturalY` BEFORE the
>     child call and advances `innerY` using `naturalY + childBox.h +
>     STACK_GAP`. Mirrors the root-level pattern in `layoutRoot`
>     (line 1576/1593). Without this, pinning round.5 up shifted the
>     cursor that placed round.6, dragging round.6..16 along.
>   - H(i): `startNodeDrag` computes `parentInteriorBounds` at drag
>     start and clamps `newX/newY` to them in `onMove`. Root-level
>     nodes (no parent) keep the existing (0,0) SVG-bounds floor.
>   - 2 new regression tests in `tests/graph-view-drag.test.tsx`.
>
> See "Phase 6 session log (2026-05-20)" section below for the
> earlier bug-fix batch and the commit-by-commit trail.
>
> **Phase 6e bug-fix batch (2026-05-20).** Playwright pre-flight on
> `e2e/des-phase-6e-self-smoke.spec.ts` + the user's partial manual
> pass surfaced 8 findings; 6 fixed in this batch:
> - **Bug 1 (inspector "no frame found"):** rejoin chip + passthrough
>   chip clicks + state-edge endpoint resolution. Fix in
>   `src/core/edge-value-lookup.ts` (canonicalize both sides;
>   passthrough chips resolve to L_in/R_in via shared helper).
> - **Bug 2 (rejoin crossover X colored):** filter rejoin synthetics
>   from `sourceFanoutMap` in `src/core/source-colors.ts`.
> - **Bug 3 (no border on individual rounds):** root cause was SVG
>   paint order (parent group's rect on top of children). Fix:
>   `containersInPaintOrder` memo sorts by depth ascending in
>   `GraphView.tsx`. CSS dialled back to subtle AES-like register.
> - **Bug 4a (ciphertext placement):** moved into `.inputs` section
>   as a flex-100% row above the action buttons.
> - **Bug 10 (rejoin-source arrows showed combined 8B on both):**
>   slice by consumer's track membership in `lookupRegularState`.
> - **Bug 12 (slider + StepList shown in graph view):** wrapped both
>   in `<Show when={viewMode() !== "graph"}>`.
> - **Bug 13 (L passthrough's outgoing arrow showed 8B):** producer-
>   side counterpart of the passthrough chip fix.
> - **Bug 14 (round.1 ks replica outside Rounds group):** spine-
>   replica designation now requires source.parent === consumer.parent
>   in `replicateHighFanoutSources`.
>
> **Two findings DEFERRED to `docs/plans/graph-vertical-flow.md`**:
> - Slice 6 (NEW): R-half visible split — show R_in branching into
>   both F-function AND the bypass that becomes new_L.
> - Slice 7 (NEW): L / R color-coding in inspector + arrows.
>
> **One finding pinned for future work**: `e2e/des-phase-6e-self-
> smoke.spec.ts` checkpoint 9 pins the spec-only URL share bug
> (recipient lands on AES-128 selector + key-size error). Memory
> `project_share_url_cipher_selector_bug.md` carries the
> reproduction + two proposed fix paths.
>
> **Phase 5 detail (preserved from earlier):** (including the two
> 5a/5b polish items the original Phase 5 fell short on).
> Commits: `91f143d` (P1 oracle), `6a046d0` (P2 primitive + toy),
> `be0bb6a` (P3 step types), `7b584f3` (P4 selector wiring), `9d16c95`
> (P5-pre StepList walker), `43703e9` (P5c rejoin view), `ef1cd92`
> (P5e DES key schedule), `1542e79` (P5a track-context), `2c7508c`
> (P5b mini diagram), `dcf291f` (P5d round-key panel coverage),
> `c2b90bd` (P5f scrubber badges), and the present commit (5a + 5b
> polish — cross-panel provenance overlay + K_i cross-reference).
> Phase 6 (graph-view branched layout + manual smoke) pending.
>
> **Phase 5 sub-commit order: 5-pre → 5c → 5e → 5a → 5b → 5d → 5f
> → 5a/5b polish** (fix-broken-UX-first per advisor: 5c and 5e
> replaced previously meaningless FrameStateView renders; 5-pre
> fixed a sidebar crash on DES; the rest are additive on top of
> working baseline). Phase 5d shipped with no code change — verified
> the existing 16-byte fallback already renders DES's 6-byte K_i
> ribbons correctly. Bit-grouped unfold deferred per advisor's
> "don't over-build" guidance.
>
> **Phase 5 deferred polish items — SHIPPED 2026-05-20** (this commit):
> - **5a cell-level provenance overlay** — `FeistelTrackContext` now
>   subscribes to `useProvenanceHover` and paints two derived
>   highlights: (1) `before-cell` sources mapped onto the current
>   track's round-entry row, gated to frames whose `stateBefore`
>   byte-matches the round-entry slice (DES expand-R is the only
>   such frame today; later track steps have different-shape
>   `stateBefore` so highlights suppress naturally). Transitive
>   provenance through prior leaves is deliberately out of scope.
>   (2) The hovered `afterCellIndex` mirrored onto the "right now"
>   row, tightening the cross-panel coupling. Both gated by the
>   `hover.stepId === frame.stepId` scope guard.
> - **5b K_i label cross-reference** — `FeistelMiniDiagram` now
>   renders a `K_N` subscript label next to any F-stack leaf with a
>   `params.roundKeyAux` (DES's xor-K, and any future cipher using
>   the standard `roundKeyAux` convention). Static spec read so the
>   label appears on every frame in the round, not just the xor-K
>   frame — the panel's per-frame active-K_i highlight already
>   syncs dynamically via `frame.auxRead`.
>
> **Phase 5 manual smoke CONFIRMED 2026-05-20** by user. Browser
> pass on DES covered: scrub onto a round body; click leaves in
> `<FeistelMiniDiagram />`; click rows in `<DesKeyScheduleExplorer />`;
> hover the scrubber strip while clicking through; hover an
> after-cell on the expand-R frame and confirmed the
> `<FeistelTrackContext />` lights up the corresponding R_in cells
> (and stayed clean on later track steps per the intentionally
> narrow gate); clicked the new sidebar `⇄ rejoin` entries; R-track
> auto-expanded on round expand. Phase 6 entry gate now fully
> closed — both code-side prerequisites and the jsdom-untested
> behavior in real browsers are verified.
>
> Originally drafted 2026-05-19; architecture direction (DES first +
> true branching, per Path C) approved by user. Multi-phase: 6 phases,
> ~3000–5000 lines including tests. The branching primitive is a load-bearing
> architecture change (touches `core/types.ts`, `runtime.ts`, `graph.ts`)
> deliberately designed-once against DES's harder constraints so it carries
> the rest of the Feistel family (TEA/XTEA, 3DES, eventually Twofish) without
> a representation refactor.

The first Feistel cipher in the project. Until now every shipped cipher (AES,
Speck, Serpent) has had a linear executor contract `(state, params) → state`
that lets the runtime treat consecutive same-parent leaves as sharing state.
Feistel breaks that — L and R halves evolve independently inside a round
body — so this plan introduces a new spec primitive AND wires the first
cipher to use it.

## Context

### Why DES, not TEA

The simpler-cipher-first pattern (AES → Speck → Serpent) is a bad fit here.
TEA's F function is a single ARX expression with no internal sub-structure;
shipping TEA as the first Feistel would let us dodge the F-decomposition
question that DES (and every other "real" Feistel) forces. Specifically:

| Question | TEA stresses? | DES stresses? | Blowfish stresses? |
|---|---|---|---|
| L/R branching visible | ✅ | ✅ | ✅ |
| F-decomposition with real spine | ❌ | ✅ | ✅ |
| Key-dependent components | ❌ | ❌ | ✅ |
| Self-referential key schedule | ❌ | ❌ | ✅ |
| n-way Feistel | ❌ | ❌ | ❌ (Twofish) |

DES is the sweet spot: it forces L/R + F-decomposition (the questions we need
to answer for the family) without piling on key-dependent S-boxes and
self-referential key schedules (orthogonal Blowfish concerns that would
muddy the design). It also reuses the bit-permutation machinery already
written for Serpent IP/FP, and ships with clean published KATs
(FIPS 46-3 + NIST CAVS).

TEA / XTEA become cheap follow-up commits once the primitive is in.

### Why true branching, not tuple state or aux-mediated

Walk a DES round body under each candidate representation:

**Aux-mediated** (state passthrough, L/R held in aux): 4 of 5 F-leaves
have state-passthrough, the spine through F is flat. Pedagogically wrong
for the most iconic Feistel; replaces the spine-as-headline-narrative
with an aux thicket.

**Tuple state** (new `feistel-pair-64` state shape): L/R cleanly labeled
between rounds, but F's internals (E-expand, S-boxes, P-permute) still
have to live in aux because state is the L|R tuple. Same flat-spine
problem inside F.

**True branching** (new spec primitive): the round body forks into a
left track (carries L unchanged) and a right track (runs F on R). Inside
the right track, state IS the 32-bit value being processed; E-expand
changes its shape (32→48 bits), S-boxes change it again (48→32),
P-permute preserves it. **Spine threads continuously through F's
internals.** Rejoin combines tracks via `L ← L XOR F_out, swap`.

True branching is the only option that makes DES's textbook diagram
literal on the canvas: a fork, two parallel tracks, F-computation
visible on R, rejoin at the swap. That diagram is *why* DES is taught
the way it is — flattening it would forfeit the cipher's pedagogy.

### Scope

Single-block DES (no ECB/CBC) — both encrypt and decrypt directions.
Branching primitive in core, DES step types, UI integration, KAT against
FIPS 46-3 Appendix B test vectors.

Out of scope: 3DES (mechanical follow-up once DES ships), DES ECB/CBC
(after the modes story settles for variable-block ciphers), TEA/XTEA
(cheap follow-ups under the same primitive), Twofish/Blowfish (n-way
Feistel + key-dependent S-boxes — separate plans), codegen.

## Approach

### Process: iterative slice review

Each of the 6 phases below ships as its own commit. **Before starting
the next phase, re-consult `advisor()` with the current state of the
codebase + the next phase's design.** This plan is too long-horizon to
front-load every decision — each phase produces real lessons (a
collapsed-edge rendering surprise, a port-spread tuning need, a
narration shape that doesn't fit the registry) that should inform the
next phase's design before code lands.

This is a project-wide pattern for multi-phase architectural plans, not
DES-specific — see `[[feedback-iterative-slice-review]]`.

### Phase 1 — verification oracle — SHIPPED 2026-05-19 (`91f143d`)

Per `[[feedback-crypto-verification]]`: before pinning ANY KAT, get an
external oracle running. Two viable choices:

- `node-forge` (npm, MIT) — has DES in its symmetric-cipher module.
- `pycryptodome` (Python) — used for previous cipher verifications.

Pin the FIRST KAT against the oracle's output, not against
FIPS 46-3 cited text. The published KAT
(`PT=0123456789abcdef, K=133457799bbcdff1 → CT=85e813540f0ab405`) is
the target; the oracle verifies our intermediate decomposition (IP
output, per-round L/R, FP output) matches the canonical reference.

A short verifier script lives at `scripts/verify-des.mjs` (or similar)
and is not shipped with the app — its only purpose is to produce the
intermediate KATs the tests pin against.

### Phase 2 — branching primitive in core — SHIPPED 2026-05-19 (`6a046d0`)

The headline architecture change. Adds one new spec node kind, runtime
support for executing it, and graph-derivation handling. No DES-specific
code in this phase — validated against a TOY Feistel (a 2-step round
where F is "XOR with constant key") that exercises the primitive
end-to-end without DES's complexity.

#### Data model (`core/types.ts`)

New node kind `feistel-round` alongside `step`, `group`, and `iterate`:

```ts
export type BranchTrack = {
  /** Byte indices from the input state that seed this track. */
  readonly inputBytes: readonly number[];
  /** Step nodes operating on the track's own state. May be empty
   *  (the passthrough case — typically the L track). */
  readonly children: readonly StepNode[];
};

/**
 * Named combine ops. Each is a 4-arg function over the per-track input
 * AND output snapshots: `(tracks_in, tracks_out) → new_state_bytes`.
 * The 4-arg shape is critical — textbook Feistel's `new_L = R_in` reads
 * the ORIGINAL right-track input, not its post-F output, so a combine
 * that sees only `tracks_out` can't reconstruct it.
 *
 * Pre-defined kinds cover the shipped use cases. Each is documented
 * with its (L_in, L_out, R_in, R_out) → (new_L, new_R) formula:
 *
 *   - "feistel-standard":     (R_in, L_in XOR R_out)
 *     Classic Feistel with swap. DES rounds 1..15.
 *   - "feistel-no-swap":      (L_in XOR R_out, R_in)
 *     Classic Feistel WITHOUT the post-round swap. DES round 16
 *     (and every cipher's "last round" by Feistel convention).
 *   - "feistel-add-into-left":  (L_in + R_out, R_in)
 *     One half of TEA's cycle. Modular byte-add into L; R unchanged.
 *   - "feistel-add-into-right": (L_in, R_in + L_out)
 *     The other half of TEA's cycle. Modular byte-add into R; L unchanged.
 *
 * Adding new ops is a kind-tag bump (no schema break since `CombineKind`
 * is a string union over `string` at the JSON layer).
 */
export type CombineKind =
  | "feistel-standard"
  | "feistel-no-swap"
  | "feistel-add-into-left"
  | "feistel-add-into-right";

export type FeistelRoundGroup = {
  readonly kind: "feistel-round";
  readonly id: string;
  readonly label?: string;
  /** Tracks in order. 2-track for binary Feistel (the only shipped
   *  case); future n-track ciphers (Twofish, 4-way) extend by adding
   *  entries here without a schema migration. The runtime + combine
   *  ops today assume `tracks.length === 2`; n-track unlocks when a
   *  future cipher adds the corresponding combine kinds. */
  readonly tracks: readonly BranchTrack[];
  readonly combineKind: CombineKind;
};

export type StepNode = StepLeaf | StepGroup | IterateGroup | FeistelRoundGroup;
```

Tracks declare which input bytes they consume via `inputBytes` rather
than auto-splitting at the midpoint. This keeps the primitive
representation-agnostic — a 4-way Feistel (Twofish) just declares four
tracks with non-overlapping byte ranges and registers a new
`feistel-4way-*` combine kind.

**Why 4-arg combine, not 2-arg-with-swap-flag**: a 2-arg combine over
post-track-output state can't reconstruct `new_L = old_R` (textbook
Feistel) because the R track's children replaced old-R with F(old-R).
The 4-arg model holds both input and output snapshots so the combine
can reference either. This also generalizes cleanly to Lai-Massey
(reads `L_in`, `R_in`, AND a parallel-computed F-value) without a
data-model bump.

#### Layer 0 — synthetic nodes, track naming, inspector row order

Three small but load-bearing data-model decisions for the primitive:

**Track naming**. `BranchTrack` gains an optional `name?: string` field
defaulting to the track's index in the parent's `tracks[]` array.
`TraceFrame.branchPath` is a `readonly string[]` of track names (not
indices) so the path remains readable across n-track futures
(`["upper-right"]` vs `["t2"]`). DES specs declare `name: "L"` and
`name: "R"` explicitly.

**Rejoin synthetic node**. The rejoin is rendered as a graph node
(click-target for the 4-arg combine inspector) but is NOT a spec
node. `GraphNode` gains an optional discriminator field
`synthetic?: "rejoin"` (analog to Slice 6's `blockChipOf`). The id is
deterministic: `{roundId}:rejoin`. Renderer + click-routing +
inspector all dispatch off `synthetic === "rejoin"`. The frame
emitted at rejoin uses the same `:rejoin` suffix on `stepId`
(matching the `:b{i}` / `:t{name}` convention).

**Split anchor**. NOT a synthetic node. The "split" is a virtual edge
endpoint — the state edge entering the round fans into N edges, one
to each track's first leaf. No new node id; no inspector entry.
Avoids node-count pollution and matches the iterate primitive's
treatment of "entry into the body" (no synthetic).

**Inspector row order on combine kinds**. `CombineKind` metadata
includes an `inspectorRowOrder: readonly ("L_in"|"L_out"|"R_in"|"R_out")[]`
ordering the 4 snapshots in the inspector to match the combine's
formula left-to-right. For `feistel-standard` (formula: `new_L = R_in,
new_R = L_in ⊕ R_out`), the order is `["R_in", "L_in", "R_out", "L_out"]`
— reading-order, not track-name-order. Pedagogical readability win.

**Frame-preservation test**. The `:t{name}` track suffix must thread
through `setTrace`'s stepId-matching the same way `:b{i}` does today
(per `[[feedback-frame-preservation]]`). A test in
`tests/frame-preservation-feistel.test.ts` pins this.

#### Runtime (`runtime.ts`)

`feistel-round` walks like `iterate` but two-tracks-in-parallel:

1. Slice input state by each track's `inputBytes` into a track-local
   `BytesState`.
2. Recursively walk each track's children with a track-tag in the
   per-frame metadata (`branchPath: ["left" | "right"]`, mirrors how
   `blockIndex` works).
3. Combine tracks per `combineOp` + `combineInto`. The rejoin emits
   ONE frame (kind = pseudo-leaf), stateBefore = pre-combine-snapshot,
   stateAfter = combined.
4. If `postSwap`, emit one more frame for the swap.
5. Resume parent-scope state thread from the rejoined value.

Per-iteration step ids gain a track suffix `:t{name}` when inside a
branch (analogous to `:b{i}` for iterates; uses the track's `name`
field — `"L"` / `"R"` for DES — not its index). Frame metadata grows
by one optional field:

```ts
type TraceFrame = {
  // ...
  readonly branchPath?: readonly string[]; // ordered list of track names
};
```

#### Graph derivation (`graph.ts`)

The `feistel-round` becomes a `ContainerNode` of a new kind
(`"feistel"` joins `"group"` / `"iterate"`). Two child-id lists
(`leftChildIds`, `rightChildIds`) instead of one. Rejoin + swap are
synthetic chip nodes the renderer can draw at the right edge.

State-spine inference rules grow one branch-aware case:

- Within a track: consecutive same-parent leaves share state (today's rule).
- Across tracks: NO state edge (tracks are independent).
- Into the round: the state edge entering the round fans into N virtual
  edges, one per track, each landing on the track's first leaf. No
  synthetic "split" node — the fan-out is realized at edge-rendering
  time only.
- Out of the round: state edge from the rejoin synthetic node →
  successor. Rejoin IS a node (clickable for the 4-arg inspector); see
  Layer 0 above.
- **Replica spine-successor tiebreaker**: when `replicateHighFanoutSources`
  picks a spine-replica for a source whose consumers span multiple
  tracks (e.g., `key-expansion` feeding both pre-F XOR in L AND F's
  XOR-K in R for some future cipher), prefer the track with NON-EMPTY
  children. Avoids 16 spine-replicas stacking above an empty L-track
  in DES. One-line rule added next to the existing first-state-consumer
  heuristic.

These rules are added in `inferStateEdges` + `replicateHighFanoutSources`,
NOT as Feistel-specific hooks — the design intent is that future branched
primitives (parallel hashing, AEAD's two-output shape) reuse the same
machinery.

**Collapsed-`feistel-round` edge fanning**: when a round container
collapses to a single chip, edges TOUCHING the round (aux from
key-schedule into per-track leaves, state spine through the round)
need to retarget at the collapsed chip — analogous to Slice 6's
`expandCollapsedIterates` and the spine-through-iterate fix (commit
`9029ab4`). A new pure transform `collapseFeistelRoundEdges` in
`core/graph.ts` runs alongside the existing collapse pipeline,
fanning per-leaf edges to the round chip while preserving auxKey
identity for inspector dispatch.

#### Test: toy Feistel

Before any DES code lands, a 4-byte-block "toy Feistel" exercises the
primitive end-to-end. **F must be asymmetric** (NOT self-inverse) so
the combine model is genuinely tested — `F(R, K) = R XOR K` would
round-trip even with a buggy combine (since `x XOR x = 0`):

```ts
// 2-round toy: F(R, K) = (R + K) mod 256 per byte. State = 4 bytes (2-byte halves).
{
  kind: "feistel-round",
  id: "round.1",
  tracks: [
    { inputBytes: [0, 1], children: [] },                                 // L track (passthrough)
    { inputBytes: [2, 3], children: [                                     // R track (F-computation)
      { kind: "step", id: "round.1.add-K", type: "feistel.toy-add-k@1", params: {} }
    ]},
  ],
  combineKind: "feistel-standard",
}
```

KAT pinned against a manual hand-computation: encrypt under a chosen
key, get a specific 4-byte ciphertext, decrypt round-trips. The
asymmetric F means a swapped combine produces a DIFFERENT ciphertext,
caught by the KAT assertion. Tests also pin the trace structure
(frame count, branchPath stamps, rejoin synthetic frame).

### Phase 3 — DES step types — SHIPPED 2026-05-19

DES needs 7 new step types (the optional `des.toggle-parity-bits@1` was
skipped — explicit decision, not an oversight). **Correction to the
original draft**: bit-permutation helpers do NOT reuse
`src/steps/serpent-bit-ops.ts`'s `applyBitPermutation`. Serpent's helper
is hardcoded to 16-byte input AND uses LSB-first numbering; DES uses
MSB-first AND varies its buffer length across 4/6/8 bytes. The fix is
option (b) from the advisor's pre-Phase-3 review: a new
`src/steps/des-bit-ops.ts` mirrors the Phase-1 oracle's `bitOf` /
`permute` / bit-array helpers verbatim (MSB-first, size-agnostic),
keeping Serpent's hot path untouched and the bit-numbering convention
literal at the call site.

| Step type | What it does | Input shape | Output shape |
|---|---|---|---|
| `des.initial-permutation@1` | IP, 64 bits → 64 bits | `bytes` (8) | `bytes` (8) |
| `des.final-permutation@1` | FP = IP⁻¹ | `bytes` (8) | `bytes` (8) |
| `des.expand-R@1` | E, 32 → 48 bits | `bytes` (4) | `bytes` (6) |
| `des.xor-with-K@1` | XOR with `aux[K_i]` | `bytes` (6) | `bytes` (6) |
| `des.s-boxes@1` | 8 parallel 6→4 S-boxes | `bytes` (6) | `bytes` (4) |
| `des.p-permutation@1` | P, 32 bits → 32 bits | `bytes` (4) | `bytes` (4) |

**Note on `StepShapeContract` and byte-length**: today's
`StepShapeContract` declares `input: "bytes"` without specifying the
expected byte count. E-expand's `bytes(4) → bytes(6)` and S-boxes's
`bytes(6) → bytes(4)` are correct at runtime (each executor throws on
wrong-length input) but `validateShapes` won't catch a misordered DES
spec at edit-time. This plan **accepts runtime-only validation for
byte-length** as a deliberate trade-off: extending the contract to
carry length would touch every shipped step type's doc block (~30
entries), and the pre-Run error surface already catches mis-wires
when the user clicks Run. A future polish slice could extend the
contract; not blocking for DES.
| `des.key-schedule@1` | PC-1 + 16 shifts + PC-2, writes `roundKey.0..15` | n/a (aux-only) | passthrough |
| `des.toggle-parity-bits@1` | Optional pedagogy: strip 8 parity bits | `bytes` (8) | `bytes` (8) |

Each step ships with executor + doc + `shapeContract` + ParamEditor
block (per `src/steps/CLAUDE.md`) + narration registry entry + provenance
registry entry. The 8 S-boxes are constants from FIPS 46-3 Appendix A,
stored in `src/ciphers/des-constants.ts`.

The cipher spec wires the round body inside the `feistel-round`. Rounds
1..15 use `combineKind: "feistel-standard"`; round 16 uses
`combineKind: "feistel-no-swap"` (the textbook "no swap on final round"
exception, made visible in the spec tree rather than hidden in the
runtime):

```ts
// Round 1 (template for rounds 1..15):
{
  kind: "feistel-round",
  id: "round.1",
  tracks: [
    { inputBytes: [0,1,2,3], children: [] },             // L track (passthrough)
    { inputBytes: [4,5,6,7], children: [                  // R track (F-computation)
      { kind: "step", id: "round.1.expand-R",  type: "des.expand-R@1", params: {} },
      { kind: "step", id: "round.1.xor-K",     type: "des.xor-with-K@1", params: { roundKeyAux: "roundKey.0" } },
      { kind: "step", id: "round.1.s-boxes",   type: "des.s-boxes@1", params: { sboxes: DES_SBOXES } },
      { kind: "step", id: "round.1.p-permute", type: "des.p-permutation@1", params: { table: DES_P } },
    ]},
  ],
  combineKind: "feistel-standard",
}

// Round 16 (identical body, different combineKind):
{
  kind: "feistel-round",
  id: "round.16",
  tracks: [ /* ... same shape ... */ ],
  combineKind: "feistel-no-swap",
}
```

16 rounds wrapped in a `group` ("rounds") between IP and FP at the top
level. The final round's distinct `combineKind` is **visible in the
spec tree** — the user can click round 16 and see why DES decryption
works (the no-swap last round makes the cipher its own inverse under
key-reversal). Decrypt-spec consumes round keys in reverse order
(round 16's key first); the math otherwise is symmetric, no separate
`s-boxes-inverse` etc.

### Phase 4 — UI wiring + per-step Param/Narration/Provenance

Mechanical wiring following the Speck precedent
(`docs/plans/speck.md` §"UI / store integration"):

1. **`stores/cipher.ts`** — `Cipher` union grows to include `"des"`.
   `DEFAULT_KEY_BYTES_BY_CIPHER["des"] = 0x133457799bbcdff1` (FIPS
   Appendix B test vector). `DEFAULT_PT_BYTES_BY_CIPHER["des"] =
   0x0123456789abcdef`. Label: "DES".
2. **`stores/spec.ts`** — `defaults["des"] = { "single-block": { encrypt, decrypt } }`.
3. **`stores/cipher-mode.ts`** — `SUPPORTED_CIPHER_MODES_BY_CIPHER["des"] = ["single-block"]`.
4. **Padding selector** — disabled when `cipher() === "des"`, same
   pattern as Speck. The AES `load-block`/`store-block` overlay is
   16-byte-only, so the existing `isAesCipher` guard already catches
   DES correctly.
5. **App.tsx initial-state seeding** — `spec.inputs.plaintext.shape ===
   "bytes"` already lights up for DES (no AES overlay path).
6. **ParamEditor** — one new `Match` arm per step type. The 8-S-box
   block is the heaviest: collapsed `<details>` wrapping 8 sub-tables
   (each 64 entries arranged 4 × 16). Pattern copies Serpent's
   8-S-box block.
7. **Provenance + narration** — register one entry per DES step type
   plus one per `CombineKind` (rejoin synthetic frames are not leaves
   — see Layer 0). The 8 S-boxes get per-S-box narration units; the
   bit permutations reuse Serpent's bit-level narration pattern
   (`[[feedback-bit-level-narration-pattern]]`): one structural
   overview + N per-output-byte drill disclosures. The rejoin
   narrator includes a one-sentence callout for the cross-row
   provenance optic ("the swap is why this highlight crosses rows")
   so users don't misread the cross-track overlay as a bug.

### Phase 5 — Linear-mode UI components

Six new linear-panel components, each landing as its own commit so
the iterative-slice-review process gets clean checkpoints. All six
are independently testable against a DES trace fixture; the manual
smoke pass at the end of Phase 6 exercises them together.

#### 5a — `FeistelTrackContext.tsx` (track-context panel)

Renders only when `frame.branchPath` is set. Three sections:
**Round entry** (8 bytes split into L | R), **Right now** (current
track's evolving state highlighted; other track shown in muted style),
**Round output** (post-rejoin L' | R'). Round entry/exit are read
from the round's enclosing frames; current state is read from
`frame.stateAfter`. Bytes color-coded per track (subtle accent),
provenance overlay carries over from existing cell-overlay machinery.
~150 lines. Tests pin: panel renders only inside a branchPath,
round-entry computed correctly across all 16 DES rounds, color
coding stable when scrubbing across tracks.

#### 5b — `FeistelMiniDiagram.tsx` (mini textbook diagram)

A compact SVG (~180×220px) rendering the Feistel round's *abstract
algorithm* — split, F-stack, XOR, swap — with the current frame's
position highlighted. Live cross-reference: clicking any node in the
F-stack scrubs the trace to that leaf; the K_i label highlights in
sync with the round-key panel's ribbon.

The pedagogical headline: graph view shows spec topology; this
diagram shows the abstract Feistel structure. Side-by-side they
teach different lessons.

Cipher-agnostic — driven by the active `feistel-round`'s `tracks` +
`combineKind` rather than hardcoded DES geometry. TEA/XTEA/Twofish
get the same component without modification (combine kind label
changes, F-stack shape adapts to the track's children count).

~250 lines (SVG layout + click routing + state-driven highlight).
Tests pin: SVG renders for any `feistel-round` spec, click on a
diagram node updates the scrubber, K_i highlight syncs with the
round-key panel.

#### 5c — `RejoinFrameView.tsx` (4-arg combine display)

Replaces `<FrameStateView />` when the scrubber lands on a rejoin
synthetic frame. Shows the combine kind name + formula at the top,
4 snapshot rows in **formula order** (per `CombineKind.inspectorRowOrder`
— see Layer 0), result at the bottom. Cross-cell provenance:
hovering a byte in `new_R` lights up its source bytes in `L_in`
AND `R_out` (the XOR pair).

`L_out` shows even when the combine doesn't consume it (e.g.,
`feistel-standard`) — pedagogy: "the L track ran its body; the
output is available but this combine doesn't use it."

~120 lines. Tests pin: row order matches `inspectorRowOrder`,
provenance overlay highlights correct source cells per combine
kind, "unused" L_out rendered in muted style.

#### 5d — `RoundKeyPanel` DES 48-bit extension

Today's panel reads `prefix.N` aux entries and renders Uint8Array
ribbons. DES round keys are 48 bits (6 bytes) — not byte-aligned
relative to AES's 128-bit blocks.

Hybrid display: default to 6 hex bytes per ribbon (matches existing
rhythm); per-ribbon expand-bits affordance unfolds the bit-level
structure showing the 48 bits in 8 groups of 6 (the S-box input
grouping). When unfolded, hovering an S-box output cell in the
current frame lights up its 6 input bits in the K_i ribbon.

~80 lines (extends `RoundKeyPanel.tsx`; new sub-component
`BitGroupedRibbon.tsx` for the unfold view). Tests pin: ribbon
default shows 6 hex bytes per round key, unfold renders 48 bits
in 6-bit groups, hover sync with S-box provenance.

#### 5e — `DesKeyScheduleSimulator` (key-schedule explorer)

Replaces `<FrameStateView />` for `des.key-schedule@1` frames. Per-
round table:

| Round | Cumulative shifts | C_i (28 bits) | D_i (28 bits) | K_i = PC-2(C_i ‖ D_i) (48 bits) |

Each row clickable → scrubs to that round's first body frame. Same
pattern as AES's `KeyScheduleExplorer` (RotWord→SubWord→Rcon→XOR
chain), adapted to DES's PC-1 → 16 shifts → PC-2 chain.

~200 lines (in `src/ui/key-schedule-sim/des.ts`; the explorer
component itself ~120 lines of those). Tests: per-round simulator
output equals the executor's `aux[roundKey.N]` values byte-for-byte
(parity test analogous to AES's), all 16 rounds enumerated.

#### 5f — Track membership badge in scrubber timeline

Subtle per-frame markers in the existing scrubber timeline indicating
track membership: tiny `L`/`R` chips above standard markers for
in-track frames, `⇄` for rejoin synthetic frames, plain marker for
root-scope frames (IP, FP, key-schedule). Lets users scan ahead/back
without reading frame headers.

~50 lines (extends the scrubber timeline component; CSS for the
chips). Tests pin: chip rendered iff `branchPath` is set, `⇄` chip
appears for rejoin frames, no chip for root-scope frames.

### Phase 6 — Graph view branched layout + smoke

> **Entry gate (added 2026-05-20, user-confirmed; fully closed same
> day):** Both prerequisites for starting Phase 6 are resolved:
>
> 1. **CLOSED 2026-05-20**: Manual browser smoke pass on Phase 5 in
>    DES confirmed by user. Covered: scrub onto a round body; click
>    leaves in `<FeistelMiniDiagram />` (including verifying the K_i
>    subscript labels render and line up next to xor-K); click rows
>    in `<DesKeyScheduleExplorer />`; hover the scrubber strip while
>    clicking through; hover an `after` cell in the active step's
>    view to confirm `<FeistelTrackContext />` lights up the
>    corresponding R_in cell (and stays clean on later track steps
>    per the intentionally narrow first-step-of-track gate); click
>    the new sidebar `⇄ rejoin` entries; verify R-track auto-expand
>    on round expand. Per `[[feedback-jsdom-pointer-events-gap]]` the
>    SVG `<g>` clicks and `pointer-events: none` strip were
>    jsdom-only-tested — the smoke was the discriminating check.
> 2. **CLOSED 2026-05-20**: The two deferred 5a/5b polish items
>    (cell-level provenance overlay on FeistelTrackContext; K_i ↔
>    xor-K cross-reference in FeistelMiniDiagram) landed in the
>    "Phase 5 deferred polish items" commit referenced above. 7 new
>    tests pin both behaviors (5 in `feistel-track-context.test.tsx`,
>    2 in `feistel-mini-diagram.test.tsx`). The follow-up StepList
>    sidebar UX commit added a clickable rejoin row + R-track
>    default-expand (4 more tests).
>
> Both are pre-conditions because Phase 6 will rely on parts of the
> Phase 5 surface (linear-mode scrubber → graph leaf click coupling,
> provenance hover plumbing across views) that need to be confirmed
> working in a real browser first. Per
> `[[feedback-iterative-slice-review]]`, re-consult advisor before
> starting Phase 6 with the current state of the codebase + Phase 6
> design in hand.

Render-time work for the `feistel-round` container on the graph
canvas. Builds on the existing `iterate` rendering machinery —
branches are "iterate-like" in that they're a structural container
with internal spine — but renders two parallel tracks stacked
vertically instead of N sequential block chips.

#### Layout decisions (user-approved 2026-05-19)

- **Track orientation**: tracks stacked vertically inside the round
  container, each track flowing left-to-right. L on top, R on bottom.
  Container height ≈ 2× row height + padding; width = max(track widths).
  Rationale: matches canvas's global left-to-right flow; textbook
  diagram's top-to-bottom flow rotates 90° clockwise to top-vs-bottom
  rows. Same semantics, different coordinates.
- **Rejoin chip**: dedicated chip at the container's right edge,
  spanning the full height of both track rows. Both tracks end with
  arrows feeding into the chip; one arrow exits to the next spec
  node. Glyph indicates combine kind (`⇄` swap, `→` no-swap,
  `+L`/`+R` for add-into variants). The chip's label is the combine
  kind name; the formula renders only in the inspector (Layer 5
  detail). Port-spread machinery (`buildConsumerPortAssignment`'s
  `sideOf` callback from `[[project-crooked-round-arrow-q1]]`) handles
  the two-arrows-into-one-chip case via distinct `targetYOffset`
  values per source track.
- **Collapse**: single round-labeled chip ("Round 3"), matching how
  groups would collapse. Chevron toggles. The two-row-pill option
  (showing L/R summaries when collapsed) is deferred — would need
  per-cipher F-summary functions and adds a new collapsed-shape
  vocabulary. Revisit if Phase 6 smoke shows users want at-a-glance
  detail when collapsed.
- **Drop semantics**: per-track gutters (standard Slice 5 set:
  at-start, between-leaves, at-end) inside each track row. Container
  header stays click-to-collapse (NOT a drop target — there's no
  unambiguous default track for round-level drops). Inter-track gap
  is inert. Rejoin chip is inert as a drop target (consistent with
  synthetic endpoint pills per Slice 1). When a draggable hovers the
  container border or inter-track gap, show NO highlight — the
  absence of feedback communicates "drop into a track row, not into
  the round itself."

#### Smoke pass

Manual browser pass on:
- Forward DES with FIPS Appendix B vector — visual check L/R tracks,
  F-internals visible on R, rejoin and swap render correctly.
- Backward DES (decrypt) with same key — round keys consumed in
  reverse.
- Save → reset → Load with a `feistel-round` in the spec.
- URL share round-trip.
- Param edit on an S-box cell — trace re-runs, narration updates.
- Drop a new step into a `feistel-round` track via the palette
  (regression check: drop-anchor + drop-gutter logic handles the
  new container kind).
- Collapse round 3 — verify edges still render correctly
  (`collapseFeistelRoundEdges` from Phase 2 working end-to-end).
- Scrub through the trace — verify track context panel, mini
  diagram highlight sync, rejoin view, key-schedule explorer, and
  timeline badges all render and update together.

### Tests

- **`tests/des-vectors.test.ts`** — FIPS 46-3 Appendix B KAT
  (`PT=0123456789abcdef, K=133457799bbcdff1 → CT=85e813540f0ab405`),
  plus 2–3 NIST CAVS vectors. Frame count + structure assertions.
- **`tests/des-decrypt.test.ts`** — inverse KAT + round-trip on
  random 8-byte inputs.
- **`tests/feistel-primitive.test.ts`** — toy Feistel from Phase 2.
  Pins primitive semantics independent of DES.
- **`tests/feistel-graph.test.ts`** — graph-derivation assertions for
  the new container kind: state-spine rules, track-bounded edges,
  rejoin synthetic node placement.
- **`tests/des-roundtrip-document.test.ts`** — save→load on a spec
  containing `feistel-round` nodes. **Schema migration (revised at
  Phase 2 review, 2026-05-19)**: original plan bumped
  `CipherDocument.schemaVersion` 1 → 2 in Phase 2. Per advisor +
  user, the bump is **deferred to Phase 3** instead — Phase 2's
  `feistel-round` node kind exists only in the toy spec (not in the
  cipher selector), so AES docs saved during Phases 2–3 stay byte-
  identical to v0.5.0 and remain readable by v0.5.0 builds. Phase 2
  added `FeistelRoundGroupSchema` to the document-schema discriminated
  union without changing `CURRENT_SCHEMA_VERSION`; the toy spec round-
  trips through that path in `tests/document-roundtrip.test.ts`.
  Phase 3 will bump to schema 2 when DES enters the cipher selector
  and users can actually save a feistel-round-bearing doc.
- **`tests/state-shape-contracts.test.ts`** — extend the existing
  walker to descend into all of `feistel-round.tracks[*].children`.
  Coverage gate stays at 100%.
- **`tests/narration-registry-contract.test.ts`**, **`tests/provenance-registry-contract.test.ts`** — same extension; additionally register entries for each `CombineKind` (rejoin frames are not leaves but need narration + provenance).
- **`tests/frame-preservation-feistel.test.ts`** — pins that the
  `:t{name}` track suffix threads through `setTrace`'s stepId-matching
  the same way `:b{i}` does. Required by `[[feedback-frame-preservation]]`.
- **`tests/des-key-schedule-parity.test.ts`** — `DesKeyScheduleSimulator`
  output (per-round C_i / D_i / K_i) equals executor's
  `aux[roundKey.N]` byte-for-byte for all 16 rounds.
- **Linear-mode component tests** — one per Phase 5 component:
  `feistel-track-context.test.tsx`, `feistel-mini-diagram.test.tsx`,
  `rejoin-frame-view.test.tsx`, `round-key-panel-des.test.tsx`,
  `des-key-schedule-explorer.test.tsx`, `scrubber-timeline-badges.test.tsx`.
- **Branch-aware tests for existing graph features**: replication,
  arrow bundling, source-color coding, draggable replicas. Run as a
  regression check; expect 0–2 follow-up patches.

### Commit shape

Six commits, one per phase, plus six sub-commits inside Phase 5 (one
per linear-mode component). The iterative-slice-review process means
each commit gets an advisor pass against the current state of the
codebase BEFORE the next phase's work starts.

1. **Phase 1**: verification oracle script + initial KAT pinning (no
   shipped code). ~300 lines (oracle script + KAT capture).
2. **Phase 2**: branching primitive + toy Feistel + Layer 0 data
   model + frame-preservation test (no DES). ~1200–1500 lines.
3. **Phase 3**: DES step types + spec + KAT/roundtrip tests.
   ~1500 lines.
4. **Phase 4**: cipher selector wiring + ParamEditor blocks +
   narration/provenance for DES step types + combine-kind narrators.
   ~700 lines.
5. **Phase 5**: six sub-commits, one per linear-mode component
   (5a–5f). ~850 lines total.
6. **Phase 6**: graph view branched layout + comprehensive manual
   smoke. ~700 lines + smoke notes.

Each commit is independently shippable (passes `npm run check`). The
primitive in Phase 2 ships with the toy spec ONLY — registered in
`default-registry.ts` so the test reaches it, but not in the cipher
selector, so users can't drive it through the UI until Phase 4.

## Critical files

**New:**

- `src/steps/des-initial-permutation.ts` (+ `des-final-permutation.ts`)
- `src/steps/des-expand-r.ts`
- `src/steps/des-xor-with-k.ts`
- `src/steps/des-s-boxes.ts`
- `src/steps/des-p-permutation.ts`
- `src/steps/des-key-schedule.ts`
- `src/ciphers/des-constants.ts` (IP, FP, E, P, 8 S-boxes, PC-1, PC-2, shift schedule)
- `src/ciphers/des.ts` + `src/ciphers/des-decrypt.ts`
- `src/ui/components/FeistelTrackView.tsx` (graph view; in-container layout)
- `src/ui/components/FeistelTrackContext.tsx` (Phase 5a — linear panel)
- `src/ui/components/FeistelMiniDiagram.tsx` (Phase 5b — SVG abstract diagram)
- `src/ui/components/RejoinFrameView.tsx` (Phase 5c — 4-arg combine view)
- `src/ui/components/BitGroupedRibbon.tsx` (Phase 5d — DES bit-level ribbon)
- `src/ui/components/DesKeyScheduleExplorer.tsx` (Phase 5e)
- `src/ui/key-schedule-sim/des.ts` (Phase 5e — per-round simulator)
- `src/ui/narration/des.ts`
- `src/ui/narration/combine-kinds.ts` (rejoin narrators keyed by `CombineKind`)
- `src/ui/provenance/des.ts`
- `src/ui/provenance/combine-kinds.ts` (rejoin provenance keyed by `CombineKind`)
- `tests/des-vectors.test.ts`, `tests/des-decrypt.test.ts`,
  `tests/feistel-primitive.test.ts`, `tests/feistel-graph.test.ts`,
  `tests/des-roundtrip-document.test.ts`,
  `tests/frame-preservation-feistel.test.ts`,
  `tests/des-key-schedule-parity.test.ts`,
  `tests/feistel-track-context.test.tsx`,
  `tests/feistel-mini-diagram.test.tsx`,
  `tests/rejoin-frame-view.test.tsx`,
  `tests/round-key-panel-des.test.tsx`,
  `tests/des-key-schedule-explorer.test.tsx`,
  `tests/scrubber-timeline-badges.test.tsx`
- `scripts/verify-des.mjs` (oracle, not shipped)

**Modified (core architecture):**

- `src/core/types.ts` — `BranchTrack`, `FeistelRoundGroup`, `StepNode`
  union widened, `TraceFrame.branchPath`.
- `src/core/runtime.ts` — `feistel-round` walk.
- `src/core/graph.ts` — `ContainerNode.kind` widened to include
  `"feistel"`; `inferStateEdges` track-bounded rules; rejoin/split
  synthetic nodes.
- `src/core/document.ts` — schema-version bump, migration for older
  documents (no-op on existing schema 1 docs since they have no
  `feistel-round` nodes).
- `src/core/spec-mutations.ts` — recursive walks into track children.
- `src/core/spec-shapes.ts` — `validateShapes` walks branches; tracks
  declare their own shape contracts.

**Modified (UI wiring):**

- `src/ciphers/default-registry.ts` — register DES step types + toy
  Feistel.
- `src/ui/stores/cipher.ts` — `Cipher` union, label, defaults.
- `src/ui/stores/spec.ts` — `defaults["des"]`.
- `src/ui/stores/cipher-mode.ts` — `SUPPORTED_CIPHER_MODES_BY_CIPHER["des"]`.
- `src/ui/App.tsx` — minor: padding-disabled for DES (same `isAesCipher` guard).
- `src/ui/components/ParamEditor.tsx` — 7 new `Match` arms.
- `src/ui/components/GraphView.tsx` — `feistel-round` container layout
  (Phase 6 layout decisions: top/bottom tracks, dedicated right-edge
  rejoin chip, single-chip collapse, per-track gutters).
- `src/ui/components/LinearView.tsx` — branchPath-aware frame headers
  (path segment + track badge per Layer 6 of the UI architecture).
- `src/ui/components/RoundKeyPanel.tsx` — extended for DES 48-bit
  round keys (Phase 5d).
- `src/ui/components/Scrubber.tsx` (or wherever the timeline lives)
  — adds per-frame track membership chips (Phase 5f).
- `src/core/edge-value-lookup.ts` — new `CombineEdgeLookup` variant
  exposing all 4 snapshots in formula order (Layer 5 of UI arch).
- `src/ui/narration/registry.ts`, `src/ui/provenance/registry.ts` —
  walk into track children.
- `tests/state-shape-contracts.test.ts`,
  `tests/narration-registry-contract.test.ts`,
  `tests/provenance-registry-contract.test.ts` — track-aware walks.

## Out of scope

- **3DES**. Mechanical follow-up: same step types, three DES applications
  in sequence with different keys, two spec leaves wrapping the round
  group.
- **TEA / XTEA**. Cheap follow-up — same branching primitive, simpler F
  (one leaf, ARX expression).
- **DES ECB / CBC**. Multi-block modes for DES need block-size-aware
  `load-block`/`store-block` (currently 16-byte-only for AES). Separate
  plan once the modes story generalizes past AES.
- **Twofish**. 4-way Feistel — `BranchTrack` design already supports
  n-tracks but Twofish also needs key-dependent S-boxes (a separate
  architectural concern).
- **Blowfish**. Self-referential key schedule + key-dependent S-boxes,
  both orthogonal to the branching question.
- **Codegen target**. Architecture supports it eventually; not this plan.

## Pitfalls flagged for this work

- **Bit-numbering convention**: FIPS 46-3 uses 1-indexed bit numbering
  with bit 1 = MSB. JavaScript bitwise ops use 0-indexed LSB. The
  conversion is `bit_i (FIPS) = bit_(64 - i) (JS)` for a 64-bit value.
  Off-by-one here will pass the *first* IP test (output ≠ input) but
  fail the round-trip. Pin against the oracle EARLY.
- **DES key parity bits**: every 8th bit of the 64-bit key is a parity
  bit, ignored by the cipher. `des.key-schedule@1`'s PC-1 step drops
  them, so a user-typed key with arbitrary parity bits will produce the
  same trace as the parity-corrected version. Surface this in the
  step's narration so users don't see "I changed bit 7 of the key and
  nothing happened" as a bug.
- **Track state-shape changes**: E-expand turns 32 bits into 48; S-boxes
  collapse 48 back to 32. The state-shape walker MUST tolerate per-leaf
  shape changes within a track. The existing executor contract already
  allows this, but the new `validateShapes` walker needs to thread
  shape across track-internal leaves (NOT short-circuit at the track
  boundary).
- **Last-round combine kind**: forward DES swaps after every round
  EXCEPT the last (so L_16 || R_16 enters FP, not R_16 || L_16).
  Decrypt has the same exception. In this plan that's not a runtime
  special-case but a spec-visible distinction: rounds 1..15 use
  `combineKind: "feistel-standard"` and round 16 uses
  `combineKind: "feistel-no-swap"`. The "DES is symmetric under
  key-reversal" property is what makes a single executor work for both
  directions; it breaks if every round uses the same combine kind
  unconditionally.
- **Rejoin frame's `stepId`**: synthesized at runtime, NOT a user-
  authored leaf. It needs a deterministic id (`{roundId}:rejoin`)
  for trace stability across re-runs (`[[feedback-frame-preservation]]`).
  Same applies to the post-swap frame (`{roundId}:swap`).
- **Cross-mode mirror buttons**: DES has no class-1 or class-2
  cross-mode mirror surfaces. The 8 S-boxes have no "inverse" sibling
  that would benefit from a "Sync inverse S_i to decrypt" button — DES
  is symmetric under key-reversal, so encrypt and decrypt share the
  same S-boxes verbatim. `cross-mode-mirror-registry.ts` gets ZERO new
  entries. The `tests/cross-mode-mirror-coverage.test.tsx` walker
  doesn't need updating. Stated explicitly so a future session
  doesn't assume a missing surface.
- **`feistel-round` inside `iterate`**: ECB(DES) would nest a
  `feistel-round` inside an `iterate`. The branchPath + blockIndex
  combination on a frame stamps both — make sure the trace store
  scrubber preserves stepId correctly across re-runs with both
  suffixes. See `[[feedback-frame-preservation]]`.
- **Graph state-spine through `feistel-round`**: today's
  `inferStateEdges` has an iterate-boundary suppression rule
  (`[[feedback-state-spine-no-phantoms]]`). The new container kind
  needs an analogous boundary rule — state into the round flows to
  the split anchor, state out flows from the rejoin synthetic. Don't
  let DFS-consecutive-leaves leak across the branch.
- **Universal cipher-shape plan integration**: this plan's
  `BranchTrack` and `FeistelRoundGroup` are the lessons the
  `[[project-universal-cipher-shape-plan]]` was queued to absorb.
  After Phase 5 ships, revisit that plan's hybrid-type-alias-vs-union
  decision with the real data model in hand.

## Phase 6 session log (2026-05-20)

Phase 6 entered with a fresh advisor pass per the iterative-slice-review
pattern. Four substantive points surfaced, two became user picks
(full per-track structural editing for 6d; experiment-then-decide on
`collapseFeistelRoundEdges`). Sub-slices shipped in this order:

1. **6a** (`513e97e`) → superseded same day. Original L-row-top +
   R-row-bottom layout (90° CW rotation from textbook). Browser
   smoke revealed empty L row read as wasted space, not as a
   passthrough track.
2. **6c** (`4a1b8f7`). Experiment proved generic `collapseGraph`
   already handles feistel-round collapse correctly; the planned
   `collapseFeistelRoundEdges` transform was vestigial.
3. **6a-revision** (`12b88e0`). Pivoted to side-by-side L/R columns
   (user pick: textbook convention — L on left, R on right). Chips
   stack vertically within each column.
4. **6a-revision-fix** (`3dea9d5`). Regression from the pivot:
   track-only iteration skipped replica synthetic ids. Right-gutter
   placement (user pick over left-gutter / above-consumer / etc.).
   15/16 replicas visible.
5. **Spine-replica splice fix** (`d58202e`, NOT in original plan).
   Pre-existing bug surfaced by DES — `source.parent ≠
   spineSuccessor.parent` case the existing graph.ts:1786 comment
   had flagged. One-line fix: spine-replica anchors on `edge.from`
   (source's id) instead of `edge.to` (consumer's id).
   Byte-equivalent for AES/Speck/Serpent; 16/16 DES replicas now visible.
6. **Output-anchor descent fix** (`573fb50`, NOT in original plan).
   User-flagged AES inconsistency: spine ended at `round-10`
   container instead of `round.10.add-round-key`. Universal fix:
   `endpointAnchors` memo recurses into terminal container to
   find innermost last state-consumer. Iterate returns container
   id (boundary); feistel-round returns rejoin synthetic; group
   transparent. AES fixed; DES/Speck/AES-ECB unchanged.

**Issue A noted, accepted for now** (2026-05-20): DES's 16-round
vertical stack extends beyond visible canvas (~3.2K tall). Revisit
when a many-round cipher like TEA (64 rounds) ships and the scroll
becomes a real pain point.

**Remaining work (future session):**

- **Phase 6b** — three sub-commits. User pick (2026-05-20):
  id-bearing L passthrough chip (graph.ts emits `predecessor →
  passthrough → rejoin` instead of today's `predecessor → rejoin`
  shortcut) over pure-visual Slice-1-style synthetic. Rationale:
  Phase 6d's per-track drop gutters get a natural anchor; the
  passthrough chip becomes hoverable/clickable for provenance like
  any other leaf; semantically honest (L track IS a real algorithmic
  step). Cost: graph.ts changes + `inferStateEdges` awareness +
  `container.childIds` invariant audit + narration/provenance
  registry rows + frame-preservation check + graph-derivation test
  updates.
  - **6b-i SHIPPED** (commit `9d88c49`) — rejoin chip layout box +
    `RejoinChip` render component + direction-aware placement
    (bottom edge for vertical-flow parent / right edge for future
    iterate-contained Feistel, probed via `containersById.get(
    parentId)?.kind === "iterate"`). Closes the DES spine gap
    (`round.16.p-permute → final-permutation` arrow now lands on
    a real chip). 2 new tests in `graph-view-des-feistel.test.tsx`
    (chip renders per round + sits below R-track tail for
    vertical-flow); existing "rejoin does NOT render" assertion
    flipped to "rejoin renders". 1524 tests total, all pass; bundle
    509.3 → 511.1 KB.
  - **6b-ii SHIPPED** (this commit) — id-bearing L passthrough
    chip. Five-piece change:
    1. `core/graph.ts` — `synthetic` discriminator widened to
       `"rejoin" | "passthrough"`; new `feistelPassthroughId(roundId,
       trackIdx)` helper exported so `walkSpec` (materializer) and
       `processFeistelRound` (edge-routing) agree on spelling;
       `walkSpec`'s feistel branch synthesizes a passthrough node
       per empty track + appends it to `feistelTracks[trackIdx]`;
       `processFeistelRound` replaces the `predecessor → rejoin`
       shortcut with the 3-leg chain `predecessor → passthrough →
       rejoin` (the passthrough → rejoin half is invariant; the
       predecessor → passthrough half is conditional on a present
       non-boundary predecessor — same gate as the non-empty-track
       fan-in).
    2. `GraphView.tsx` — new `PassthroughChip` component (modeled on
       `RejoinChip`): no `data-drop-anchor`, no DeleteGlyph, no
       drag, no warnings. Label `"{trackName} passthrough"` via
       `feistelTrackNames[trackIdx]` lookup (e.g. "L passthrough"
       for DES); falls back to `"track N passthrough"` for unnamed.
       Click scrubs to the round's `:rejoin` frame (nearest semantic
       anchor — the passthrough has no frame, no information to
       carry × 16 frames/run) + toggles inspector selection on the
       passthrough id.
    3. `GraphView.tsx` render For loop dispatches on
       `node.synthetic === "passthrough"` before the rejoin branch.
       trackIdx reverse-parsed from id via `/:passthrough-(\d+)$/`.
    4. Tests — `des-graph.test.ts` flipped `feistelTracks[0] === []`
       to `[{roundId}:passthrough-0]` + new test asserting the
       passthrough node exists with correct containerPath +
       synthetic marker; `feistel-graph.test.ts` toy spec updated
       analogously, plus the empty-L-track edge test flipped from
       "predecessor → rejoin direct" to "predecessor →
       passthrough-0 → rejoin chain" + a `has("pre", "round.1:rejoin")
       === false` assertion pinning the shortcut is gone; 2 new
       render tests in `graph-view-des-feistel.test.tsx` (per-round
       chip presence + label text).
    5. Audits done before edits: only ONE `synthetic === "rejoin"`
       check existed (the one I added in 6b-i); other
       `container.childIds` walkers in GraphView are gated on
       `consumerContainer?.kind === "iterate"` so the feistel branch
       doesn't reach them; `canonicalStepId`'s SUFFIX_PATTERN is
       untouched (no frames for passthrough → no canonicalization
       call site). Total: 1527 tests, bundle 511.1 → 513.0 KB.
  - **6b-ii deferred:** vertical centering of the passthrough chip
    in the L column (today top-aligned, which falls out of the
    track loop). If browser smoke says it looks asymmetric vs the
    body-bearing R column, add a layout pass that centers the
    passthrough on R's midpoint. Not in 6b-ii's scope.
  - **6b-iii SHIPPED** (this commit) — diagonal X-crossings
    between Feistel rounds, encoding the swap semantic visually.
    Implementation is renderer-only — graph.ts already emits the
    two `roundN:rejoin → roundN+1:*` edges (L target =
    `roundN+1:passthrough-0` after 6b-ii; R target =
    `roundN+1.expand-R`). The renderer adds a source-x shift so
    the two arrows EXIT the rejoin chip from opposite sides:
    L-target arrow exits the rejoin's RIGHT side (encoding
    `L_{n+1} = R_n`); R-target arrow exits its LEFT side
    (encoding `R_{n+1} = L_n ⊕ F`). Visually the two arrows form
    an X between rounds.
    - New pure helper `rejoinSwapSourceXSign(edge, nodesById,
      containersById) → -1 | 0 | 1` in GraphView.tsx. Returns
      `+1` for L-target-from-rejoin under `feistel-standard`
      (push source-x right), `-1` for R-target same kind (push
      left), `0` otherwise (non-rejoin source, non-swap kind,
      target outside a feistel-round, not 2-track).
    - Composed into `renderBundle`'s `sourceXOffset` memo additive
      with `replicaSourceXOffset`: `swapShift = sign × fromBox.w
      × 0.25` (quarter-chip-width, well inside EdgePath's clamp
      so the start point stays in the box). A rejoin is never a
      replica in practice so the two contributions don't compete.
    - `feistel-no-swap` (DES round 16) returns 0 — natural
      parallel arrows ARE the visual encoding of no-swap.
      `feistel-add-into-{left,right}` also return 0 (no shipped
      cipher uses them; their pedagogical visual is less
      standardised — branch when a future cipher demands it).
    - 6 new unit tests in `tests/rejoin-swap-source-x.test.tsx`
      (pure helper, hand-rolled `nodesById`/`containersById`
      fixtures, no GraphView render). Covers: standard L+R, no-swap
      both directions, non-rejoin source, target outside feistel-round
      (e.g. `round.16:rejoin → final-permutation`), add-into-left.
      Test file is `.tsx` + `@vitest-environment jsdom` because
      importing from `GraphView.tsx` pulls in Solid's
      `delegateEvents` which touches `window`.
    - Geometric assertion in `graph-view-des-feistel.test.tsx` (the
      DOM-side smoke check that the SVG path's `M sx,sy` actually
      lands on the expected side) intentionally deferred — the
      EdgePath path-string format is brittle to regenerate; the
      jsdom value is the BUILD result, not the visual that
      reaches the user. Manual browser smoke at Phase 6e is the
      discriminating check.
    - Total: 1533 tests, bundle 513.0 → 513.6 KB.
- **Phase 6d SHIPPED** — per-track drop gutters across seven commits.
  Plan file at `~/.claude/plans/swirling-meandering-barto.md` (the
  6d-specific plan; this file is the umbrella plan). Sub-commits:
  - **6d-i** (`474fc71`) — `transformParentArray` walker descends
    into a feistel-round's tracks. `insertStepAfter` / `Before` /
    `removeStep` / `reorderStep` now work on track-resident step
    ids without new exports. Reference-equality discipline pinned
    by test (`tracks.map(t => i === idx ? { ...t, children: new
    } : t)` — untouched tracks keep their refs so the spec
    store's debounced effect doesn't re-run trace on every track
    edit). 1533 → 1544 tests.
  - **6d-ii** (`6ae23ef`) — `StepLocation` widens its `parent`
    union to `StepGroup | IterateGroup | FeistelRoundGroup | null`
    + optional `trackIdx?: number`. `findStepAndParent` descends
    per-track and reports `{ parent: roundNode, trackIdx,
    indexInParent }` for track-resident matches. Callsite audit
    (3 production): `isRoundDuplicatable` + `duplicateRoundGroup`
    bail with defensive throws on the impossible-today feistel-
    parent case; `FeistelMiniDiagram::lookupRoundForFrame`
    unaffected (reads loc.node only). 5 new tests; 1544 → 1549.
  - **6d-iii** (`14183cb`) — new `prependChildToTrack(spec,
    roundId, trackIdx, newStep) → spec` primitive. Sibling to
    `prependChildToContainer`; parameterized by `trackIdx`
    because a feistel-round has no unambiguous default body.
    `prependChildToContainer`'s feistel branch now throws with a
    pointer to the new primitive (was: "resolves to a leaf"). 10
    new tests; 1549 → 1559.
  - **6d-iv** (`6f5714c`) — new `into-track-start` anchor variant
    in `insertStepIntoSpec`. Routes to `prependChildToTrack` with
    the same try/catch fallback the `into-start` branch uses for
    unexpected throws. 5 new store-level tests; 1559 → 1564.
  - **6d-v** (`7019b99`) — `dropGutters` memo emits per-track
    gutters: empty L track gets ONE sentinel encoded
    `into-track-start:roundId#trackIdx` (`#` separator avoids
    ambiguating the existing `:`-prefix split); populated R track
    gets standard before/between/after horizontal strips using
    real chip ids. Synthetic ids (passthrough, rejoin) and
    replicas filtered out of the gutter walk. `handleDrop` parses
    the new prefix. Horizontal-flow parent (Feistel-inside-
    iterate, no shipped cipher) documented but deferred. 6 new
    tests; 1564 → 1570.
  - **6d-vi** (test-only) — DES round-trip test extending
    `tests/built-from-palette-roundtrip.test.tsx`: switch cipher
    selector to DES, palette-author into round.5's L track,
    edit params, pin layout, Save with include-session, reset,
    Load, verify track membership + params + layout pin all
    survive AND DES ciphertext stays byte-equal to baseline.
  - **6d-vii inter-track-gap dispatch fix** (advisor-flagged blind
    spot in self-checks). The plan promised "drop on inter-track
    gap → insert AFTER round in parent" (user-picked). Actual
    behavior pre-fix: chain hit `prependChildToContainer` →
    throws on feistel (6d-iii's improved error) → store fallback
    root-appended the leaf. `handleDrop` now special-cases
    `anchorContainer.kind === "feistel"` to route to
    `{kind: "after", stepId: roundId}` directly. Test
    `inter-track-gap drop` pins the "leaf lands in `rounds` group
    at indexInParent === roundN" semantic so a future refactor
    can't silently regress it.
- **Phase 6e** — comprehensive manual browser smoke pass.
  Pre-conditions: 6a-vi roundtrip test passes (✓), inter-track
  gap regression test passes (✓), all sub-commits on `main`.

**Bundle:** 504 KB → 513.6 KB over the session. Soft Vite warning
non-blocking; lazy-loading the Feistel components is the obvious
response if it gets worse.
