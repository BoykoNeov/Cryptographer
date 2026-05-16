# Cross-mode mirror operations + click feedback

Establish a coherent architectural pattern: every meaningful step whose
encrypt-side param has a different-but-related decrypt-side value gets an
**explicit, user-triggered "mirror" button** below its param editor.
Encrypt and decrypt are *never* auto-synced — that would hide the
algorithmic relationship between the two sides and defeat the
pedagogical goal. Instead, the user observes the asymmetry through the
button: it names the operation ("Sync inverse to decrypt", "Copy S-box
to decrypt") and the user can choose to invoke it, decline, or undo it.

This plan rolls out the remaining mirror buttons (key-expansion S-box
copy, MixColumns inverse, Serpent S-box trio) and introduces a shared
**click-feedback primitive** so every action button — old and new —
gives the user a visible signal that the click registered.

## Status

**Planned 2026-05-16.** Slices 1 + 2 shipped 2026-05-16
(commits `4fb1b6f`, `d35bd96`). Slices 3 + 4 shipped 2026-05-16
(commit `c50a05f`). Slice 5 shipped 2026-05-16 — GF(2^8) 4×4
Gauss-Jordan inverter (`src/core/state/gf-matrix.ts`) + Sync inverse
MixColumns button + 18 tests across the inverter, the store mutator,
and the UI row. **All five slices now on `main`.**

The architectural foundation already exists from prior work:

- `syncSboxInverseToCounterpart` (commit `d5c0949`) and the `SyncInverseRow`
  component wired into `SbxBlock` proved the pattern.
- Pure helpers (`invertSbox`, `repairToPermutation`, `findDuplicateIndices`,
  `countRedundantDuplicates`) are size-parameterized — they work at N=16
  (Serpent) and N=256 (AES) without modification.
- The two-spec store (`specs: { encrypt, decrypt }`) and the
  `updateAllStepsByType` mutator route already support cross-slot
  writes; new buttons only need a new helper that calls it.

## Context

**The four parameter mirror classes** (from prior architectural review):

| Class | Example | Cross-mode operation |
|---|---|---|
| 1. Identity-mirrored | Round count, key | Same value both sides (`copy`) |
| 2. Inverse-mirrored | S-box, MixColumns matrix | Algebraic inverse (`invert`) |
| 3. Structural-mirrored | Round order | Reverse order (handled by `duplicateRoundInSpec`) |
| 4. Not-mirrored | Future debug params | No relationship |

The architecture this plan establishes:

> **Every step whose `(stepType, paramKey)` falls in class 1 or 2 ships
> with a Sync button below its editor. The button is opt-in, never
> automatic. The button's label names the operation specifically
> ("Copy …", "Sync inverse …") so the user reads the algorithmic
> relationship even before clicking.**

A **registry-driven enumeration test** enforces this so new step types
can't silently ship without a mirror button.

**Why now:** The S-box Repair + Sync-inverse work (commits `89c7d17`,
`d5c0949`) demonstrated the pattern works for one stepType. Extending
it to the remaining meaningful steps closes the asymmetry footgun and
makes the principle visible across the whole UI, not just one panel.
The click-feedback primitive lifts a cross-cutting UX gap that
otherwise leaves every action button feeling unresponsive — values
change behind the scenes (decrypt slot, after duplicate-round, after
Sync) and users can't tell their click did anything.

## Advisor consultation

This plan was reviewed by advisor before drafting. Surfaced findings:

1. **Architectural principle needs enforcement, not just prose.** Add
   `tests/cross-mode-mirror-coverage.test.ts` that walks a registry of
   `(stepType, paramKey, mirrorClass)` entries and asserts a `SyncRow`
   renders for each one. Without this, the principle rots silently on
   the next cipher addition. — adopted as **Slice 4**.

2. **Key-expansion: ship it, but the verb has to be different.**
   "Copy S-box to decrypt" not "Sync inverse to decrypt". The label
   IS the pedagogical hook — it names the *different* operation
   (FIPS-197 §5.2: key expansion uses forward S-box even when
   decrypting). Cite the spec section in the tooltip. — adopted as
   **Slice 3**.

3. **MixColumns: all-or-nothing.** Project's "no half-finished
   implementations" rule rules out a canonical-only stub. Real
   GF(2^8) Gauss-Jordan with KATs against `AES_INV_MIX_MATRIX`. The
   primitives (`xtime`, `gfMul`) already exist in
   `src/core/state/matrix.ts` so the slice is ~60-80 lines (lower
   than advisor's initial ~100 estimate). Place last; doesn't block
   other slices. — adopted as **Slice 5**.

4. **Click feedback: button-internal flash, not adjacent inline
   text.** Adjacent text causes layout shift. Button briefly
   transitions to a success state (✓ glyph + accent-success
   background) for ~900ms, then reverts. Pair with a
   `<span class="visually-hidden" aria-live="polite">` for screen
   readers. Wrap as a reusable primitive (`useActionFeedback()` hook
   or `<ActionButton>` component) so new buttons inherit it for
   free. — adopted as **Slice 1**.

5. **The retrofit is the blocking constraint.** Slice 1 MUST also
   retrofit the existing Repair + Sync-inverse buttons that shipped
   in `d5c0949`. Without that, two visual languages coexist on the
   same panel — old buttons silent, new ones with feedback. UX
   regression. — adopted as part of **Slice 1**.

**Recommended ordering** (adopted): feedback primitive (+ retrofit) →
Serpent → key-expansion → enumeration test → MixColumns.

## Pedagogical principle (to land in `CLAUDE.md`)

Add a short section titled "Cross-mode mirror buttons" under
Conventions:

> **Encrypt and decrypt are held simultaneously in the store but
> *never* auto-synced.** A user can edit either side independently
> and learn what breaks. Every step whose param has a known
> cross-mode relationship (class 1: identity-mirror, class 2:
> inverse-mirror) ships with a labelled, opt-in Sync button below
> its param editor. The button's label names the specific operation
> ("Sync inverse S-box to decrypt", "Copy S-box to decrypt",
> "Sync inverse MixColumns to decrypt"). Tooltip cites the spec
> section that justifies the relationship. A `cross-mode-mirror-
> coverage.test.ts` enumeration test ensures new step types in
> class 1 or 2 cannot ship without their button.

## Slices

### Slice 1 — Action-feedback primitive + retrofit (1 commit) — **SHIPPED 2026-05-16 (`4fb1b6f`)**

**Empirical scope cut during implementation:** the plan listed the
graph-view round-duplicate `+` glyph as one of the retrofits. The flash
turned out to be infeasible there — clicking the glyph triggers a spec
mutation that reconstructs the containers array, and Solid's `<For>`
rebuilds child instances when the array reference changes, so the new
`DuplicateGlyph` instance starts with `flashing=false` regardless of
timing (reordering `triggerFlash()` before `props.onDuplicate()` did not
help — Solid's batched-update flush still replaces the DOM before the
next paint). The click's RESULT is intensely visible anyway (new round
group appears mid-canvas, every subsequent round renumbers, decrypt
counterpart auto-mirrors), so no supplementary signal needed.
Documented inline at `DuplicateGlyph` in `GraphView.tsx` and at the
end of `src/ui/app.css` where the CSS rule would have lived.

**Generalization for future SVG action affordances inside spec-derived
`<For>` loops:** local-signal-based flash won't work. Either a stable
`keyBy` on the `<For>` (changes Slice 8 drag-drop semantics) or a
graph-store-level "recently-acted" set the renderer reads. Neither is
worth doing for a single button; revisit if multiple SVG action
glyphs ever need flash feedback.



**Goal:** Every "this clicked and did something" button gives a
~900ms visible signal, plus an aria-live announcement.

**Implementation:**
- New file `src/ui/components/ActionButton.tsx`: Solid component
  wrapping `<button>`. Props: standard button props +
  `onAction: () => void`, `feedbackLabel?: string` (for aria-live;
  defaults to button text). Manages a `flashing` signal (`true` for
  900ms after click) and applies `.action-button.flashing` class.
- CSS additions to `src/ui/app.css`:
  - `.action-button.flashing` → background transitions to
    `--accent-success` (new var, green hue), foreground to white;
    `transition: background-color 200ms ease-out`.
  - Inside `.action-button.flashing` an `::after` with content
    `✓` slides in.
  - Reverts via class removal after 900ms.
  - Honor `prefers-reduced-motion` (no slide, just color flash).
- Aria-live region: `<span class="visually-hidden" aria-live="polite">`
  populated with `feedbackLabel` on click, cleared on revert.
- **Retrofit** existing buttons:
  - `SboxEditor.tsx`: `.sbox-warning-repair` → `<ActionButton>`.
  - `SyncInverseRow` in `ParamEditor.tsx` → `<ActionButton>`.
  - "Apply to all" in `ParamEditor.tsx` (if it's a discrete button —
    verify during implementation) → `<ActionButton>`.
  - Duplicate-round button in `GraphView.tsx` → `<ActionButton>`.
- Tests:
  - `tests/action-button.test.tsx` (jsdom): click → assert
    `.flashing` class present → assert aria-live text → wait 900ms
    → assert class removed.
  - `prefers-reduced-motion` honored via CSS only; no JS test (CSS
    media query, not easy to mock in jsdom).

**Acceptance criteria:**
- All four retrofitted buttons flash on click.
- No new buttons land without `<ActionButton>` wrapping (enforced
  socially this slice; mechanically in Slice 4).
- Aria-live region announces "Repaired S-box to permutation" /
  "Synced inverse S-box to decrypt" / etc. — names the operation,
  not just "clicked".
- `npm run check` passes.

**Out of scope this slice:**
- Toast notifications (would be a separate primitive; not needed
  for the current footprint).
- Sound effects (no).

### Slice 2 — Serpent 4-bit S-box duplicate-detection + Repair + Sync (1 commit) — **SHIPPED 2026-05-16 (`d35bd96`)**

**Plan deviation (advisor-confirmed in-scope):** the original Slice 2
declared multi-table sync out of scope, expecting a single forward
S-box like AES. The actual Serpent data model has 8 distinct S-boxes
cycling across the 32 rounds (`S_{(r-1) mod 8}`), and all 32 encrypt
leaves share the `serpent.sub-bytes@1` step type — broadcasting one
inverted table to every leaf in the counterpart slot (the existing
`syncSboxInverseToCounterpart` semantic) would overwrite 28 of 32
decrypt rounds with the wrong inverse.

Resolution: new sibling mutator
`syncSboxInverseToCounterpartByIndex(stepType, sboxIndex,
invertedSbox)` in `src/ui/stores/spec.ts`. Filters by
`params.sboxIndex === sboxIndex` inside the update fn so non-matching
leaves return reference-equal — `updateAllStepsByType`'s tree walker
short-circuits the rebuild for those subtrees. The two mutators
read as parallel siblings: "AES has one S-box, Serpent has eight,
Sync semantics differ accordingly."

**Within-encrypt sboxIndex consistency is deferred** — editing
round.4's S_3 and clicking Sync only writes to decrypt-side
sboxIndex-3 leaves; encrypt's round.12/20/28 (also S_3) stay
un-edited and diverge from their decrypt counterparts. Same "each
leaf owns its params" semantic AddRoundKey has had since launch.
A future "Apply S_3 to all rounds using S_3" affordance could
address it, but it's a separate slice.

**No ApplyAllRow on Serpent SubBytes** — broadcasting one S-box
across 32 rounds would destroy 28 sboxIndex assignments (project's
"skip ApplyAllRow when copying across siblings is actively harmful"
guidance).

**Implication for Slice 4 (enumeration test):** the registry shape
described in Slice 4's section is incomplete for Serpent. A single
entry `{ stepType: "serpent.sub-bytes@1", paramKey: "sbox",
mirrorClass: "inverse" }` asserts "a Sync button exists" but
cannot assert the per-index semantic — Serpent's button is per-leaf,
not per-step-type. Slice 4 needs to extend the entry shape with
`groupBy?: "sboxIndex"` or accept that the enumeration test only
checks presence (and pin the per-index semantic via
`tests/sync-serpent-sbox-inverse.test.ts` instead). The Serpent
mutator's docstring carries this flag.

**Testing gotcha** discovered during implementation (now in
`docs/gotchas.md` under "Solid UI"): tests that call
`setCipher("serpent-128")` to flip the active cipher MUST import
`setCipher` from `@/ui/stores/spec`, NOT `@/ui/stores/cipher`. The
former calls `buildCanonicalPair` and rebuilds the spec; the latter
only flips the signal, so the spec store still serves AES-128.
Both Serpent tests in this slice hit this bug on first iteration.

**Goal:** Apply the existing AES S-box affordances to Serpent.
Helpers are already size-parameterized; this is rollout, not new
logic.

**Implementation:**
- In `ParamEditor.tsx`, the `serpent-sbox-grid` rendering (current
  location: ~line 625; verify before editing):
  - Add `duplicateSet`, `collisionGroups`, `redundantCount` memos
    (same as `SboxEditor.tsx`).
  - Pass `duplicate` prop to each `ByteCellInput` in the grid.
  - Render a smaller warning banner above the 4×4 grid when
    `redundantCount() > 0`. Style scope: `.serpent-sbox-warning`
    (similar to `.sbox-warning-banner` but tighter padding for the
    smaller grid context).
  - Add a Repair button (`<ActionButton>`) wired to
    `repairToPermutation`.
  - Add a `SyncInverseRow` below the grid, gated on bijection,
    targeting `serpent.sub-bytes@1` ↔ `serpent.inv-sub-bytes@1`.
  - Re-use `SbxBlock` if structurally close; otherwise factor out
    a `<SboxValidationPanel size={16}>` shared component used by
    both AES and Serpent block bodies (preferred — same pattern at
    different N).
- Step types involved: `serpent.sub-bytes@1` and
  `serpent.inv-sub-bytes@1`. Verify both expose a `sbox` param.
- Tests:
  - `tests/serpent-sbox-validation.test.tsx` (jsdom): banner
    appears, Repair button repairs, Sync button gated on
    bijection. Mirror the AES test pattern.
  - `tests/serpent-sync-inverse-store.test.ts` (node): exercise
    `syncSboxInverseToCounterpart("serpent.sub-bytes@1", inverse)`
    against canonical Serpent spec.

**Acceptance criteria:**
- Editing a Serpent S-box cell into a duplicate flags the cell
  red and shows the banner.
- Repair restores a 4-bit permutation of 0..15.
- Sync writes the inverse to the matching `serpent.inv-sub-bytes`
  steps in the counterpart slot.
- `npm run check` passes.

**Out of scope this slice:**
- Serpent's 32 separate S-boxes (one per round) — the current
  shape is single S-box; multi-table sync waits for the universal
  cipher-shape work if it ever proves needed.
- MixColumns equivalent in Serpent (linear transformation table)
  — separate consideration.

### Slice 3 — Key-expansion S-box copy-sync (1 commit)

**Goal:** Wire an opt-in "Copy S-box to decrypt" button on the
key-expansion editor. Distinct verb ("Copy" not "Sync inverse")
to name the FIPS-197 §5.2 asymmetry.

**Implementation:**
- New mutator in `src/ui/stores/spec.ts`:
  `syncSboxCopyToCounterpart(stepType, sboxValue)`. Same shape as
  the existing inverse mutator but writes `sboxValue` directly
  (no invert step). Docstring cites FIPS-197 §5.2.
- New component in `ParamEditor.tsx` (or factored helper):
  `<CopySboxRow stepType={...} currentSbox={...}>`. Wraps an
  `<ActionButton>`. Tooltip when enabled: *"Copy this S-box to
  every {stepType} step in the {counterpart} slot. FIPS-197 §5.2:
  key expansion uses the FORWARD S-box even when decrypting, so
  the same table appears on both sides (this overwrites any
  per-step customizations on that side)."* Tooltip when disabled:
  *"Repair to a permutation first — a non-bijective key-expansion
  S-box still copies, but the result is unlikely to be useful."*
- Wired into the key-expansion block in `ParamEditor.tsx`
  (currently `KeyExpansionBlock` per the prior session's notes).
- Tests:
  - `tests/sync-sbox-copy.test.ts` (node): store-level cross-slot
    copy. Both directions (encrypt→decrypt, decrypt→encrypt).
  - `tests/copy-sbox-row.test.tsx` (jsdom): renders, gated on
    bijection (same gating policy as the inverse case for
    consistency, though copy *could* technically run on a
    non-permutation; we gate it to keep behavior coherent across
    all S-box rows).

**Acceptance criteria:**
- Selecting an `aes.key-expansion@1` step shows the new Copy row.
- Click → counterpart-mode key-expansion S-box becomes identical
  to active mode's value, every matching step updated.
- ActionButton flash confirms the click.
- Tooltip text cites FIPS-197 §5.2.
- `npm run check` passes.

**Out of scope this slice:**
- Generalizing the copy semantic to non-S-box params (e.g.,
  rcon — separate consideration when/if rcon ever diverges
  between modes).

### Slice 4 — Enumeration test + CLAUDE.md note (1 small commit, or fold into Slice 3)

**Goal:** Make "every class-1/2 step has a mirror button" a
verifiable invariant.

**Implementation:**
- New file `src/ui/components/cross-mode-mirror-registry.ts`:
  exports a const `CROSS_MODE_MIRROR_ENTRIES: readonly { stepType:
  string; paramKey: string; mirrorClass: "identity" | "inverse";
  counterpartStepType?: string }[]`. Entries:
  - `{ stepType: "generic.byte-substitution@1", paramKey: "sbox",
     mirrorClass: "inverse" }` (AES SubBytes)
  - `{ stepType: "aes.key-expansion@1", paramKey: "sbox",
     mirrorClass: "identity" }`
  - `{ stepType: "aes.key-expansion@2", paramKey: "sbox",
     mirrorClass: "identity" }` (the renumber variant)
  - `{ stepType: "serpent.sub-bytes@1", paramKey: "sbox",
     mirrorClass: "inverse", counterpartStepType:
     "serpent.inv-sub-bytes@1" }`
  - `{ stepType: "aes.mix-columns@1", paramKey: "matrix",
     mirrorClass: "inverse" }` (added in Slice 5)
- New test `tests/cross-mode-mirror-coverage.test.tsx` (jsdom):
  for each registry entry, render `<App />`, navigate to a step
  of that type via `setSelectedStepId`, assert a button exists
  whose `data-mirror-class` attribute matches the entry's class.
  `<ActionButton>` accepts and forwards `data-*` props.
- Add the "Cross-mode mirror buttons" section to `CLAUDE.md`
  under Conventions (prose from "Pedagogical principle" above).

**Acceptance criteria:**
- New step type with a class-1/2 param is added to the registry →
  test passes. Forgotten → test fails with a clear message
  ("Step type X has paramKey Y class inverse but no mirror button
  rendered in ParamEditor").
- `CLAUDE.md` carries the principle so a future Claude session
  reading it knows the rule before touching new ciphers.

**Out of scope this slice:**
- Auto-generating the SyncRow from registry data (would need a
  per-class component dispatch — possible later, but the four
  hand-wired call sites are easy to maintain).

### Slice 5 — MixColumns inverse-sync (1 commit)

**Goal:** Apply the same Sync pattern to the MixColumns matrix.
Requires GF(2^8) 4×4 matrix inversion.

**Implementation:**
- New file `src/core/state/gf-matrix.ts`:
  - `gfInverse(a: number): number` — multiplicative inverse via
    256-entry lookup table built once (`for a in 1..255: find b
    where gfMul(a,b) === 1`). Throws on `a === 0`.
  - `gfMatInverse4x4(M: readonly (readonly number[])[]):
     number[][]` — Gauss-Jordan on `[M | I]` over GF(2^8) using
    `gfMul`/`gfInverse`. Returns the inverse or throws if `M` is
    singular over GF(2^8).
  - Uses existing `xtime` / `gfMul` from
    `src/core/state/matrix.ts` (import, don't re-implement).
- Tests `tests/gf-matrix.test.ts` (node):
  - `gfInverse(1) === 1`, `gfInverse(2) === 0x8d` (known
    GF(2^8) inverse). Spot-check 3-4 known pairs.
  - Property: for all `a in 1..255`, `gfMul(a, gfInverse(a)) === 1`.
  - KAT: `gfMatInverse4x4(AES_MIX_MATRIX)` equals
    `AES_INV_MIX_MATRIX` byte-for-byte.
  - Property: `gfMatMul(M, gfMatInverse4x4(M))` equals the 4×4
    identity for several random invertible `M`.
  - Singular matrix throws (e.g., all-zeros row).
- New mutator `syncMixColumnsInverseToCounterpart(stepType,
  invertedMatrix)` in `src/ui/stores/spec.ts`. Same shape as the
  S-box inverse mutator.
- New component `<SyncMixColumnsRow>` in `ParamEditor.tsx`.
  Gating: `mixColumnsIsInvertible(currentMatrix)` (catches the
  singular case before the user clicks). Tooltip cites FIPS-197
  §5.3.3.
- Tests:
  - `tests/sync-mix-columns-store.test.ts` (node): canonical KAT
    + bidirectional.
  - `tests/sync-mix-columns-row.test.tsx` (jsdom): disabled on
    singular matrix.
- Registry update in Slice 4's file.

**Acceptance criteria:**
- Editing the MixColumns matrix on encrypt side, clicking Sync,
  flips decrypt's `aes.mix-columns@1` matrix to the GF(2^8)
  inverse.
- Setting matrix to the canonical AES_MIX_MATRIX and clicking
  Sync produces AES_INV_MIX_MATRIX in the counterpart slot (KAT
  inversion verified at UI level, not just unit level).
- Singular matrix disables the button with a tooltip explaining
  why.
- `npm run check` passes.

**Out of scope this slice:**
- Visual highlighting of which matrix entries make the determinant
  zero (the singular-matrix warning is plaintext only).
- Sync from row to row inside one matrix (different operation, not
  cross-mode).

## Suggested ordering (final)

1. **Slice 1** — Action-feedback primitive + retrofit. (Foundation.)
2. **Slice 2** — Serpent S-box trio. (Smallest, proves the
   primitive works at N=16.)
3. **Slice 3** — Key-expansion Copy-sync. (Same shape, different
   verb — exercises the architectural principle.)
4. **Slice 4** — Enumeration test + CLAUDE.md principle. (Locks
   the pattern; can fold into Slice 3's commit if small enough.)
5. **Slice 5** — MixColumns inverse-sync. (Largest; the
   GF(2^8) work is committable independently.)

## Critical files

| File | Slice(s) | Role |
|---|---|---|
| `src/ui/components/ActionButton.tsx` (new) | 1 | Reusable feedback-on-click button. |
| `src/ui/app.css` | 1 | `.action-button.flashing` rules + `--accent-success` var. |
| `src/ui/components/SboxEditor.tsx` | 1 | Retrofit Repair button. |
| `src/ui/components/ParamEditor.tsx` | 1, 2, 3, 5 | Retrofit Sync row; add Serpent panel, CopySboxRow, SyncMixColumnsRow. |
| `src/ui/components/GraphView.tsx` | 1 | Retrofit duplicate-round button. |
| `src/ui/components/sbox-validation.ts` | 2 | No changes needed — helpers already size-parameterized. |
| `src/ui/stores/spec.ts` | 3, 5 | Add `syncSboxCopyToCounterpart`, `syncMixColumnsInverseToCounterpart`. |
| `src/core/state/gf-matrix.ts` (new) | 5 | `gfInverse` + `gfMatInverse4x4`. |
| `src/core/state/matrix.ts` | 5 | Import `xtime` / `gfMul` (no edits expected). |
| `src/ui/components/cross-mode-mirror-registry.ts` (new) | 4 | Registry data driving the enumeration test. |
| `tests/action-button.test.tsx` (new) | 1 | Flash + aria-live. |
| `tests/serpent-sbox-validation.test.tsx` (new) | 2 | Banner + Repair + Sync at N=16. |
| `tests/serpent-sync-inverse-store.test.ts` (new) | 2 | Store-level. |
| `tests/sync-sbox-copy.test.ts` (new) | 3 | Copy semantic. |
| `tests/copy-sbox-row.test.tsx` (new) | 3 | UI gating. |
| `tests/cross-mode-mirror-coverage.test.tsx` (new) | 4 | Enumeration. |
| `tests/gf-matrix.test.ts` (new) | 5 | GF inversion KAT + properties. |
| `tests/sync-mix-columns-store.test.ts` (new) | 5 | Store-level. |
| `tests/sync-mix-columns-row.test.tsx` (new) | 5 | UI gating + singular case. |
| `CLAUDE.md` | 4 | Architectural principle prose. |
| `CHANGELOG.md` | every slice | Keep-a-Changelog entry. |

## Out of scope

- **Auto-sync** — explicitly rejected. The whole point is opt-in
  visibility.
- **Toast/snackbar notification system** — the in-button flash
  covers the click-feedback need; a global toast root is more
  infrastructure than warranted.
- **Sound effects on click** — no.
- **Undo/redo of a Sync click** — the user can re-edit the
  counterpart by mode-switching and using the editor or re-running
  Sync the other direction. A unified undo stack is a separate
  feature.
- **Per-step custom mirror operations** — every entry in the
  registry uses a uniform class (identity or inverse). If a future
  step needs a per-step custom function, extend the registry then.
- **Cross-mode sync of structural changes** — `duplicateRoundInSpec`
  already handles round duplication; no other structural mirror is
  needed today.
- **Speck32/64 cross-mode sync** — Speck is symmetric across modes
  by construction (no S-box, no MixColumns); no mirror button is
  meaningful. No registry entry needed.
- **Stream/AEAD/Hash future** — when those land, they're not class
  1 or 2 and don't need mirror buttons. The principle still holds
  ("encrypt + decrypt independent"), just degenerates to "no
  mirror needed" for asymmetric or one-direction primitives.

## References

- Prior shipped work: commits `89c7d17` (Repair button) and
  `d5c0949` (Sync inverse).
- Feistel-near-future caveat ([[project_feistel_near_future]]):
  when a branching-state Feistel cipher lands, its left-/right-
  half params may need a different mirror class. Out of scope
  here; revisit when Feistel's data model is concrete.
- FIPS-197 §5.2 (Key Expansion uses forward S-box) and §5.3.3
  (InvMixColumns) for the spec citations baked into tooltips.
