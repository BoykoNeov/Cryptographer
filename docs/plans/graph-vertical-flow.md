# Graph view — vertical (top-to-bottom) outer flow

> **Status:** drafted 2026-05-20 in response to a Phase 6e DES smoke
> finding. **Not started.** Multi-slice plan; advisor pass before each
> slice per `feedback_iterative_slice_review.md`. Approval needed before
> Slice 1 begins.

## Context

DES is the first cipher in this project where a container's body
already runs vertically (top-to-bottom), driven by the `feistel-round`
primitive shipped in Phase 2 of `docs/plans/des-feistel.md`. Inside a
round, L and R tracks stack downward and the rejoin chip sits below
both. Across rounds inside the parent `Rounds` group container, the
sequence reads the same way: round.1 above round.2 above round.3...
visually a single vertical column with crossover X arrows between
consecutive rejoins.

But at the root level (outside any container), `layoutRoot` still
positions nodes along an X axis with constant Y. The current DES root
layout reads (left → right):

```
plaintext → initial-permutation → [Rounds container, 2700px tall] → final-permutation → ciphertext
```

The "Rounds" container is the tall vertical column. So the cipher's
flow reads "across the top, then down a column, then back across the
top to the output." The arrow from the bottom of the rounds column to
the ciphertext pill skips back UP to the top row — visually long, and
breaks the "trace flows in one direction" reading the rounds column has
already established. The same direction-flip happens at the
initial-permutation → first round transition.

User-flagged 2026-05-20 in the Phase 6e DES smoke. The fix is not
DES-specific — every cipher whose body runs vertically inside a
container would benefit, and Feistel-family follow-ups (TEA, XTEA,
3DES, eventually Blowfish/Twofish) all share this body shape.

## Goal

Single-axis vertical reading order for the entire graph view: root-
level nodes stack top-to-bottom in the same direction container bodies
already use, so cipher trace flow has ONE direction the eye follows
from plaintext to ciphertext without an axis flip.

## Non-goals

- **Rewriting horizontal-flow containers.** `Rounds` (a group) currently
  expands its child column vertically; AES round groups expand
  horizontally. We're flipping the ROOT axis only; group containers
  remain free to lay out their own children in whichever direction
  their nature demands (existing AES horizontal groups don't visually
  change). The state-spine arrow inside a container still flows in the
  container's local direction.
- **Renaming or re-shaping any spec primitives.** The change is layout-
  only: same `CipherSpec`, same `CipherGraph`, same `Trace`. Only the
  `layoutRoot` output's (x, y) coordinates change.
- **Touching the linear-mode or JSON views.** Both views are unaffected.
- **Re-routing arrows through a different algorithm.** The existing
  per-edge router (curve / orthogonal / bundle) keeps the same
  semantics; the only thing that changes is what it draws between
  given (x, y) anchors.

## Affected surface

This is a layout-architecture refactor; the diff fans out beyond the
obvious sites:

| Surface | Concern |
|---|---|
| `layoutRoot` (the main loop) | Stack along Y instead of X. New `STACK_GAP_ROOT` constant (or reuse `FLOW_GAP`). |
| Replica lift | Today: replicas lift "above" their consumer (smaller y). Tomorrow: replicas lift "to one side" (offset x), since "above" is now the spine direction. Likely lift left for inputs, right for outputs — TBD. |
| Aux-only-root placement | Same direction question as replica lift. `key-expansion` currently lifts to `CANVAS_MARGIN`; needs a new axis to lift along. |
| State-spine arrow routing | Today assumes left-to-right shaft direction. The router has bend rules ("come into the chip from the left," "exit from the right") tuned for that. Vertical equivalents: enter from top, exit from bottom. Currently in `EdgePath` rendering. |
| Endpoint pill anchors | `__cipher_input__` sits at left edge today. Move to top edge. `__cipher_output__` from right edge to bottom edge. The "first-state-consumer anchor" + "into terminal container descent" both work in graph-id space, but their pixel-coordinate side derivations need flipping. |
| Port-spreading geometry | `portAssignment` buckets visual targets by (target, side) where side ∈ {left, right, top, bottom}. The horizontal-regime extension shipped in commit `8604236`; the vertical-flow case needs the same bucket logic but biased the other way. |
| `STACK_GAP` vs `FLOW_GAP` axis assignment | Two constants today: STACK_GAP for orthogonal-to-flow separation, FLOW_GAP for along-flow separation. Flipping root direction means STACK_GAP_ROOT_X (was Y) and FLOW_GAP_ROOT_Y (was X). Could rename to "primary" / "secondary" but cost-benefit weak; consider keeping XY names and adjusting only the root-level call sites. |
| Arrow-bundling label position | Today the ×N pill sits at t=0.25 along the arrow from source. Vertical arrows still want that ratio but the label rotation needs to be set so text reads horizontally regardless of the underlying line angle (text rotation 0, no transform). Already the case today for horizontal arrows — vertical arrows need explicit text orientation. |
| Drop-anchor priority | `walkSpec`'s drop-anchor lookup walks the spec tree top-down; the visual mapping (cursor → anchor) currently uses x-axis distances at root level. Need a y-axis distance variant for root drops, body drops unchanged. |
| `tests/graph-view-layout.test.ts` + replica-placement tests | Pin x/y coordinates against the AES-128 / DES / Speck / Serpent fixtures. Every one of these needs re-baselining after the flip. |
| User layout-pin sidecar | `LayoutSpec.positions` stores absolute (x, y) per stepId. After the flip, existing saved positions still work BUT they were set in the old axis convention; if a user-saved layout pins a node at (520, 80), that may now read as "in the middle of the canvas" rather than "right of plaintext." Either: (a) accept this and let users re-pin; (b) write a migration that swaps x and y in saved positions; (c) bump `LayoutSpec.schemaVersion` and gate the flip on the new version. Discuss before implementing. |
| Bundle size | Adds nothing structurally — should be neutral. |
| Tests touching screenshots | None of the existing e2e specs (`slice-6`, `slice-7c`) pin pixel layouts beyond "this id exists with non-default coords." Should pass without re-baselining if I'm careful. |

## Plan

### Slice 1 — Introduce a `RootFlowDirection` constant + thread it through `layoutRoot`

**Goal:** prove the constant works end-to-end without flipping any
production cipher yet. Add `"horizontal" | "vertical"` enum at the
`LayoutConstants` level; `layoutRoot`'s root-stacking loop reads it and
branches between X-stacking (today) and Y-stacking (new). Default the
constant to `"horizontal"` so production output is byte-identical until
Slice 4 flips it.

**Tests:**
- `tests/graph-layout-root-direction.test.ts` (new) — synthetic 3-node
  graph driven through `layoutRoot` once with `"horizontal"`, once with
  `"vertical"`. Assert (x, y) coordinates swap on the appropriate axes.
- `tests/graph-view-layout.test.ts` — existing AES-128 byte-equivalence
  tests must still pass (default is still horizontal).

Commit: 1 file added (layout test), 2 files modified (`GraphView.tsx`
for the constant + branch, the layout type definitions).

**Risk:** low. Adding a branch behind a constant that defaults to
today's behavior.

### Slice 2 — Replica lift + aux-only-root axis flip

**Goal:** under `direction === "vertical"`, replicas lift to one side
(propose: left, so inputs converge from the left into the vertical
spine) and aux-only roots lift to the same side. Same byte-identical
gate for `"horizontal"`.

**Tests:**
- Layout test asserting the relative positioning of replicas vs their
  consumer under each direction.

**Risk:** medium — the existing replica-row stacking logic uses Y for
the row index. Under vertical flow, "rows" become "columns" and the
math touches `replicaLiftHeight` / `replicaLiftWidth`.

### Slice 3 — Arrow routing: top/bottom entry, vertical label orientation

**Goal:** under `vertical`, `EdgePath` rendering enters chips from the
top edge and exits the bottom edge. Arrow-bundling labels keep
horizontal text orientation regardless of shaft angle. Endpoint pills
anchor at top (input) and bottom (output) edges.

**Tests:**
- Edge-path geometry test: synthetic vertical-flow graph + assertion
  on `<path d>` shape (start/end coordinate sides).
- Endpoint pill anchor test: with `vertical` direction, input pill's
  bounding box sits above the first state-consumer's box.

**Risk:** medium-high. Routing has accumulated edge cases over the
last 3 months (port-spreading, overhead routing for crowding,
arrow-bundling). Each branch needs vertical-aware variants.

### Slice 4 — Flip the default constant + re-baseline tests

**Goal:** change the default from `"horizontal"` to `"vertical"` at
the `LayoutConstants` factory. AES, Speck, Serpent, DES all now lay
out top-to-bottom at the root. Re-baseline the AES / Speck / Serpent /
DES fixture tests that pin exact x/y coordinates.

**Tests:**
- All existing fixture-pinned tests: re-record coordinates.
- Add a "first frame's stateBefore sits above last frame's stateAfter
  in canvas y" smoke for each cipher (the user-facing property
  becomes asserting once direction is flipped).
- Manual browser smoke (this slice's "human pass"):
  - AES-128 single-block: does the vertical layout read cleanly?
  - AES-128 ECB / CBC: the iterate's `ecb-blocks` body still flows
    horizontally inside the container (its OWN direction); only
    root nodes stack vertically.
  - Speck-32/64 (both byte orders): horizontal-internal cipher under
    vertical-root layout.
  - Serpent: the IP/FP bit-permutations get long arrow paths; verify
    they don't kink.
  - DES: the headline. Compare to today's layout in `test-results/`.

**Risk:** high. This is the slice where users see the change. Likely
one or two follow-up commits for visual polish.

### Slice 5 — `LayoutSpec` migration for saved positions

**Goal:** decide policy + implement. Options surfaced earlier (accept
breakage, migrate, gate on schema bump). Recommend: bump
`LayoutSpec.schemaVersion`; on load, if the saved version predates the
flip, swap x↔y in positions before applying. Document in
`docs/versioning.md`.

**Tests:**
- Document-roundtrip test: pre-flip saved document loads cleanly into
  post-flip code, with positions re-aligned.

**Risk:** medium. Migration logic is straightforward; edge cases are
relative-position deltas (`relativePins`) and pinned containers vs
their nested children.

### Slice 6 — R-half visible split (Feistel branching pedagogy)

> Added 2026-05-20 from Phase 6e smoke: user observed that "the R half
> is actually split — one transforms, one comes out directly as the
> next L — but this isn't apparent in the current visualization." In
> the standard Feistel combine, R_in is used twice: once as the input
> to the F-function (expand-R → xor-K → s-boxes → p-permute), and
> once as the value that flows around F to become new_L (the swap).
> The current graph shows R_in flowing into expand-R only; the second
> copy of R_in (the bypass) is implicit in the rejoin's combine logic
> and invisible to the reader.

**Goal:** make the R_in bypass visible. Two design directions to
evaluate before implementing:

- **(a) Synthetic "R-tap" node** at the start of each R-track that
  visibly branches into TWO outputs: one to the first F-stack leaf
  (expand-R), one to a "to next L" anchor that arrows down to the
  rejoin's L-side. The tap is non-functional (it carries identity);
  its job is purely visual.
- **(b) Implicit second edge** drawn from the round's entry boundary
  (the R-track's input point) directly to the rejoin's L-output port.
  No new node — just a routed edge labelled "R_in → new_L (swap)".
  Lighter graph but the edge has no producer node, complicating
  inspector lookups.

**Recommendation:** start with (b) — minimal graph surgery, no new
node kind. If user testing shows the edge is confusing without a
visible source, escalate to (a) in a follow-up slice.

**Tests:**
- Graph derivation: synthetic Feistel-round + assert the swap-bypass
  edge exists with the right endpoints.
- Visual smoke: capture DES round 5 before/after, eyeball the bypass
  arrow.

**Risk:** medium. Edge-value inspector needs a special-case for the
bypass edge (resolves to R_in from the rejoin frame's params, same
shape as the passthrough special-case shipped 2026-05-20).

### Slice 7 — L / R color-coding in inspector + arrows

> Added 2026-05-20 from Phase 6e smoke: user requested "different
> parts should be colored differently in the value inspector and in
> the arrows" so it's visually obvious which 4 bytes are L and which
> are R.

**Goal:** when a value displayed in the inspector OR carried by an
arrow spans both L and R bytes (the rejoin frame's combined output,
the next round's input), color-code the byte cells / arrow segments
by half. L gets one hue, R gets another. The color choice should
NOT collide with `--accent` (state-spine blue), `--accent-success`
(compare-runs green), `--changed` (round-frame amber), or the source-
color palette.

Two surfaces:
- **Inspector byte grid.** Add a `byteHalfMask: ("L" | "R")[]` field
  to `EdgeValueLookup` when the resolved value is a combined Feistel
  output. The byte-grid renderer reads the mask and applies per-cell
  background tint.
- **Arrows.** State edges out of a rejoin carry only one half (after
  Slice 6's bypass edge lands, both halves' edges are individually
  identifiable). Each edge picks the matching L or R tint.

**Tests:**
- Inspector renders the right tint pattern for a rejoin frame view
  (combined output) vs a passthrough chip (one half only).
- Edge tint test: rejoin → next-round-L arrow uses L tint; rejoin →
  next-round-R arrow uses R tint.

**Risk:** medium. The byte-grid renderer is shared across many
inspector view kinds; adding a half-mask shouldn't change other
kinds' rendering. Needs a default-no-op path.

### Position in time

Slices 6 and 7 are independent of Slices 1-5 (they apply under either
flow direction). Implementing them BEFORE the direction flip means
DES users get the Feistel pedagogy improvements regardless of the
larger layout refactor's timing. Implementing them AFTER means the
slices benefit from the cleaner vertical layout. Pick at scheduling
time.

## Position in time

After:
- Phase 6e of `docs/plans/des-feistel.md` closes (manual smoke signs
  off the four bug-fixes from the 2026-05-20 batch).
- Any visual feedback from the closed-out smoke is folded in.

Before:
- The universal cipher-shape plan (`~/.claude/plans/silly-brewing-
  sutton.md`) — that plan widens the type system; doing it on top of a
  reshaped layout means less re-work.

## Open questions for user before Slice 1

1. **Replica lift side under vertical flow.** Left (inputs converge
   from outside in) or right (auxiliary computation stays on the
   side opposite the natural reading direction)? My instinct says
   left; need a sketch + a user pick.
2. **`LayoutSpec` migration policy.** Migrate (swap x↔y), accept
   breakage (users re-pin), or schema-version gate (flip only for new
   saves)? Recommend migrate but the user may want to preserve old
   saves byte-identically.
3. **Iterate body direction.** Today `ecb-blocks` body flows
   left-to-right (the user-facing "block 1, block 2, block 3..."
   visual). Under vertical root, should the iterate body also flip
   to top-to-bottom for consistency? Or stay horizontal since its
   semantics are "N parallel runs of the same body"? Pick one before
   Slice 1.

## What we explicitly chose NOT to do

- **Per-cipher direction.** Tempted to make `direction` a spec-level
  setting so AES can stay horizontal while DES goes vertical. Rejected:
  the goal is consistency across ciphers, and mixed direction would be
  worse than either pure choice. The constant is global to the layout
  engine.
- **Auto-detect direction from container shape.** Considered "vertical
  if the spec has a `feistel-round` anywhere, horizontal otherwise" —
  but inconsistent across the user's cipher gallery, and bites when
  the user authors a hybrid spec. Single global default is cleaner.
- **Compass-rose direction (left, right, up, down) as a four-way
  enum.** Two values cover every realistic case; over-engineering.
