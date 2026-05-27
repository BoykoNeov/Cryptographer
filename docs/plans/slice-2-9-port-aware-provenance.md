# Slice 2.9 — Port-aware inspector + provenance for SHA-256

> **Status: DRAFTED 2026-05-27. Slice 2.9a SHIPPED 2026-05-27 PM
> (+9 tests, +0.12 KB raw bundle). Slices 2.9b–e NOT STARTED.** Drafted
> after a session that surveyed today's frame shape for port-native
> SHA-256 leaves, ran an empirical probe, and consulted the advisor
> twice. Replaces the original three-bullet Slice 2.9 sketch in
> [`universal-port-phase-2-slices.md`](./universal-port-phase-2-slices.md)
> with a five-sub-slice arc.
>
> **2.9a-shipped notes.** Advisor pre-impl flagged the critical
> predicate trap: the runtime's `kind === "ported"` branch (line 300)
> is entered by BOTH pure port-native AND lifted-legacy steps. Gating
> port-field capture on `kind === "ported"` alone would have populated
> portInputs/portOutputs for AES SubBytes (lifted-legacy with `legacy`
> defined), which 2.9b's predicate would then dispatch into
> PortFlowView. The implementation uses `meta === undefined` as the
> port-native discriminator (equivalent to `legacy === undefined` at
> line 607; both fall out of the same "pure port-native = no projection
> metadata" Slice 1.2 contract). Negative test covers AES SubBytes
> + key-expansion under flag-on; legacy-path test sweeps every AES
> frame under flag-off. Frame-parity matrix
> (`tests/runtime-ported-dispatch-frame-parity.test.ts`)
> field-iterates rather than shape-iterates, so the new optional fields
> are invisible to it — parity stays untouched.

## Context — why the original sketch couldn't ship

The plan-text for Slice 2.9 reads:

> Wire cell-level provenance for SHA-256 words — hovering an output
> word lights up source words in the consumed inputs (e.g., hovering
> T1 lights up h, e, f, g, K_t, W_t).

The plan text was drafted before **Slice 2.6d** decomposed SHA-256
into generic port-native primitives. Two facts surface against today's
codebase:

1. **No SHA-256-specific compound leaves exist anymore.** The spec is
   built from generic port-native primitives — `xor@1`, `add-mod-32@1`,
   `rotate-bits-right@1`, `byte-slice@1`, `concat@1`, etc. There is no
   `sha256.compute-T1@1` leaf to register a provenance fn against. The
   "SHA-256 leaf types" the plan refers to don't exist.

2. **Port-native frames carry `stateBefore === stateAfter`.** Empirical
   probe (scratch test, 2026-05-27): 16 of 17 distinct port-native
   step types in the SHA-256 trace emit frames where stateBefore equals
   stateAfter byte-by-byte. Only `bytes-to-state@1` is shape-changing.
   The runtime never projects port outputs into `stateAfter` for pure
   port-native steps (no `meta.stateOutputPort`), so the linear
   inspector — which dispatches by `(stateBefore.shape, stateAfter.shape)`
   and renders state — has no port I/O to surface. The cell the user
   hovers belongs to the surrounding state, not the port-native step's
   actual transformation.

Together: the original "hover T1, light up h/e/f/g/K_t/W_t" outcome
isn't deliverable under today's renderer because T1's value isn't
visible to the inspector at all.

## Decision — sub-slice the gap into a port-aware inspector

User pick 2026-05-27 (Option B in the three-options consult — A
administrative close, B port-aware inspector, C scope reduction to
shape-changing steps only):

> **Build the port-aware inspector first.** If needed, split into
> different sub-slices that can be done on different sessions.

This sub-slice plan is that split. **The overlay surface (formula
chips, labeled state rows, matrix views) is OUT OF SCOPE for Slice 2.9.**
See "Deferred for future planning" at the bottom for the rationale; the
short version is: don't design the overlay until you have empirical
evidence from scrubbing port-cell-only views that the cells alone are
insufficient.

## Resolved design decisions

| ID | Question | Decision | Rationale |
|---|---|---|---|
| Q1 | Port I/O queryable from a frame how? | **Extend TraceFrame** with optional `portInputs?: ReadonlyMap<string, Uint8Array>` / `portOutputs?: ReadonlyMap<string, Uint8Array>` populated by the runtime for port-native frames. | ~50 KB/run memory cost (acceptable; SHA-256 trace already at ~2486 frames). Simpler downstream consumers — provenance fns + the inspector read directly from the frame. AES/DES rebuilds (Phase 3+) get this for free. Lazy-resolver alternative rejected for iterate-body ambiguity (which producer frame for which iteration?). |
| Q2 | Plan-doc shape | **Own file** at `docs/plans/slice-2-9-port-aware-provenance.md` (this file). | Cleaner cross-session resumption. Status updates land in one place. Pattern matches `docs/plans/sha-256-density-polish.md`. |
| Q3 | Inspector layout for port-native frames | **Vertical stack.** Per-port byte-cell rows stacked vertically — inputs first, then output(s). Each row labeled with port name. | Composes recursively under hierarchical frames (deferred but on roadmap). Scales gracefully to N=8 (`concat` repack) and N=5 (`add-mod-32` T1). Each port row picks its own rendering (BytesView per port; future MatrixView when `layout: "matrix-cm-4x4"`). Two-column rejected for wide N; diagram-style rejected for hierarchical drill-in cost. |
| Q4 | Overlay surface for "famous identities" (T1, Σ1, σ1, Ch, Maj) | **OUT OF SCOPE for Slice 2.9.** Cells alone are the deliverable. | Advisor verdict 2026-05-27 — cells + provenance hover deliver ~80% of pedagogical value; the overlay surface is ~10 "famous moments" of polish that should be designed AFTER empirical evidence from scrubbing the cells-only view. Premature abstraction otherwise (one schema won't fit SHA-256 formulas + AES matrix + DES F-function diagrams equally well). |

## Sub-slice arc

Five sub-slices. Each ships independently and is verifiable on its own.
Sequencing matters — 2.9b consumes 2.9a's frame shape, 2.9c consumes
2.9b's renderer, 2.9d consumes 2.9c's source shape.

### 2.9a — Port-value lookup infrastructure (pure)

**Goal:** make port inputs/outputs queryable from a frame, with no UI
changes.

**Scope:**
- Extend `TraceFrame` in `src/core/types.ts` with optional fields:
  ```ts
  readonly portInputs?: ReadonlyMap<string, Uint8Array>;
  readonly portOutputs?: ReadonlyMap<string, Uint8Array>;
  ```
- Runtime (`src/core/runtime.ts`) populates these for **pure port-native**
  dispatch (`portedDispatch && registration.kind === "ported" &&
  meta === undefined`). The `inputs` map already exists at frame-emit
  time (line 419-483); the `outputs` map already exists (line 479-504).
  Copy both into the frame.
- For legacy frames + lifted-legacy frames: leave both fields
  `undefined`. **Critical:** lifted-legacy is ALSO `kind: "ported"`
  (just with `meta` + `legacy` defined). Gating only on `kind === "ported"`
  would corrupt AES/Speck/Serpent/DES inspector dispatch in 2.9b.
  The actual gate is `meta === undefined` (= "no projection metadata"
  = "pure port-native" per the Slice 1.2 contract), equivalent to
  `legacy === undefined` at runtime.ts line 607.
- Helper: `framePortBytes(frame, portName, side: "input" | "output")`
  → `Uint8Array | null`. Lives in `src/core/port-projection.ts` (the
  module that already owns port↔state conversions).

**Pass/fail gate:**
- Unit test in `tests/frame-port-values.test.ts`:
  - For an `add-mod-32@1` frame in a SHA-256 trace, `frame.portInputs`
    has 5 entries (operand0..4) of 4 bytes each.
  - `frame.portOutputs` has 1 entry (`output`) of 4 bytes.
  - The output bytes equal the manual modular-add of the 5 inputs.
- Existing 2412-test suite still green (post-impl: **2421**, +9).
- Frame parity matrix (Slice 1.11) untouched — `expectFramesEqual`
  field-iterates rather than shape-iterates, so the new optional
  fields are invisible to it.
- No bundle size growth at the UI layer (no UI changes). Measured
  post-impl: 689.53 → 689.65 KB raw / 202.48 → 202.49 KB gzipped.

**Sequencing note:** must land before 2.9b. Pure runtime + types
change; no UI consumer wires up yet.

### 2.9b — Port-aware inspector view (cells only)

**Goal:** render port-native frames in the linear inspector as a
vertical stack of port-input rows + port-output rows. No provenance
hover yet — just the layout.

**Scope:**
- New component `src/ui/components/PortFlowView.tsx`. Renders a port
  frame: each row is one port (input or output), labeled by name,
  filled with cells (one per byte) using the existing byte-cell visual
  vocabulary (same as BytesView).
- Dispatch in `App.tsx::SingleFrameView`:
  ```ts
  <Show when={isPortNativeFrame(props.frame)} fallback={<existing matrix/bytes dispatch>}>
    <PortFlowView frame={props.frame} />
  </Show>
  ```
  Predicate: `frame.portInputs !== undefined || frame.portOutputs !== undefined`.
- Port name labels use the spec leaf's bindings as authoritative; the
  `inputs` map's key set IS the port-name set. No `narrationOverride`
  consumption yet.
- Visual: cells reuse `.byte-cell` CSS; row labels use a `.port-label`
  class (left-aligned, fixed-width). Separator line between inputs and
  outputs.
- Byte-format toggle (`useByteFormat`) honored.

**Pass/fail gate:**
- New jsdom test `tests/port-flow-view.test.tsx`:
  - 5-way `add-mod-32` frame renders 5 input rows + 1 output row.
  - Each row's cell count matches the port's byte length.
  - Port labels render with the canonical names (`operand0`..`operand4`, `output`).
- Manual smoke (small, in dev): scrub onto an `xor@1` frame in
  SHA-256, see 3 input rows of 4 cells each + 1 output row.
- Existing inspector dispatch unchanged for legacy frames (AES /
  Speck / Serpent / DES traces unaffected — visual smoke per cipher).
- Bundle delta: new component + dispatch branch. Expect <3 KB raw.

**Sequencing note:** consumes 2.9a's frame shape. Must land before 2.9c.

### 2.9c — ProvenanceSource port-cell variant

**Goal:** widen the provenance source union with port-cell kinds and
wire hover signal plumbing through `PortFlowView`. No per-primitive
provenance fns yet.

**Scope:**
- Extend `ProvenanceSource` in `src/ui/provenance/registry.ts`:
  ```ts
  export type ProvenanceSource =
    | { kind: "before-cell"; index: number; label?: string }
    | { kind: "aux-cell"; auxName: string; index: number; label?: string }
    | { kind: "port-input-cell"; portName: string; index: number; label?: string }
    | { kind: "port-output-cell"; portName: string; index: number; label?: string };
  ```
- `useProvenanceHover` store gains derived helpers:
  - `portInputHighlights(portName) → ReadonlySet<number>`
  - `portOutputHighlights(portName) → ReadonlySet<number>`
- `PortFlowView` (from 2.9b) attaches `onMouseEnter` to each output
  cell; calls `lookupProvenance(frame.stepType)` and sets the hover
  signal with port-cell sources. Reads the signal on each input row
  to outline contributing cells.
- Mouse leave clears the hover signal (existing pattern).
- No changes to `lookupProvenance` itself; the fn registry already
  returns `readonly ProvenanceSource[]` — the new variants are
  data-side additions.

**Pass/fail gate:**
- Existing aes / serpent / des provenance fn callers unchanged
  (`before-cell` / `aux-cell` still the only sources they emit).
- Unit test: hover signal accepts `port-input-cell` sources; derived
  helpers return the correct sets per portName.
- jsdom test in `tests/port-flow-view.test.tsx`: simulating
  `mouseenter` on an output cell with a stubbed provenance fn lights
  up the asserted input cells.
- TS strict / biome / vitest all green.

**Sequencing note:** consumes 2.9b's renderer; widens
`ProvenanceSource` so 2.9d can emit the new variants.

### 2.9d — Per-primitive provenance fns + registration

**Goal:** register provenance fns for the port-native step types
reached by SHA-256.

**Scope:**

New module `src/ui/provenance/port-native.ts` (or `sha-256.ts` if the
fns are SHA-256-specific — most aren't; the primitives are
cipher-agnostic, so the generic name is better and reusable for AES
rebuild later).

The 16 port-native step types reached by SHA-256, with the provenance
shape each gets:

| Step type | Provenance shape |
|---|---|
| `xor@1`, `and@1` | Output cell i ← all operand cells at index i (same-position N-way). |
| `not@1` | Output cell i ← input cell i (same-position). |
| `add-mod-32@1` | Output cell i ← all operand cells at index `i mod 4` and adjacent indices for carry propagation. Honest call: highlight all operand cells in the same 4-byte word (mod-32 carries can propagate across all 4 bytes). |
| `rotate-bits-right@1` | Output bit i ← input bit `(i + rotateBy) mod wordBits`. Byte-level approximation: highlight the source byte(s) that contain the contributing bits. |
| `shift-bits-right@1` | Output bit i ← input bit `i + shiftBy` (or 0 if shifted in). Byte-level approximation similar to rotate. |
| `byte-slice@1` | Output cell i ← input cell `i + start`. One-to-one with offset. |
| `split-bytes@1` | Output port `outputN` cell i ← input cell at the running offset. Use a per-output offset table from params.widths. |
| `concat@1` | Output cell i ← `operandK` cell `i - prefixSum(widths, K)` for the operand K that contains byte i. |
| `bytes-to-state@1` | Output cell i ← input cell i (same-position; only shape changes). |
| `state-to-bytes@1` | Output cell i ← input cell i (same-position; only shape changes). |
| `aux-load-bytes@1` | Output cell i ← aux cell i of the named aux (when available). Existing aux-cell source variant reused. |
| `constant-load@1` | No source — output cells are spec-bound constants. Allowlist (the constant IS the source). |
| `pad-with-byte@1` | Output prefix cells ← input cells same-position; output suffix cells are "injected" (no source). Use a label `"injected"`. |
| `append-be64-length@1` | Output prefix (input bytes) ← input cells same-position; output suffix 8 bytes are length-derived (no source — label `"length"`). |
| `generic.aux-load@1` | Reuse `aux-cell` source variant. Already covered by today's aes/serpent fns' aux pattern. |
| `generic.state-to-aux-bytes@1` | Aux-cell on the source side; bridge step. May be cleaner to allowlist if the provenance is "state input cell i → aux output cell i" — same-position trivial. |

Wire all in `src/ui/provenance/index.ts::initProvenanceRegistry`.

**Pass/fail gate:**
- New `tests/provenance-port-native.test.ts`:
  - One test per fn — hover output cell i, assert the returned
    sources match the expected port + index list. Mock-frame
    construction with synthetic `portInputs` / `portOutputs`.
- The `tests/provenance-registry-contract.test.ts` widening in 2.9e
  passes against this batch.
- Existing `tests/provenance-aes.test.ts` /
  `tests/provenance-serpent.test.ts` etc. unchanged.

**Sequencing note:** depends on 2.9c's source variants existing.

### 2.9e — Contract test widen + browser smoke + close

**Goal:** widen the contract test so port-native steps are inventoried;
manual browser smoke confirms end-to-end pedagogy; close Slice 2.9.

**Scope:**
- Widen `tests/provenance-registry-contract.test.ts`'s inventory to
  include port-native registrations (those with `kind: "ported"` and
  no `shapeContract`). Today the test filters by
  `shapeContract.input === "matrix4x4-bytes" | "bytes"`; widen to also
  include any port-native step type that appears in any shipped spec.
- Update `PROVENANCE_NO_OP_ALLOWLIST` to remove the stale Slice 2.6b
  entries (`sha2.message-schedule-step@1`, `sha2.compression-round@1`,
  `sha2.final-add@1`) — those step types no longer exist post-2.6d.
- Add explicit allowlist entries for the SHA-256 port-native primitives
  whose 2.9d treatment is "no provenance" (today the candidates are
  `constant-load@1`, possibly `generic.state-to-aux-bytes@1`).
- Manual browser smoke (the user runs at `http://localhost:5173`):
  1. Boot SHA-256 selector → digest of "abc" matches FIPS §A.1 KAT.
  2. Scrub onto a σ1 `xor@1` frame inside `round.0` → see 3 input
     rows of 4 cells + 1 output row. Hover output cell 0 → cell 0 in
     all 3 input rows highlights.
  3. Scrub onto a T1 `add-mod-32@1` frame → see 5 input rows
     (operand0..4) + 1 output. Hover output cell 0 → contributing
     cells highlight across all 5 input rows.
  4. Scrub onto a `rotate-bits-right@1` frame → see 1 input + 1
     output. Hover output cell 1 → source byte(s) per the rotation
     constant.
  5. Scrub onto a `bytes-to-state@1` frame → port view replaces with
     the matrix dispatch (this is the one shape-changing port-native
     step; legacy dispatch wins).
  6. Switch to AES — visual unchanged (legacy ciphers untouched).

**Pass/fail gate:**
- `npm run check` GREEN.
- Contract test passes — every port-native step type in shipped specs
  is either registered or allowlisted with a clear rationale.
- Manual smoke 1-6 all green.
- Update `docs/plans/universal-port-phase-2-slices.md`'s Slice 2.9
  section to reference this file + record GREEN status.

**Sequencing note:** terminal. Closes Slice 2.9.

## What gets preserved vs. fades

| Preserved | Fades |
|---|---|
| Existing `before-cell` / `aux-cell` provenance variants (AES, Serpent, DES fns unchanged) | Stale Slice 2.6b allowlist entries (`sha2.message-schedule-step@1`, etc.) — these step types don't exist post-2.6d |
| `lookupProvenance` registry shape and import pattern | The contract test's `shapeContract`-only inventory filter — widened to include port-native types |
| `useProvenanceHover` store (extended, not replaced) | |
| MatrixView / BytesView hover handlers for legacy frames | |

## Deferred for future planning

- **Overlay surface for famous identities (T1, Σ1, σ1, Ch, Maj, etc.).**
  Cells-plus-provenance is what 2.9 ships. The overlay system — a
  "bigger picture" view that renders formula chips, labeled state
  rows, or matrix overlays alongside port cells — is deferred because
  (1) advisor verdict 2026-05-27: cells deliver ~80% of pedagogical
  value, overlays earn their architecture only for ~10 famous-identity
  moments in SHA-256; (2) the JSX-vs-structured-data choice should be
  informed by 2-3 actual cipher overlays' needs (SHA-256 + AES + DES
  want genuinely different shapes), not pre-decided; (3) hierarchical
  frames (per universal-port-dataflow plan "Deferred for future
  planning" item iii) materially affect overlay design — a rolled-up
  container leaf's overlay differs from a primitive's. Use cells for a
  few sessions, note where pedagogy feels thin, then decide overlay
  shape with concrete examples in hand. Probable new plan file:
  `docs/plans/inspector-overlays.md`.

- **`layout: "matrix-cm-4x4"` rendering inside port rows.** Today's
  2.9b ships BytesView-style cell rows for every port. When AES rebuild
  (Phase 3) introduces `byte-substitute@1` / `gf-matrix-multiply@1`
  with `layout: "matrix-cm-4x4"` on a 16-byte port, each port row could
  switch to a MatrixView rendering. Not needed for SHA-256 (no
  matrix-shaped ports). Add when Phase 3 wires the first AES-shaped
  port.

- **Hierarchical-frame port overlays.** When hierarchical trace lands
  (deferred per the parent plan), a rolled-up container leaf will need
  its own port surface (the container's "in" and "out" boundary
  ports). 2.9b's `PortFlowView` should compose recursively — each
  level of hierarchy renders one vertical stack of ports. Sequencing:
  no work until hierarchical frames are scoped.

- **User-authored overlays (Phase 4f compose-and-save).** Not a stated
  deliverable of the universal-port-dataflow plan today. If it becomes
  one, the overlay-surface decision (JSX for shipped ciphers, structured
  for user-composed, hybrid) re-opens at that point.

## Pointers

- Parent plan: `docs/plans/universal-port-dataflow.md` — universal
  port-based dataflow plan; Slice 2.9 belongs to Phase 2.
- Sibling Phase 2 plan: `docs/plans/universal-port-phase-2-slices.md`
  — original three-bullet Slice 2.9 sketch; this file supersedes that
  section.
- SHA-256 spec: `src/ciphers/sha-256.ts` — the corpus 2.9 will be
  measured against.
- Existing provenance pattern: `src/ui/provenance/registry.ts` +
  `index.ts` + per-cipher files (`aes.ts`, `serpent.ts`, `des.ts`)
  — 2.9c and 2.9d extend this without breaking the existing pattern.
- Empirical probe results: the scratch test from 2026-05-27 confirmed
  16 of 17 port-native step types in the SHA-256 trace emit
  `stateBefore === stateAfter` frames. Deleted post-confirmation; see
  this doc's "Context" section for the summary.
- Advisor consults: two during the 2026-05-27 session — first on
  scope/option-pick (recommended Option B + verify-the-gap-first),
  second on overlay-surface scope creep (recommended deferring
  overlays entirely from 2.9 and shipping cells first).
