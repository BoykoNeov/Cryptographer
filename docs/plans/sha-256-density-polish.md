# SHA-256 density polish

Follow-up plan for the manual-smoke findings on 2026-05-26 that did not
fit the same-day Slice 2.8 close. Three Phase-2-density issues surfaced
*because* SHA-256 is the first reachable port-native cipher with 1829
leaves — they aren't caused by Slice 2.8's narration work, but they
make the SHA-256 experience worse than the AES/Speck/Serpent baseline.

## Context

Slice 2.8 (narrationOverride for every SHA-256 leaf) shipped today.
Manual smoke confirmed the narration prose is correct where checked
(`s_3`, `Ch`, `σ1`, `Σ1` rotation chains all matched FIPS 180-4 with
no errors). The smoke ALSO surfaced three classes of UX bugs that all
trace back to "SHA-256 is dense and port-native, the existing UI was
built around AES-scale legacy specs":

1. **Param panel raw-JSON fallback** for port-native primitives. Every
   `rotate-bits-right@1`, `xor@1`, `aux-load-bytes@1`, `byte-slice@1`,
   `add-mod-32@1` leaf — i.e. most of SHA-256 — renders the
   `ParamEditor.tsx:109` fallback that dumps params as raw JSON
   (`{"wordBits": 32, "bits": 17}`) with the prose "no editor for step
   type X (raw params view)". That's jarring and has no pedagogical
   value — the user already knows from the narration prose what the
   leaf does; the raw JSON below the description undermines the
   pedagogical surface.

2. **Graph layout obstructions on SHA-256's preamble row**. After the
   manual smoke + investigation probe (deleted; commit `47d12c7`'s test
   list captures the trial), several preamble-row leaves
   (`H-constant`, `init-working-vars`, `K-to-aux`, `H-to-aux`,
   `W-publish`) flow as siblings on a single horizontal row. Three
   distinct symptoms:
   - **Arrows behind chips:** `msg-schedule → W-publish` (state edge,
     confirmed via probe to exist), arrows from `W-publish` and
     `K-to-aux` to their consumers, all route behind H-row chips. User
     report: "message schedule ends with no arrows leading out from
     it". NOT a derivation bug — the edges exist; layout routes them
     under other chips.
   - **Long H-to-aux arrow:** the aux edge from `H-to-aux` to
     `final.fetch-H` (which lives 64+ rounds away) is rendered as a
     single long arrow passing behind every compression-round chip
     between them. Replication helps but doesn't eliminate the eyesore
     on the first source-end of the edge.
   - **Msg-schedule chip discoverability:** Even with the outgoing
     arrow drawn, the collapsed `msg-schedule` chip reads as a
     dead-end visually because the arrow is invisible.

3. **Narration prose density (deferred from this session's same-day
   uplift).** Today's commit uplifted 10 high-impact leaves to the
   `s_3` level (σ1/σ0/Σ1/Σ0/Maj combines, new_a/new_e, K_t and W_t
   fetch+slice, fetch-p2, K-to-aux, H-to-aux). The remaining "middle
   term" and "last term" rotation/AND leaves (~30 of them) still have
   minimal detail ("Middle term of `σ0(x) = ...` (FIPS 180-4
   §4.1.2)"). That's consistent with their role (you don't need full
   intuition on three near-identical rotation leaves) but a future
   pass could either:
   - **(a)** Add one-sentence "what bit positions this affects" per
     rotation leaf.
   - **(b)** Roll the three rotation leaves into one collapsed
     "compute three rotations" frame in linear mode so the eye lands
     on the combine leaf as the unit of explanation.

## Three sub-slices, can ship independently

### Slice S1 — port-native ParamEditor blocks — SHIPPED 2026-05-26 (manual browser smoke pending)

**Outcome.** 7 new ParamEditor block components + 2 extensions to existing
matches, plus a coverage gate test (mirrors
`tests/cross-mode-mirror-coverage.test.tsx`). The literal string "no editor
for step type" no longer renders on any leaf in any shipped cipher/hash
spec.

**What landed:**

- **Editable blocks (wrong-value-produces-divergent-trace pedagogy):**
  - `BitOpBlock` — `rotate-bits-right@1` / `shift-bits-right@1`. Editable
    `bits` integer + operation label + read-only `wordBits`.
  - `ByteSliceBlock` — `byte-slice@1`. Editable `offset` + `length`;
    read-only `sourceByteLength`.
  - `AuxLoadBytesBlock` — `aux-load-bytes@1`. Editable `auxName` via the
    existing `AuxNameInput`; read-only `byteLength`.
  - `PadWithByteBlock` — `pad-with-byte@1`. Editable `padByte` (ByteCellInput)
    + `padTarget` (IntInput); read-only `blockSize`.
- **Read-only blocks (wrong-value-throws-at-runtime):**
  - `InputCountBlock` — `xor@1` / `and@1` / `add-mod-32@1` / `concat@1`.
    Operation label + read-only `inputCount`. Editing `inputCount` without
    re-wiring downstream throws "input port inputN not wired" — that's a
    hard-error path with no pedagogical signal, so the param is locked.
  - `SplitBytesBlock` — `split-bytes@1`. Same rationale as InputCountBlock;
    read-only widths chip row.
  - `ConstantLoadBlock` — `constant-load@1`. Read-only `bytes` as a hex
    dump inside a collapsed `<details>`. SHA-256's K table (256 bytes) and
    H table (32 bytes) display cleanly without dominating the editor
    panel.
- **Match extensions (no new component):**
  - `NoParamsBlock` extended to match `not@1` / `state-to-bytes@1` /
    `bytes-to-state@1` / `append-be64-length@1` with type-specific blurbs.
  - `StateToAuxBlock` match widened to include `generic.state-to-aux-bytes@1`
    (same single-`auxName` param shape).
- **Coverage gate:** `tests/param-editor-coverage.test.tsx` walks every
  shipped cipher (9) + hash (1) spec and asserts no leaf renders the
  raw-JSON fallback. 10 tests; encrypt-mode scope documented in the test
  header (decrypt-only unpad steps already have blocks; this gate doesn't
  cover them).
- **CSS:** `.int-input`, `.param-readonly-array` / `.param-readonly-cell`,
  `.param-hex-dump` added to `app.css`. Mirrors the colorway and font
  rhythm of `.aux-name-input` / `.param-scalars`.
- **Editability rule (codified in the in-file comment block):** "read-only
  when edit-without-rewire produces a runtime throw; editable when it
  produces wrong-but-defined output." This is the existing precedent from
  `BlockSizeBlock`, `KeyExpansionBlock`, `SpeckKeyScheduleBlock` — the
  polish plan's "default to editable" framing is overridden by the
  precedent for params where edit-without-rewire is a hard-error path
  (`inputCount`, `widths`, `byteLength`).

**Counts:** suite 2347 → 2357 (+10). Bundle 676.10 → 683.31 KB raw / 199.29
→ 200.67 KB gzipped (+7.21 KB / +1.38 KB — 7 new components + CSS).

**Smoke pending.** The coverage test pins the negative ("no fallback string"
never appears) but cannot catch (a) blocks rendering empty/broken-looking
for default param values, (b) the hex-dump CSS rendering the 256-byte K
table awkwardly, (c) IntInput keyboard commit paths (Enter/Escape/blur).
30-second manual pass: SHA-256 → scrub a `rotate-bits-right` leaf (Bits
field editable), an `xor` leaf (Input count read-only), the K-constant
leaf (expand hex dump). Same close-gate pattern as Slice 2.8.

### Slice S1 — port-native ParamEditor blocks (original plan, preserved)

**Scope:** add `ParamEditor` blocks for the SHA-256-shaped port-native
primitives so the param panel renders prose + read-only display
(matching the existing `aes.sub-bytes` editor pattern, not the raw-JSON
fallback). Top of the list:

- `rotate-bits-right@1` / `shift-bits-right@1` — single editable
  `bits` integer, read-only `wordBits` (always 32 for SHA-256).
- `aux-load-bytes@1` — read-only `auxName` string + read-only
  `byteLength` int.
- `byte-slice@1` — editable `offset` + `length` integers.
- `add-mod-32@1` / `xor@1` / `and@1` — read-only `inputCount`.
- `not@1` — empty params, render an explanatory blurb instead.
- `state-to-aux-bytes@1` / `aux-load@1` — `auxName` (read-only after
  spec saved), `bytes` for `aux-load@1` (large readonly hex dump).
- `bytes-to-state@1` / `state-to-bytes@1` — empty params, explanatory
  blurb.
- `split-bytes@1` — editable `widths` int array (small grid editor).
- `constant-load@1` — `bytes` (large readonly hex dump).

**Pass/fail gate:** scrubbing every SHA-256 leaf in the linear mode
shows EITHER a meaningful editor (when params have user-tweakable
knobs) OR a read-only display with prose context (when params are
structural). The literal string "no editor for step type" should never
render on a registered step type.

**Cost estimate:** ~10 new ParamEditor blocks, each ~30 lines. Likely
one commit per editor or a single batch commit. No infrastructure work
— just filling the existing block-registration surface.

**Out of scope:** the SAME-day pedagogical concern over which params
should be USER-EDITABLE (e.g. should `bits: 17` on a σ1 rotation be
editable? Editing breaks FIPS conformance — but that's the point of
the "tinker with the cipher" thesis). Default to "render the editor,
let users break things; rely on KAT tests + visible trace to expose
the break." Locking specific params is a future concern.

### Slice S2 — graph preamble layout improvements

Three obstruction symptoms above; root cause is shared
("H-row siblings on the same horizontal row obstruct sibling-arrow
visibility"). Advisor framing 2026-05-26: the three symptoms have
three distinct root causes, the right shape is a hybrid not a
pick-one, and option (d) below addresses a real gap the port-native
migration left.

#### S2(d) — extend auxOnlyRootIds for port-native pure sources — SHIPPED 2026-05-26

**The gap.** `auxOnlyRootIds` only lifted root leaves whose
`shapeContract.input === "any"` (legacy/lifted-ported entries:
`aes.key-expansion@1`, `generic.iv-load@1`, `generic.aux-load@1`,
`generic.state-to-aux-bytes@1`). Port-native primitives
(`constant-load@1`, `aux-load-bytes@1`) omit `shapeContract` entirely
— their surface is described by `PortContract` — so the heuristic
skipped them and the H-row preamble half-lifted: `K-to-aux` /
`H-to-aux` / `W-publish` floated up via the legacy path, but
`H-constant` (a pure 32-byte constant emitter) stayed pinned to the
spine alongside `init-working-vars` (the actual state writer).

**The fix.** Widen the `auxOnlyRootIds` memo with a second predicate
— three conjuncts, all required:

1. Registration's `kind === "ported"`.
2. `meta` declares neither `stateInputPort` nor `stateOutputPort` —
   the step neither reads nor writes the spine state variable.
3. The spec leaf declares no `portInputs` — it's a true source in the
   spec-edge graph, not a port-chain consumer.

The first two conjuncts together capture all port-native step types
that don't touch the runtime state variable. The third (added in a
same-day tightening after advisor surfaced the blind spot) excludes
port-chain consumers like `pad-with-byte@1` and `append-be64-length@1`
— port-native with no state-port meta, but they declare spec-level
`portInputs` (`pad`'s input wires to `plaintext-source.output`).
Without the third conjunct the SHA-256 spec's `pad` and `length-append`
would have incorrectly lifted to the top row alongside the actual
constant emitters.

Final captured set on SHA-256: `H-constant` (`constant-load@1`, no
`meta` at all, no `portInputs`) and `aux-load-bytes@1` leaves (legacy
lift path also applies). Excluded: state bridges (`bytes-to-state@1`
has `stateOutputPort`; `state-to-bytes@1` has `stateInputPort`),
port-chain consumers (`pad`, `length-append`).

**Test:** `tests/graph-view-sha256-preamble-lift.test.tsx` (5 tests).
Pins `H-constant` lifts to the same y as `H-to-aux` (legacy lift
reference); pins both `init-working-vars` and `seed-schedule`
(state writers) stay strictly below the lifted row; pins `pad`
and `length-append` (port-chain consumers) stay on the spine.

**Counts:** suite 2357 → 2362 (+5). Bundle 683.31 → 683.58 KB raw /
200.67 → 200.77 KB gzipped (+0.27 KB / +0.10 KB).

**Smoke pending.** This is the "verify-then-decide" step the advisor
asked for before pulling in (b) or (c). Open SHA-256 in the graph
view, check the H-row: `H-constant` should now sit at the top row
alongside `H-to-aux`, and the spine should flow only through state
writers. Then re-evaluate which of the three smoke symptoms persist
— a clean preamble row may make the remaining issues easier to
characterize, or may resolve some of them outright.

#### S2(d) smoke re-evaluation — 2026-05-26

**Outcome:** S2(d)'s lift worked correctly (H-constant lifted to top
row; pad, length-append, seed-schedule, init-working-vars stayed on
spine). But the smoke surfaced that the original three symptoms were
**misdiagnosed as layout problems** — they're actually a **graph
derivation gap**.

**The probe.** A test that dumped every rendered `data-edge-key`
showed:

- `H-constant edges: []` — no outgoing edges at all
- `final.fetch-H edges: []` — no outgoing edges
- `final.split-wv edges: []` — should have 8 (one per output port)
- `final.split-H edges: [final.split-H|final.s0|state|state]` — only 1 visible, should have 8 outgoing port-flow edges
- `final.state-in edges: [final.state-in|final.split-wv|state|state]` — only the spurious "state" edge from consecutive-siblings inference

**Diagnosis.** `grep -rna "portInputs" src/core/` confirms `portInputs`
is consumed by `runtime.ts` (execution) and `spec-shapes.ts`
(validation), but **NOT by `graph.ts`'s `deriveAuxGraph`**. Slice 2.6a
introduced `portInputs` and explicitly touched `graph.ts` only to add
new warning kinds — the edge-emission half was never shipped.

The visible "state" edges in the final-add area come from the legacy
"consecutive-siblings get a state arrow" rule, even though the real
relationship is port-flow. So:

1. ~22 real port-flow edges (`H-constant → init-working-vars`,
   `fetch-H → split-H`, `split-wv.output_i → s_i`,
   `split-H.output_i → s_i`, `s_i → assemble`, `assemble → out`) are
   missing from the graph entirely.
2. The few visible "state" edges in port-native scopes are
   mislabeled — they're actually port-flow.

**Original (b)/(c)/(a) options are obsolete.** None of them address
the derivation gap. Re-scoped as three new sub-slices below.

#### S2(e) — port-flow edge derivation — SHIPPED 2026-05-26

**Outcome.** `inferPortEdges(spec)` walks every leaf's `portInputs`
and emits a `kind: "state"` edge `{ from: binding.node, to: leaf.id,
auxKey: PORT_FLOW_AUX_KEY }` per binding. Port-flow edges share `kind:
"state"` with legacy passthrough state edges so the renderer paints
both as the cipher's primary spine — but a DISTINCT `auxKey:
"port-flow"` sentinel discriminates them so `dropAuxOnlyStateEdges`
can filter legacy passthroughs from lifted aux-only roots without
also dropping the real port-flow handoffs.

**Discriminator was load-bearing.** Initial implementation used a
shared `STATE_AUX_KEY` and was caught by the manual browser smoke:
`H-constant`'s outgoing edge to `init-working-vars` (port-flow) was
being dropped by `dropAuxOnlyStateEdges` because the filter saw
`H-constant` in `auxOnlyRootIds` (lifted via S2(d)) and dropped every
`kind: "state"` edge touching it. Same fate would await
`final.fetch-H → final.split-H` and other port-flow edges from any
future lifted aux-only root. The auxKey discriminator (added after
the smoke surfaced the issue) lets the filter discriminate by
provenance.

**Test:** `tests/graph-port-edge-derivation.test.ts` (9 tests). Pins
`final.s_0` has exactly 2 incoming edges (`split-wv.output0`,
`split-H.output0`); `final.assemble` has 8 incoming edges (one per
word); `H-constant → init-working-vars` edge exists; all port-flow
edges from a port-native source carry `kind: "state"` + `auxKey:
"port-flow"`.

#### S2(f) — per-edge state-spine suppression on port-native consumers — SHIPPED 2026-05-26

**Refined scope.** The original plan (whole-spec suppression via
`requiresPortedDispatch(spec, registry) === true`) was implemented
first and caught by the same manual browser smoke: it ALSO suppressed
legitimate state-thread handoffs into lifted-legacy ported consumers
(W-publish, init-working-vars, the 64 per-round `state-in`/
`state-out` pairs). Result: the visible round chain
`init-working-vars → round.0 → round.1 → … → round.63 → final.state-in`
disappeared from the SHA-256 graph view. The whole-spec gate violated
the assumption it was built on — that "port-native spec" implies
"every consumer reads inputs via portInputs." SHA-256's lifted-legacy
ported leaves (bytes-to-state, state-to-aux-bytes, state-to-bytes)
still consume state via the state-thread; the whole-spec gate broke
those handoffs.

**Per-edge gate.** `inferStateEdges(spec, registry?)` now builds a
`skipStateEdgeTo: Set<string>` of leaf ids that should NOT receive an
inferred consecutive-siblings state edge — three flavors of
"doesn't read state via state-thread":
1. Pure port-native registration (`kind: "ported"` AND `meta` absent).
2. Lifted-legacy ported registration whose `meta.stateInputPort` is
   undefined (pure source like `aux-load-bytes@1`).
3. Lifted-legacy ported registration whose `meta.stateInputPort`
   exists but the spec leaf declares `portInputs[stateInputPort]`
   (per-port override — the explicit port-flow binding represents
   the real input).

`emitChain` skips emitting edges to ids in this set. Without a
registry the set stays empty (backward-compat for the ~110 existing
callsites). Containers aren't in the set — group/iterate/feistel/
for-each-subgraph consumers continue to participate in the state-
spine.

**Test:** the same `tests/graph-port-edge-derivation.test.ts` pins:
- Spurious chain through `final.s_0 → … → final.s_7` suppressed.
- `final.split-wv → final.fetch-H` and `final.assemble → final.out`
  spurious edges suppressed.
- `init-working-vars → round.0.state-in` KEPT.
- `round.0.state-out → round.1.state-in` and the analogous
  `round.62 → round.63` inter-round handoffs KEPT.
- `round.63.state-out → final.state-in` KEPT.
- AES-128 ECB byte-identical between `{ registry }` and no-opts
  calls (legacy specs have no port-native leaves → skipStateEdgeTo
  empty → behavior unchanged).

**Counts:** suite 2362 → 2371 (+9). Bundle 683.58 → 684.39 KB raw /
200.77 → 201.02 KB gzipped (+0.81 KB / +0.25 KB).

**Pre-existing follow-up surfaced by the smoke (NOT a S2 regression).**
`msg-schedule → W-publish` state-spine edge is emitted by
`inferStateEdges` (msg-schedule is a container, not in skipStateEdgeTo;
W-publish reads state-thread, not in skipStateEdgeTo either) — but
then DROPPED by `dropAuxOnlyStateEdges` because W-publish is in
`auxOnlyRootIds` (Path 1: `shapeContract.input === "any"`). The
filter is too aggressive for state-thread INCOMING edges into
aux-only roots that have a real state-writing predecessor. This is
the original plan's symptom #3 ("msg-schedule looks like a dead
end") — the plan misdiagnosed it as a layout issue. The filter
overreach predates S2(e)/(f) and survives them unchanged. Filed as
S2(h) below.

#### S2(g) — polymorphic-state-shape dead-code cleanup — SHIPPED 2026-05-26 (audit-only)

**Outcome.** The audit IS the deliverable. `graph.ts` has zero
references to `BigIntState`/`BitVecState`/`bigint`/`bitvec` — the
plan's primary hypothesis ("dead code at graph-derivation level")
confirmed. Graph derivation is shape-agnostic: it walks aux maps +
port bindings, neither of which discriminates on `State.shape`.
The single piece of genuinely dead code surfaced — `makeBitVec` in
`src/core/state/bitvec.ts`, exported with zero importers in `src/`
or `tests/` — was deleted; `cloneBitVec` stays as the live branch
the universal `cloneState` switch dispatches into.

**The audit (recorded here so the future Phase 5 reader inherits
the scope rather than redoing this walk):**

- `src/core/graph.ts` — ZERO references. No polymorphic branches.
- `src/core/state/bitvec.ts::makeBitVec` — DEAD, deleted in this
  slice (6 lines + 1 blank).
- `src/core/state/bitvec.ts::cloneBitVec` — LIVE (consumed by
  `clone.ts`'s switch).
- `src/core/port-projection.ts` lines 297-308, 322-339, 362-383,
  467-486 — LOAD-BEARING. Pinned by
  `tests/port-projection-matrix-array-roundtrip.test.ts:150-172`
  (the bitvec encode-as-bytes contract + the bigint deferral
  throw). The `readBigintEncoding` Phase-1 stub (line 479) that
  returns `{}` is a deliberate anchor for the future encoding
  decision; its empty-object spread at the call site (line 149) is
  intentional. Leave both in place.
- `src/core/types.ts` — the `State` union with `BitVecState`/
  `BigIntState` variants. Schema-breaking to remove (saved
  `CipherDocument` JSON may reference these shapes). PHASE 5.
- `src/core/document-schema.ts:126` — `StateShapeSchema` Zod enum
  including `"bitvec"`/`"bigint"`. Schema-breaking. PHASE 5.
- `src/core/state/clone.ts` lines 12-15 — `cloneState` switch
  cases. Tied to the union. PHASE 5.
- `tests/state-shape-contracts.test.ts:50-63` — `VALID_INPUT_VALUES`
  and `VALID_OUTPUT_VALUES` enumerate `"bitvec"`/`"bigint"`. Tied to
  the union typings. PHASE 5.
- `src/ui/components/GraphView.tsx:7212-7218` —
  `formatStateOneline` cases. Display surface. PHASE 5.
- `src/ui/components/StepPalette.tsx:66-67` — `SHAPE_LABELS` map
  entries. Display surface. PHASE 5.
- 9 test files under `tests/runtime-ported-dispatch-*.test.ts` —
  each carries a `case "bitvec":` arm in a shape-discriminator
  switch (helper for ported-dispatch frame comparison). Tied to
  the union. PHASE 5.

**Phase 5 deprecation scope (recorded for the future reader).**
Removing `BitVecState`/`BigIntState` is a coordinated migration:
(a) bump the document schema (`schemaVersion`) and write a migration
that errors / rewrites any saved `CipherDocument` referencing
these shapes; (b) remove the union variants from `types.ts`;
(c) remove the dispatch arms from `clone.ts`, `port-projection.ts`,
`GraphView.tsx`, `StepPalette.tsx`; (d) remove the
`port-projection-matrix-array-roundtrip.test.ts` cases that pin the
current contract; (e) shrink `VALID_INPUT_VALUES`/
`VALID_OUTPUT_VALUES` in `state-shape-contracts.test.ts` and the
shape-discriminator switches in `runtime-ported-dispatch-*.test.ts`;
(f) drop `src/core/state/bitvec.ts` entirely (`cloneBitVec` dies
with the union variant). Bundle savings will be modest — the
real value is removing a polymorphic surface that no shipped cipher
exercises, per the user's Rule 2.

**Counts:** suite 2371 → 2371 (no test changes; `makeBitVec` had no
test). Bundle 684.39 → 684.39 KB raw / 201.02 → 201.02 KB gzipped
(6 lines deleted is below the rounded-KB display precision).

#### S2(h) — dropAuxOnlyStateEdges asymmetric endpoint sets — SHIPPED 2026-05-26

**Refined scope** during the session opener: option (a) as literally
stated in the deferred plan doesn't fix the bug. After S2(f) suppresses
W-publish's outgoing edges (W-publish → K-to-aux dropped at emit because
K-to-aux is in `skipStateEdgeTo`), W-publish has zero outgoing legacy
state edges in the pre-filter graph — option (a)'s symmetric "to is a
true sink" check would STILL drop `msg-schedule → W-publish`. The
discriminator option (a) needs isn't "has outgoing edges" but "actually
reads the state thread at runtime." That's option (c) — `meta.stateInput
Port` declared by the registration — applied per-endpoint, asymmetric.

**The fix.** `dropAuxOnlyStateEdges(graph, auxOnlyIds, auxOnlySinkIds?)`
takes an optional third parameter. The from-side rule is unchanged
(every aux-only root contributes identity-passthrough state on its
outgoing edge — always misleading). The to-side rule is now narrowed
to the smaller `auxOnlySinkIds` set: aux-only roots whose registration
has no `meta.stateInputPort`. SHA-256's W-publish (`generic.state-to-
aux-bytes@1`, has `stateInputPort: "state"` per `stateToAuxBytesMeta`)
sits in the wider set (lifts to the preamble row) but NOT the narrower
set (so its incoming `msg-schedule → W-publish` spine edge survives).

The default `auxOnlySinkIds = auxOnlyIds` preserves pre-S2(h) symmetric
behavior for the ~3 existing callsites in `tests/replicate-fanout.test.ts`
that don't differentiate. GraphView passes both sets explicitly via two
parallel memos (`auxOnlyRootIds` for the wider set + layout-lift,
`auxOnlyRootSinkIds` as a registry-driven subset for the narrower
filter).

**Why the asymmetry is robust under legacy ciphers.** Every AES/Speck/
Serpent/DES key-schedule registration has no `stateInputPort` (their
executors pass state through untouched — `aes.key-expansion@1`'s meta
explicitly omits it; same for Speck/Serpent/DES). So the narrower set
equals the wider set on those specs, and the asymmetric filter
collapses to the original symmetric behavior. `tests/drop-aux-only-
state-edges-asymmetric.test.ts`'s "no change vs. pre-S2(h) symmetric
filter behavior" case pins byte-equal output of the two-arg vs.
three-arg call on AES-128 ECB.

**Tests:**
- `tests/drop-aux-only-state-edges-asymmetric.test.ts` (4 tests) — pins
  the end-to-end behavior on real specs:
  (1) SHA-256 `msg-schedule → W-publish` survives.
  (2) W-publish is in the wide set but NOT the narrow set
      (heuristic-and-bug pinned together).
  (3) AES `key-expansion → split-blocks` outgoing spine edge is still
      dropped (from-side rule preserved).
  (4) AES-128 ECB byte-equal edges between two-arg and three-arg
      filter calls (no regression on legacy specs).
- `tests/replicate-fanout.test.ts` — pre-existing bidirectional test
  RENAMED ("to-side: when terminal-aux is in BOTH source AND sink sets
  (non-reader), its incoming spine edge is dropped") + comment block
  explaining the S2(h) rescoping. Two new synthetic tests pin the
  W-publish-analog (kept when excluded from sink set) and key-
  expansion-analog (dropped via from-side rule even when in both sets)
  cases.

**Counts:** suite 2371 → 2377 (+6). Bundle 684.39 → 684.69 KB raw /
201.02 → 201.11 KB gzipped (+0.30 KB / +0.09 KB).

**Smoke pending.** The vitest run pins the edge derivation + filter
predicate; it does NOT confirm the user-visible rendering. Manual
30-second pass: open SHA-256 in the graph view, locate `msg-schedule`
in the preamble row, confirm an arrow now leaves it toward `W-publish`
(it should land at the W-publish chip on the same preamble-row top).
AES sanity: open AES-128 in the graph view, confirm `key-expansion` is
still lifted to its own row WITHOUT a state arrow into `initial.add-
round-key` (only the aux fan-out arrows + the plaintext-pill arrow
to the first state consumer remain). If both check out, S2(h) is
closed.

**Original symptom #3 from the Context block — now resolved.** "Msg-
schedule chip discoverability: even with the outgoing arrow drawn, the
collapsed `msg-schedule` chip reads as a dead-end visually because the
arrow is invisible." Post-S2(h), the arrow IS drawn, terminating at
W-publish. The original misdiagnosis ("layout problem hiding arrow
behind chips") was the rabbit hole; the actual fix was filter
overreach.

#### S2(i) — port-flow state edges count toward replication fanout — SHIPPED 2026-05-26

**Symptom.** User-reported: `final.split-wv` and `final.split-H` "produce
a lot of arrows that are essentially one on the other" on the SHA-256
graph. The s-row inter-stage gaps (s_0 → s_1 → … → s_7 → assemble) also
pile up several arrows on the same horizontal line.

**Root cause.** `replicateHighFanoutSources` counted only `kind: "aux"`
edges for fanout eligibility. SHA-256's `final.split-wv` and
`final.split-H` each emit 8 port-flow edges to `final.s_0..s_7` (one per
output port), but port-flow edges have `kind: "state"` (auxKey
`"port-flow"`) per Slice S2(e). So both sources scored fanout 0 and never
qualified for replication — leaving 8 long lines fanning from one origin
horizontally through the s-row.

**The fix.** Eligibility predicate widened to
`kind === "aux" || (kind === "state" && auxKey === PORT_FLOW_AUX_KEY)`.
Legacy passthrough state edges (auxKey === `"state"`) stay excluded —
they're 1-to-1 between consecutive same-parent leaves by construction
and would inflate counts for every spine participant. AES/Speck/Serpent/
DES have no port-flow edges and remain byte-identical.

**Tests:**
- `tests/replicate-fanout.test.ts` new "Slice S2(i) — port-flow fanout
  eligibility (SHA-256 split-wv / split-H)" describe block (2 tests):
  (1) Synthetic split-wv-analog: 8 port-flow state edges from one
      source to 8 distinct consumers replicates at threshold 6;
  (2) Negation: 8 legacy passthrough state edges (auxKey: "state")
      from one source identity-short-circuit even at threshold 1
      (the lowest non-trivial setting) — pins that the discriminator
      doesn't drift loose and start counting legacy spine.

**Counts:** suite 2377 → 2379 (+2). Bundle 684.69 → 684.73 KB raw /
201.11 → 201.12 KB gzipped (essentially flat — +10 LOC + tests).

**Open caveat (NOT addressed by this slice).** The s_i → assemble
fan-IN pile-up surfaced in the user's image 2 is structurally
different: each `final.s_i` has fanout = 1 (only to `final.assemble`),
so no s_i source qualifies for replication. The 8 port-flow edges
funneling into `assemble` from increasingly-distant sources remain a
visual cluster — `final.s_0 → final.assemble` physically traverses the
s_1..s_7 corridor. If still visually annoying after S2(i), this needs
its own slice (sink-side replication, or layout rethink). Filed here
rather than rolled into S2(i) per advisor's "don't bundle structurally
different changes" guidance.

#### S2(e)+S2(f) browser smoke outcome — 2026-05-26

**Confirmed working:** H-constant → init-working-vars arrow visible;
final.assemble shows 8 incoming port-flow arrows from final.s_0..s_7;
init-working-vars → round.0.state-in (state-thread) visible; round.X
→ round.X+1 inter-round state handoffs visible via the collapsed-
round container chain; round.63 → final.state-in visible; AES-128
ECB sanity-check legacy spine intact (key-expansion in lifted
gutter row, fan-out aux edges to each round).

**Pre-existing issue surfaced (NOT a S2 regression):**
`msg-schedule → W-publish` still missing — `dropAuxOnlyStateEdges`
overreach (S2(h)). The plan's original symptom #3 traces to this
filter rather than to a layout problem.

**Edges to follow up on if pursued:** the chain through
`W-publish → K-to-aux → H-to-aux → H-constant` (the "loading
phase" of aux constants) is also currently filtered; S2(h) would
restore visibility.

#### Original (a)/(b)/(c) options — closed as misdiagnosed

For historical reference; not actionable now.

- **(a) Force preamble verticalize** — closed: original symptom was
  derivation, not layout. Verticalize was the wrong tool.
- **(b) Lower replication threshold for preamble sources** — closed:
  the "long arrow" symptom (`H-to-aux → final.fetch-H`) was actually
  the source's outgoing edges being routed misleadingly because the
  consumer-side port edges weren't being emitted at all.
- **(c) Spine-arrow z-order lift** — closed: the invisible arrows
  weren't hidden behind chips, they weren't in the derivation graph.

### Slice S3 — narration density second pass

Deferred from this session per the bucket-C scoping above. Two routes
(a) or (b) per the "Context" section. Defer until S1 + S2 ship — the
ParamEditor + layout fixes change what the user sees per scrub, which
may change which leaves "need more prose."

## Order

S1 first — it's pure additive editor work, no risk of regression to
the graph layout. S2 needs a planning round to pick (a) / (b) / (c) /
hybrid. S3 is the lowest priority and benefits from waiting on the
other two.

## What this plan does NOT cover

- The general "should ParamEditor allow editing structural params"
  question (per-cipher conformance lockdown). Worth raising
  separately if a user reports breaking SHA-256 by editing `bits:
  17` to `bits: 12` (which the existing trace-rerun discipline
  surfaces via a divergent digest — pedagogically arguably correct).
- Multi-block SHA-256. Today's spec is single-block (max 55-byte
  message); multi-block lands as its own slice. Not in scope here.
- Other future hashes (SHA-3, SHA-512, MACs, KDFs). Each gets its own
  density review when it ships.

## Memory pointers

- [[project_universal_port_dataflow_proposal]] — Phase 2 spine.
- [[feedback_port_native_param_names]] — gotcha table for the param
  names that S1's editors will surface.
- [[project_hash_future]] — endpoint-label seam closure (Slice S1 of
  THIS session, not of this plan; mentioned for cross-reference).
