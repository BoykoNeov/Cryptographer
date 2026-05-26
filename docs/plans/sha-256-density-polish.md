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

#### S2(e) — port-flow edge derivation — DEFERRED to a future session

**Scope:** extend `deriveAuxGraph` in `src/core/graph.ts` to walk
every step's `portInputs` and emit a graph edge per binding (from
upstream node's output port → this node's input port). Likely 30-60
lines of code. Test pinning SHA-256's `final.s_0` shows two incoming
edges (from `split-wv.output0` and `split-H.output0`); `final.assemble`
shows 8 incoming edges; `H-constant` shows one outgoing edge to
`init-working-vars`.

**Pass/fail gate:** manual smoke on SHA-256 shows every real port-flow
arrow rendered. Duplicate edges between consecutive siblings (one
state-spine, one port-flow) accepted as known noise; S2(f) cleans up.

#### S2(f) — whole-spec suppression of legacy state-spine inference — DEFERRED to a future session

**Scope:** add a predicate (e.g. `requiresPortedDispatch(spec)` or
equivalent — read "does this spec contain any port-native step") and
gate the legacy consecutive-siblings state-spine inference behind
`!predicate`. When true, skip the inference entirely.

**Safety rationale.** Per user architectural decision 2026-05-26
(`docs/plans/universal-port-dataflow.md` "Architectural decisions"
addendum + `feedback_all_specs_port_native.md` memory): every shipped
spec is either 100% legacy OR 100% port-native; no hybrids. The
whole-spec suppression strategy is therefore permanently safe — there
is no shipped spec where the legacy inference is needed for some
leaves but not others. Per-edge suppression would have been more
defensive but is unnecessary under this rule.

**Pass/fail gate:** AES / Speck / Serpent / DES graph views render
byte-identically to today (legacy specs → predicate false → inference
fires unchanged). SHA-256 graph view shows port-flow arrows only — no
duplicate "state" edges between consecutive port-native siblings.

#### S2(g) — polymorphic-state-shape dead-code cleanup — DEFERRED to a future session

**Scope:** audit `src/core/graph.ts` (and adjacent files in
`src/core/`) for branches handling `BigIntState` / `BitVecState`.
Under the user's Rule 2 (specialized math is internal to a node;
ports stay byte-flat), these state shapes don't cross port
boundaries. They're slated for deprecation in Phase 5; the branches
that handle them are likely dead code at graph-derivation level
already.

**Folding rationale.** User pick Q4 of 2026-05-26 — fold into S2 work
since we're touching `deriveAuxGraph` anyway. Scope may be small
(no current consumer in `graph.ts`) or non-trivial (the polymorphic
branch might be load-bearing for some test path). Reassess scope
after S2(e) lands.

**Pass/fail gate:** test suite stays green; bundle size shrinks
proportionally to whatever dead code was removed.

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
