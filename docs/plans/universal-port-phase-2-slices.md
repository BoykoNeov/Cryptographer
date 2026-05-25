# Universal port-based dataflow — Phase 2 sub-slice plan

> **Status: DRAFT 2026-05-24 + Slice 2.0a GREEN 2026-05-24 + Slice 2.0b-i
> GREEN 2026-05-24 + Slice 2.0b-ii GREEN 2026-05-24 + Slice 2.0c GREEN
> 2026-05-24 + Slice 2.1a GREEN 2026-05-24 + Slice 2.1b GREEN 2026-05-24
> + Slice 2.2 GREEN 2026-05-24 + Slice 2.3 GREEN 2026-05-24
> + Slice 2.4 GREEN 2026-05-24 + Slice 2.5 GREEN 2026-05-25.** Drafted after Phase 1 closed (1748/1748 tests, all 13
> sub-slices + caveat 1+3 follow-up green) and two advisor consults
> framed the Phase 2 surface.
> Slice 2.0a's four contract-design questions resolved + SHIPPED (suite
> 1753/1753; surfaced the `:t < :b < :r` suffix rule as type-order +
> outer-first-walk-order, NOT "innermost-first"). Slice 2.0b sub-
> divided into 2.0b-i (contract widening + toy fixture) and 2.0b-ii
> (lift `split-blocks` / `concat-blocks`) per the operational note
> "one commit per sub-slice." **Slice 2.0b-i SHIPPED** — two user
> picks locked (Open #N1 = (b) concatenated single port; Slice-2.0b
> sub-decision = (X) node-explicit fields); `ForEachSubgraphNode`
> widened with four optional item-array fields; runtime walker handles
> item-array mode; 8-case toy fixture + 5 mode-exclusivity throws.
> Suite at 1761/1761. **Slice 2.0b-ii SHIPPED 2026-05-24** — plan
> slip discovered + resolved at slice start (concat-blocks is shape-
> transforming on state, NOT just an aux State[] widening; the runtime's
> `stateToBytes` encode boundary at `port-projection.ts:281` throws on
> shape mismatch upstream of the executor's `_state` indifference);
> user picked **option C** (relax `stateToBytes` so `expected: "bytes"`
> accepts any non-bigint State variant) over option A (split-slice)
> and option B (ProjectionMetadata asymmetric layouts widening). New
> aux-layout tag `"matrix-cm-4x4-array"` added to `auxPortBytesToValue`
> + symmetric encode in `auxValueToPortBytes` + file-private
> `auxValueToBytes` (centralized via `encodeStateArrayToBytes` helper).
> Both `split-blocks@1` and `concat-blocks@1` lifted as `kind: "ported"`
> with legacy fallback preserved. Suite at 1773/1773 (+12 new round-
> trip tests in `tests/port-projection-matrix-array-roundtrip.test.ts`);
> Slice 1.11 frame-parity matrix (22 rows) auto-widens — ECB/CBC
> encrypt/decrypt now exercise the new code through the ported path.
> **Slice 2.0c SHIPPED 2026-05-24** — `ForEachSubgraphWithHistoryNode`
> ships as a sibling `StepNode` kind (Q2 = sibling, not third mode)
> with declarative `lookbackOffsets` (Q1 — Open #N4 closed) +
> per-invocation history seeded from parent state bytes + per-outer
> reset semantics (Q3) + aux snapshot+restore. Three advisor-sharpened
> questions (Q1/Q2/Q3) replaced the plan's original (a/b/c) framing;
> the contract is now FINAL per Invariant 3. Suite at **1791/1791**
> (+18 new tests). Phase 1 matrix untouched.
> **Slice 2.1a SHIPPED 2026-05-24** — `StepRegistration` widened:
> `legacy` AND `meta` both optional on the `kind: "ported"` variant
> (advisor flagged the `meta`-too-must-be-optional asymmetry pre-edit).
> Runtime hardened with TWO explicit guards: off-flag dispatch throws
> *"step type `<type>` is port-native; requires portedDispatchEnabled:
> true"*; on-flag dispatch throws *"port-native and requires spec
> edge-wiring (Slice 2.6+)"* — port-native steps are reachable today
> only via direct executor invocation in tests. First port-native step
> `rotate-bits-right@1` ships in `src/steps/rotate-bits-right.ts` with
> a `PortedExecutor` + `PortContract` (one in / one out, polymorphic
> `byteLength`, `layout: "raw"`) + `StepDocumentation` (NO
> `shapeContract`) + 26 unit tests in `tests/rotate-bits-right.test.ts`
> covering identity / KATs across all 4 wordBits / multi-word / modulo
> canonicalization / round-trip property / param validation / both
> dispatch-path guards. `state-shape-contracts.test.ts` widened to skip
> port-native registrations (`kind: "ported"` with no `legacy`); other
> coverage tests (narration, provenance) already gated on
> `shapeContract` so they auto-skip. Plan's hand-cited KAT
> `0x12345678 ROR 2 = 0x80123456` was incorrect — advisor caught the
> bug pre-implementation; KATs derived from textbook formula land on
> `0x048D159E` instead. Suite at **1817/1817** (+26 new). Next stop:
> **Slice 2.1b** (`xor@1` widened N-way + `add-mod-32@1`).
> **Slice 2.1b SHIPPED 2026-05-24** — second + third port-native step
> types land: `xor@1` (`src/steps/xor.ts`, 24 tests) and `add-mod-32@1`
> (`src/steps/add-mod-32.ts`, 28 tests). Both follow the Slice 2.1a
> precedent: `kind: "ported"` registration with NO `legacy`, NO `meta`,
> NO `shapeContract`; reachable today only via direct executor
> invocation in tests (off-flag and on-flag dispatch each throw the
> exact 2.1a guard message). Both use function-form `PortContract.inputs`
> (operand count varies with `params.inputCount`, port names
> `operand0`..`operand{N-1}` per S3) and static-form `outputs` (a fixed
> single `output` port — matches rotate-bits-right precedent per the
> "function form only when N varies on THIS side" rule from Slice 1.4).
>
> **Fork 1 (xor inputCount floor): N ≥ 1.** Single-operand identity is
> a legal authoring-time intermediate; reject N=0 because output
> byteLength is undecidable. Pinned in xor's param-validation tests.
>
> **Fork 2 (add-mod-32 arity): SHIPS N-WAY, not plan-literal 2-way.**
> The plan body's sketch reads *"params: { inputCount: 2 } (always 2
> for SHA-256; future additions can widen)"*. User pick 2026-05-24
> overrode this in favor of N-way symmetry with `xor@1`: addition
> mod 2³² is associative so the math is identical, and SHA-256's
> compression-function update `T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]`
> reads cleanly as one 5-operand node rather than four chained 2-way
> adds. Slice 2.1b's `add-mod-32@1` accepts `inputCount` integer ≥ 2
> (no degenerate single-operand identity case — rejected as
> indistinguishable from passthrough; revisit if a real use case
> appears). The asymmetric N-floor with xor (≥1) is intentional and
> documented in both executors' headers.
>
> Together with rotate-bits-right@1 (Slice 2.1a) the three primitives
> SHA-256 needs (rotate, XOR, modular-add) are all registered. Suite
> at **1869/1869** (+52 new tests across the two files). Phase 1
> matrix untouched.
>
> **Slice 2.2 SHIPPED 2026-05-24** — Open #N5 (word-state encoding)
> resolved via user pick **(a+)**: consolidate the duplicate inline
> BE-word codec helpers into `src/core/word-codec.ts` covering all four
> widths (8/16/32/64), **WITHOUT** adding a `word-array-be-32`
> PortContract layout tag. Rationale: under Q1 hybrid posture, layout
> tags are advisory; no Phase 2 editor / graph / inspector surface
> reads port layout-as-data (the `matrix-cm-4x4` precedent IS load-
> bearing because it carries State[] aux-passthrough info through
> `port-projection.ts`, but a word-array tag has no equivalent
> consumer). Per-leaf "this is a 32-bit BE word" prose lives in
> `narrationOverride` (Slice 1.10), not in port layout. If Phase 2.10's
> graph view eventually needs grey-out logic between word-typed and
> raw-typed ports, adding the tag then is a small follow-on commit
> (~30 lines + Q-gate-9 extension).
>
> **API shape:** per-width fns (`decodeBE8/16/32/64`, `encodeBE8/16/32/64`,
> `ror8/16/32/64`). 8/16/32-bit paths use plain `number`; 64-bit uses
> `bigint` (JS number bit ops truncate to 32-bit). A unified
> `decodeBEWord` returning `number | bigint` would force `as number`
> casts at every 32-bit call site and BigInt allocation on the hot
> path — per-width split is the cleaner API. Add-mod-32 (which is
> fixed-width 32) imports only `decodeBE32` + `encodeBE32`;
> rotate-bits-right dispatches on `wordBits` outside the loop, picks
> the per-width triple once, runs a tight composed `decode → ror →
> encode` loop. Width coverage carries Speck rebuild (16/32/64) +
> SHA-512 (64), not just SHA-256.
>
> **Q-gate-9 extension framing:** "shared codec proves byte-equal to
> removed inline helpers" — the existing 26 rotate-bits-right tests
> + 28 add-mod-32 tests + the new 44 word-codec direct tests together
> ARE the gate; no separate parity test added. Suite at **1913/1913**
> (+44 new). Bundle 567.76 KB gzipped (+~9 KB from Slice 2.1b's
> 558.74 KB). Phase 1 matrix untouched. **Open #N5 CLOSED.** 6 open
> spec decisions remaining (N1/N2/N3/N4/N7/N8).
>
> Next stop: **Slice 2.3** (Open #N3 — SHA-256 helpers Σ0/Σ1/Ch/Maj as
> step types vs in-spec compositions vs hybrid).
>
> **Parent plan:** [`docs/plans/universal-port-dataflow.md`](./universal-port-dataflow.md)
> **Phase 0 findings:** [`docs/plans/universal-port-phase-0-findings.md`](./universal-port-phase-0-findings.md)
> **Phase 1 slices:** [`docs/plans/universal-port-phase-1-slices.md`](./universal-port-phase-1-slices.md)
> **Memory:** `project_universal_port_dataflow_proposal.md`

## Goal of Phase 2

Ship **SHA-256 implemented entirely under the ported contract** — the
first port-native cipher with no legacy counterpart. Validate that the
universal-port model expresses a primitive (cryptographic hash) that
legitimately cannot fit single-state-thread: SHA-2 has output
multiplicity (8 hash words), internal feedback (message-schedule
expansion), and nested iteration (per-block × per-round) that today's
contract handles awkwardly.

Phase 2 introduces:

- **`for-each-subgraph` spec node kind** (new) — a port-native iteration
  construct that handles **both** the per-round state-carrying body
  pattern AND the per-block item-array outer pattern (Q4 superset pick).
- **Three new universal primitives** — `rotate-bits-right@1`,
  `xor@1` widened N-way, `add-mod-32@1`. All ship port-native (no legacy
  underlying executor).
- **Spec-level `requiresPortedDispatch` opt-in mechanism** — Phase 1's
  parity matrix stays green; SHA-256 self-declares its dispatch
  requirements (Q3 pick).
- **Word-state encoding** — Phase 0 findings flagged SHA-2's 8×32-bit BE
  words as a forcing decision (Open #N5 below).
- **First shipped use of `narrationOverride`** (Slice 1.10's foundation
  field) — every SHA-256 leaf carries cipher-specific narration.

Full UI surfaces (linear view, narration, provenance overlay, graph
view) work for SHA-256 (Q1 full-scope pick).

## Resolved design decisions taken at consult time

User picks 2026-05-24 framing the Phase 2 surface.

### Decision Q1 — Phase 2 scope: FULL (per parent plan literal)

KAT pass + linear view + narration + provenance overlay + graph view
all polished for SHA-256. Estimated **15 sub-slices**. Matches parent
plan wording verbatim.

**Rejected alternatives:**
- Thin end-to-end first (KAT only, ~7 slices, UI polish in Phase 2b).
- Thin KAT + narration only (~9 slices, provenance + graph in Phase 2b).

### Decision Q2 — Slice 2.0 framing: for-each-subgraph contract + toy fixture (advisor's pick)

Design the new spec node kind, runtime walker, and frame-emission
semantics on a synthetic toy fixture **before** any SHA-256 specifics
land. SHA-256 starts at Slice 2.3 (compositions of new primitives).
The for-each-subgraph contract is THE load-bearing decision of Phase 2,
not the primitive vocabulary — primitives are mechanical follow-ups.

**Rejected alternatives:**
- New primitives first (`rotate-bits-right` etc. before contract).
- Word-state encoding decision first.

### Decision Q3 — Ported dispatch enable: spec-level opt-in

Spec carries `requiresPortedDispatch: true` (or registry derives from
"uses any port-native step type"). Phase 1's 22-row parity matrix
stays green untouched; SHA-256 spec is the first declarer. Reversible
later — flipping the global default in Phase 4/5 is a one-line change.

**Rejected alternatives:**
- Global default flip in Phase 2 (higher blast radius; procedurally
  backwards — Phase 1 exit criteria stated the cutover gate is Phase 2's
  proof).
- Surface mid-slice.

### Decision Q4 — Outer per-block loop: also for-each-subgraph (superset)

`for-each-subgraph` handles BOTH inner per-round (state-carrying body)
AND outer per-block (item-array) patterns in its first shipped use.
`iterate` becomes a candidate for early deprecation in Phase 4/5.

**Implications for Slice 2.0 design:**
- The new node kind must accommodate two distinct patterns in its
  first contract — higher risk of getting the contract wrong vs. the
  legacy-iterate-reuse path.
- **Phase 1's Open #1 (`split-blocks` port shape: per-block ports vs.
  concatenated bytes single port) lands inside Slice 2.0b**, not Phase 4.
- `aux[outBlocksAux]` side-effect channel (Phase 0 findings, "do not
  collapse") needs an explicit port-level model — likely an output port
  on the for-each-subgraph node carrying per-iteration outputs.

**Rejected alternatives:**
- Reuse legacy `iterate` (narrower contract, isolated risk; rejected
  for long-term cleanness).
- Single-block first, defer multi-block (ruled out by Q1 full-scope
  pick).

### Sharpenings adopted from advisor consult #2 (2026-05-24)

| ID | Sharpening | Adoption |
|---|---|---|
| S1 | Slice 2.0's contract has three forcing requirements (state-thread, iteration-outputs port, feedback/lookback), not one | **Split Slice 2.0 into 2.0a / 2.0b / 2.0c** — one requirement per sub-slice with its own toy fixture and gate. More conservative than widening one mega-toy. |
| S2 | Nested-loop frame suffix convention unspecified | **Pin in Slice 2.0a** — toy fixture exercises a nested iteration to force the choice. Candidate convention: outer `:b{i}` × inner `:r{j}` → composed `:b{i}:r{j}`. |
| S3 | `xor` N-way port semantics under sink-only edges | **Flagged explicitly in Slice 2.1b** — each of N input ports reads from spec's edge graph (sink-only `inputs` map per Q-edges), NOT from `aux`. |
| S4 | Slice 2.1 mixes contract change with primitives | **Split into Slice 2.1a / 2.1b** — 2.1a widens `StepRegistration.legacy` to optional + ships `rotate-bits-right@1` as first port-native registration. 2.1b is mechanical follow-up. |
| S5 | Spec-level opt-in needs its own slice | **Slice 2.7 = pure opt-in plumbing** (no KAT). Slice 2.6 covers first end-to-end via direct `runSpec({portedDispatchEnabled: true})` flag; Slice 2.7 wires the spec-level field so Slice 2.10's cipher selector can launch SHA-256 in the live app. |

## Open spec decisions (flagged, NOT resolved in this plan)

These need user picks at the named slice's start. **Surface at the
right moment; do not pre-resolve here.**

### Open #N5 — Word-state encoding for SHA-256 — **CLOSED 2026-05-24 (user picked (a+))**

SHA-256 works on 8×32-bit BE words. The plan-time framing was three
candidates; advisor consult at Slice 2.2 start narrowed to two
(plan-verbatim (a) was a non-option after Slice 2.1a/2.1b's TODO
comments explicitly flagged the inline-codec duplication for
consolidation). Final pick: **(a+) shared codec, no layout tag.**

- **(a+) Codec consolidation only.** Per-width BE codec + ROR helpers
  consolidated into `src/core/word-codec.ts` covering 8/16/32/64-bit
  widths (Speck rebuild + SHA-512 future-readiness, not just SHA-256).
  All three port-native primitives keep `layout: "raw"`. Q-gate-9
  "extension" becomes "shared codec proves byte-equal to removed
  inline helpers" — the existing 26 rotate-bits-right + 28 add-mod-32
  tests + 44 new word-codec direct tests together ARE the gate.
- **Rejected (b) Codec consolidation + `word-array-be-32` layout tag.**
  Under Q1 hybrid posture the tag is advisory; no Phase 2 editor /
  graph / inspector surface reads port layout-as-data. The
  `matrix-cm-4x4` precedent IS load-bearing — it carries State[] aux-
  passthrough info through `port-projection.ts` — but a word-array tag
  has no equivalent consumer today. Per-leaf "this is a 32-bit BE word"
  prose lives in `narrationOverride` (Slice 1.10). If Phase 2.10's
  graph view eventually needs grey-out logic between word ports and
  raw ports, adding the tag then is one small commit.
- **Rejected (a) Plan-verbatim, codecs stay inline.** Doubles down on
  duplication that 2.1a/2.1b already flagged with TODO comments.
- **Rejected (c) New State variant `WordArrayState`.** Contradicts the
  universal-port plan's thesis that State variants collapse to
  Uint8Array at runtime.

**Pinned principle from this slice:** *layout tags appear when a
consumer needs them.* (a+) sets the precedent so future slices don't
add PortContract surface area on speculation.

### Open #N4 — Per-iteration feedback/lookback contract shape (decided at Slice 2.0c)

SHA-256 message schedule: W_t computed from W_{t-2}, W_{t-7}, W_{t-15},
W_{t-16}. Iteration body needs to read **earlier W values**, not just the
immediately prior iteration's "state."

Three candidates:

- (a) **`for-each-subgraph` contract widens to expose a per-iteration
  history channel** — body receives `aux.priorIterations: Uint8Array[]`
  (or named `aux.history[<offset>]`) populated from prior iterations'
  outputs. Single node kind handles all three patterns (round-body,
  block-array, feedback-lookback).
- (b) **Sibling node kind `for-each-subgraph-with-history@1`** — body
  declares lookback ports with explicit indices (`prior[-2]`,
  `prior[-7]`, etc.). Cleaner separation of concerns; doubles spec node
  vocabulary.
- (c) **Message-schedule expansion as a sequence of N hand-rolled leaf
  steps in the spec** (one leaf per W_t, t ∈ [16, 64)). No iteration
  primitive at all for message schedule. Pedagogically clearest (each
  W_t is a discrete frame the user can scrub). Verbose spec — 48 leaf
  declarations.

User pick at Slice 2.0c start.

### Open #N6 — Nested-loop frame suffix convention — **CLOSED 2026-05-24 (user picked (a))**

Outer per-block × inner per-round canonical stepId composition: **(a)
`<leafId>:b{i}:r{j}` — outer-first concatenation, extends existing
`:b{i}` convention.** Each loop kind appends one coordinate; nested
loops concatenate. Slice 2.0a's nested toy pins it in the gate test.

Rejected alternatives:
- (b) `<leafId>:i{i,j}` single bracketed coordinate (loses per-loop
  semantic).
- (c) Generic `:{i}` with nesting (most compact; weakest pedagogy).

### Open #N1 — `split-blocks` port shape — **CLOSED 2026-05-24 (user picked (b))**

Q4 superset pulled this from Phase 1 (where it was deferred to Phase 2)
into Slice 2.0b. **User picked (b) Concatenated single port** at slice
start after advisor flagged that Phase 1's "(a) is the precedent" carries
a hidden premise — Decision B's per-port-per-round-key shape works
because `PortShapeMap` is a function of *spec-time* `params.rounds`
(fixed when the user picks AES-128/192/256). **Block count is run-time
data** (varies with plaintext length), so picking (a) would force one of
three contract extensions: widen `PortShapeMap` to take run-time data,
bake a magic-number `params.maxBlocks` cap into every CBC spec, or
invent a wildcard-edge convention. (b) needs none of these.

Graph-view fidelity worry resolved: today's legacy iterate shows ONE
aux edge from `split-blocks` → iterate; arrow bundling collapses N
parallel aux edges to a ×N pill anyway. (b)'s single edge with run-time
×N annotation matches what users see today, not a regression. (b) also
preserves the existing `MatrixState[]` "one bundled array" posture and
makes `split-blocks` near-trivial under the lift (`matrixFromBytes` is
identity-on-bytes; concat(blocks.map(b => b.bytes)) === original bytes).

Rejected alternative (a) per-block ports captured in the originating
session for posterity.

### Open #N1-a — Item-array mode field shape — **CLOSED 2026-05-24 (user picked (X) Node-explicit)**

Surfaced at Slice 2.0b start after Open #N1 resolved. The advisor's
Phase 2 consult #3 flagged that picking (b) leaves two follow-on design
points the slice plan didn't pin: where `blockByteLength` lives, and
how `iterationCount` derives. Two options:

- (X) **Node-explicit fields.** `for-each-subgraph` carries
  `inputArrayPort` + `outputsPort` + `blockByteLength` + `blockLayout`
  directly. `iterationCount` auto-derives as
  `inputs[inputArrayPort].length / blockByteLength`. Self-contained;
  mirrors legacy iterate's `blocksFromAux/countFromAux/outBlocksAux`
  pattern; no graph-introspection coupling.
- (Y) **Source-port introspection.** `for-each-subgraph` carries
  `inputArrayPort` + `outputsPort` only; reads layout + per-block size
  from the wired source port's PortContract. Cleaner if a sequence
  layout exists in vocabulary, but requires the runtime to walk graph
  edges to discover shape — couples node behavior to graph topology.

**User picked (X)** at slice start. Implemented via four optional fields
on `ForEachSubgraphNode`; mode-exclusivity invariants enforced at runtime
(partial-field configs throw; both-modes-set throws; both-modes-absent
throws).

### Open #N2 — Constants entry strategy — **CLOSED 2026-05-24 (user picked (b) at 72-leaves granularity)**

K_0..K_63 (round constants) and H_0..H_7 (initial hash values) are 32-bit
constants needed by SHA-256. Two candidates:

- (a) **Leaf params** — each leaf that needs a constant carries it in
  `params` (e.g., compression round leaf reads `params.K = <hex>`).
  Constants embedded in spec; spec size grows.
- (b) **`constant-load@1` primitive** — a new port-native step type
  that outputs a declared byte sequence on its single output port. Each
  constant becomes a leaf in the spec, wired as input to consumers.
  Pedagogically richer (constants are visible chips in the graph);
  spec is more verbose.

**User picked (b) at 72-leaves granularity** — one leaf per constant
(8 H_t leaves + 64 K_t leaves). Advisor surfaced a hidden granularity
dimension under (b) — 72 individual leaves vs. 2 tables (256-byte K +
32-byte H) vs. per-round bundled — and user chose the maximally thesis-
aligned option (every constant visible as its own chip, addressable
individually by editors). The primitive doesn't enforce granularity;
specs that prefer compact bundles can set `params.bytes` to a longer
array — but the SHA-256 build at Slice 2.6 uses 72 leaves.

### Open #N3 — SHA-256 helpers (Σ0, Σ1, Ch, Maj) — step types vs in-spec compositions (decided at Slice 2.3)

Σ0(x) = ROR(x,2) ⊕ ROR(x,13) ⊕ ROR(x,22). Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z).
Two candidates:

- (a) **Step types** — each gets its own registered step type with one
  output port (e.g., `sha2.sigma-0@1`, `sha2.ch@1`). Cleaner narration
  per-helper; specs use four helpers as opaque leaves. Risks
  cipher-specific step types creeping back after Phase 1 worked to
  eliminate them.
- (b) **In-spec compositions** — Σ0 expressed in the spec as three
  `rotate-bits-right@1` + one `xor@1` N-way. Ch needs `and@1` + `not@1`
  + `xor@1` primitives — adds two new step types (`and@1`, `not@1`)
  to the universal vocabulary. Pedagogically richer (the user sees the
  decomposition in the graph); spec is verbose.
- (c) **Hybrid** — Σ0/Σ1 as compositions (rotate+xor only, primitives
  already exist); Ch/Maj as step types (avoids adding `and@1`/`not@1`
  primitives this phase). Pragmatic middle ground.

User pick at Slice 2.3 start.

### Open #N7 — Cipher selector category for SHA-256 (decided at Slice 2.10)

`SUPPORTED_CIPHER_MODES_BY_CIPHER` in `stores/cipher-mode.ts` and
`defaults` in `stores/spec.ts` are fixed enums (per CLAUDE.md gotcha:
"Adding a new (cipher, cipherMode) spec means updating TWO tables").
Two candidates:

- (a) **SHA-256 as a cipher sibling** — added to the existing list
  alongside AES/Speck/Serpent/DES. Cipher-mode selector shows a single
  "hash" mode option. Pedagogically odd ("a hash is not a cipher")
  but minimum UI changes.
- (b) **New top-level "hash" category** — UI separates ciphers from
  hashes with a new selector axis. Larger UI surface; sets up SHA-3,
  MAC, KDF for cleaner growth. Aligns with `project_hash_future.md`.

User pick at Slice 2.10 start. (b) is the more honest answer but bigger
slice scope.

### Open #N9 — Spine-termination at for-each-subgraph boundary is mode-conflated (surface at Slice 2.6)

Surfaced by advisor consult #4 (2026-05-24, post-Slice-2.0b-i). Slice
2.0a widened `graph.ts::walkSpec`'s spine-termination treatment to
include `for-each-subgraph` boundaries — mirroring legacy `iterate`,
where state IS clobbered from aux per iteration entry (advisor consult
during Slice 2.0a discussed this; suppression is honest there).

For **item-array mode** (Slice 2.0b-i), this remains honest — state IS
clobbered per iteration entry (the runtime calls `portBytesToState(slice,
blockLayout)` and assigns to `state`). Spine suppression matches reality.

For **state-thread mode** (Slice 2.0a, first shipped consumer = SHA-256
compression in Slice 2.6), this is **structurally wrong** — state
genuinely threads through iterations. Spine suppression hides the data
flow the user wants to see. Will surface as a noticeable bug the moment
SHA-256 compression lands in graph view at Slice 2.6.

Three candidates (decide at Slice 2.6 start):

- (a) **Per-mode branch in `inferStateEdges` / `walkSpec`**. State-thread
  keeps spine; item-array suppresses (status quo). One conditional check
  on the four item-array fields.
- (b) **Spine-passthrough optional flag on for-each-subgraph node** —
  `spineThreadsThroughBody?: boolean`, defaulting true (state-thread is
  the more common case once SHA-256 + other hash compressions land).
  Decouples graph treatment from runtime mode-discriminator.
- (c) **Defer until SHA-256 graph treatment surfaces the bug visibly**
  and pick mid-Slice-2.6 with full context.

User pick at Slice 2.6 start. Flagged here so the bug doesn't surface
cold to a future reader.

### Open #N8 (lower priority) — Bundle size posture (flagged, not pre-engineered)

Already at ~543 KB (Phase 1 close, post-Slice-1.12). Vite warning
threshold is 500 KB. Phase 2 adds:

- 1 spec node kind + runtime walker code (~150 LOC)
- 3 universal primitives (~50 LOC each)
- 4 SHA-256 helpers (~30 LOC each if step types; ~0 LOC if compositions)
- ~10 SHA-256 leaf narration modules
- 1 SHA-256 provenance module
- 1 SHA-256 key-schedule simulator (if applicable; SHA-256 has no key
  schedule, but a "message schedule simulator" may surface for
  inspection)

Estimated +25 KB to +60 KB depending on Open #N3 (step types vs
compositions) and Open #N2 (constants embedded vs primitive). Worth
flagging in plan but **do not lazy-load SHA-256 modules pre-emptively**
— per CLAUDE.md "don't add features beyond what the task requires." If
the bundle warning becomes blocking, lazy-loading is the obvious
mechanical response.

## Three correctness invariants Slice 2 must preserve

1. **`TraceFrame` shape unchanged.** Both legacy and ported paths
   continue to produce frames with byte-equal `auxRead` / `auxWritten`
   under their respective dispatch. SHA-256's frames (port-native only)
   produce `auxRead` / `auxWritten` populated from `meta.auxReadPorts` /
   `meta.auxWritePorts` bindings — identical SHAPE to Phase 1 frames
   even though no legacy executor produced them. Graph derivation
   (`core/graph.ts`) reads exactly those fields and works unmodified.

2. **Phase 1 parity matrix stays green.** Slice 1.11's 22-row
   `runtime-ported-dispatch-frame-parity.test.ts` continues to pass
   exactly as it did at Phase 1 close. Q3 spec-level opt-in keeps
   AES/Speck/Serpent/DES specs running under `portedDispatchEnabled:
   false` by default; no shipped cipher's dispatch path changes in
   Phase 2.

3. **For-each-subgraph contract is finalized at Slice 2.0c.** Subsequent
   slices treat the contract as immutable; design changes to handle
   late-discovered patterns force a planning re-open, not a silent
   contract bump. This protects Slices 2.3–2.6 from cascade-rewriting
   when message-schedule's feedback shape (Slice 2.0c) interacts with
   compression's state-thread shape (Slice 2.0a).

## Sub-slice breakdown (15 sub-slices)

Each sub-slice ships as ONE commit + push, with `npm run check` GREEN
before the commit lands. A failing gate stops the sequence — surface to
user, do not silently continue.

**Detail level:** Slices 2.0a / 2.0b / 2.0c / 2.1a are detailed (load-
bearing contract surfaces). Slices 2.1b through 2.11 are sketched — they
firm up at slice start, after upstream context lands.

### Slice 2.0a — `for-each-subgraph` spec node kind: state-thread round-body pattern

**Goal:** introduce the new spec node kind into `core/types.ts` and the
runtime walker; validate it on the simplest of three target patterns
(state-thread round-body, the inner per-round loop SHA-256's
compression will use).

**User picks LOCKED IN 2026-05-24** (four contract-design questions
surfaced and answered before slice authoring; pros/cons exchange visible
in the originating session):

- **Q-2.0a-1 (node shape) = (a) Mirror iterate.** Body inline as
  `children: StepNode[]`. Same convention as existing `iterate` /
  `feistel-round`. Implicit state-thread (first child reads `state`,
  last child's output becomes next iteration's `state`). Branches and
  merges inside the body are still expressible via children's `inputs`
  edge maps (graph, not sequence) — Q4 superset / branching is free,
  not blocked by node shape.
- **Q-2.0a-2 (iterationCount source) = number-or-fromParam.**
  `iterationCount: number | { fromParam: string }`. SHA-256 compression
  uses the literal `64`; param-form anticipates per-cipher round-count
  variation (e.g., a future SHA-256-variant spec where rounds are a
  param). Item-array source (`{ fromInputPort: string }`) defers to
  Slice 2.0b when that pattern lands.
- **Q-2.0a-3 (nested-suffix convention, closes Open #N6) =
  `:r{i}` rounds, composed `:b{i}:r{j}` when nested.** Extends the
  existing `:b{i}` block convention from `iterate`. Each loop kind
  appends one coordinate; nested loops concatenate. Reads as "leaf,
  block i, round j." Generic `:{i}` and single-bracketed `:i{i,j}`
  alternatives rejected — loses per-loop semantic.
- **Q-2.0a-4 (toy fixture content) = 5-iter XOR-with-constant.**
  Body: one `xor-aux-into-state@1` leaf (or equivalent port-native
  XOR) with a fixed 4-byte constant. Each iteration XORs state with
  the constant. Final state = start XOR (5 × constant) = start XOR
  constant (because XOR self-inverses pairwise; 5 odd applications net
  one XOR). Easier to reason per-iteration than ROT13⁵.

**Scope:**

- New spec node kind in `core/types.ts`:
  ```ts
  type ForEachSubgraphNode = {
    readonly kind: "for-each-subgraph";
    readonly id: string;
    readonly label?: string;
    readonly iterationCount: number | { readonly fromParam: string };
    readonly children: readonly StepNode[];
    // Slice 2.0b widens with inputArrayPort? + outputsPort?.
    // Slice 2.0c widens with feedback/lookback fields per Open #N4.
  };
  ```
- `StepNode` discriminated union gains the new `kind` variant in
  `core/types.ts`; `core/spec-shapes.ts` validator (`validateShapes`)
  recognizes the new variant.
- `core/document-schema.ts` Zod schema gains the new variant — saved
  documents using it must round-trip through Save/Share unchanged.
- Runtime walker (`runtime.ts::walk`) handles `kind ===
  "for-each-subgraph"`:
  - Resolve iteration count: literal `iterationCount` if number, else
    `params[iterationCount.fromParam]` from the closest containing leaf
    (or from a sibling param accessor — exact mechanism settled at
    implementation; matches `iterate`'s `countFromAux` lookup pattern
    in shape).
  - Iterate N times. For iteration `i`:
    - Snapshot `state` (clone — same defensive copy `iterate` does today).
    - Walk children topologically using their `inputs` edge maps (so
      branched bodies work; sequential walking is just the special case
      where every child reads from the immediate predecessor).
    - Body's final state becomes the seed for iteration `i+1`.
    - Each emitted frame's stepId is suffixed with `:r{i}` per Q-2.0a-3.
      Nested under an `iterate` or outer for-each-subgraph: the outer
      `:b{j}` prefix concatenates → `<leafId>:b{j}:r{i}`.
- Toy fixture: `tests/runtime-for-each-subgraph-toy.test.ts`:
  - **Inner-only:** 5-iter XOR-with-constant on a 4-byte state.
    Expected final state = start XOR constant (5 odd applications).
    Per-iteration frames emit with `:r{0}` through `:r{4}` suffixes;
    state threads correctly.
  - **Nested:** 2-block outer `iterate` wrapping a 3-iter inner
    for-each-subgraph (or 2 outer for-each-subgraph blocks wrapping 3
    inner — TBD; the goal is exercising suffix composition). Expected
    frames: 2 × 3 = 6 body frames with `:b{0}:r{0}` … `:b{1}:r{2}`
    suffixes. Pinning the nested-suffix convention in the gate test.
- `default-registry.ts` untouched — `for-each-subgraph` is a spec node
  kind, not a step type.

**Pass/fail gate:**

- Type compiles.
- Inner-only toy: 5 frames emit with `:r{0}` through `:r{4}`; final
  state byte-equal to start XOR constant.
- Nested toy: 6 frames emit with composed `:b{i}:r{j}` suffixes; final
  state byte-equal to expected.
- Phase 1 frame-parity matrix (Slice 1.11) stays green — no legacy
  cipher uses the new node kind.
- `npm run check` green.

**If gate fails:** the contract design is wrong; surface to user,
re-open plan, no Slice 2.0b until fixed.

### Slice 2.0b — Iteration-outputs port + item-array input port (Q4 superset)

> **Status: 2.0b-i GREEN 2026-05-24 + 2.0b-ii GREEN 2026-05-24.** The
> sub-slices closed in two commits. 2.0b-i widened the
> `for-each-subgraph` node + runtime walker for item-array mode; 2.0b-ii
> lifted `split-blocks@1` + `concat-blocks@1` to `kind: "ported"` with
> the new `"matrix-cm-4x4-array"` aux-layout tag. **Plan amendment at
> 2.0b-ii slice start:** the original prose lumped both step types
> under "the State[] aux widening" but concat-blocks is genuinely
> shape-transforming on state (matrix-in / bytes-out — the same
> deferral surface `load-block`/`store-block` flagged at Slice 1.3).
> User picked **option C** (relax `stateToBytes` so `expected: "bytes"`
> accepts any non-bigint State variant) over option A (split-slice,
> defer concat-blocks) and option B (ProjectionMetadata asymmetric
> stateInputLayout/stateOutputLayout widening). Trade-off: a meta
> author who mis-declares `stateLayout: "bytes"` against a state-
> reading executor no longer surfaces at the encode boundary —
> they surface inside the executor's own shape check. Narrowed-by-
> one-shape guardrail; documented surface. BigIntState still throws.

**Goal:** widen the for-each-subgraph contract to handle the **outer
per-block** pattern (item-array input → iteration-outputs port). This
closes Phase 0 findings' `outBlocksAux` caveat with an explicit port
model and resolves Phase 1's Open #1 (`split-blocks` port shape).

**Scope:**

- For-each-subgraph node gains:
  - `inputArrayPort?: string` — when set, the runtime reads the named
    input port as a sequence (concatenated bytes per Open #N1 pick (b),
    or per-block ports per (a)) and feeds one item per iteration as
    the iteration's starting state.
  - `outputsPort?: string` — when set, the runtime accumulates each
    iteration's body-final-state into a sequence and emits it on the
    named output port at node exit.
- `split-blocks@1` is lifted with the chosen port shape (Open #N1):
  - (a) per-block ports (`block0`, `block1`, …): `meta.auxWritePorts`
    returns a dynamic map sized by computed block count.
  - (b) concatenated bytes single port: `meta.auxWritePorts` returns
    a single-entry map.
- `concat-blocks@1` symmetric (consumes whichever shape `split-blocks`
  produces).
- Toy fixture in `tests/runtime-for-each-subgraph-outer.test.ts`:
  - 3-block input (e.g., `<a, b, c>` each a 4-byte block), per-block
    iteration body is XOR-with-constant. Outer for-each-subgraph
    iterates the 3 blocks, body XORs each with the constant, outputs
    sequence is reconstructed via `concat-blocks` at node exit.
  - Pass/fail gate: final concatenated output byte-equal to expected;
    per-iteration frames emit with `:b{i}` suffix; iteration-outputs
    port populated correctly at node exit.

**User picks needed at slice start:**

- **Open #N1** (`split-blocks` port shape). Default candidate per
  Phase 1 Decision B precedent: (a) per-block ports.

**Pass/fail gate:**

- Toy fixture passes byte-equal.
- Phase 1 frame-parity matrix stays green.
- Lifted `split-blocks@1` + `concat-blocks@1` produce byte-equal frames
  to their legacy counterparts (the two were deferred from Phase 1's
  Slice 1.3 for exactly this design surface).
- `npm run check` green.

**If gate fails:** the iteration-outputs port semantics is wrong;
surface, re-open, no Slice 2.0c until fixed.

### Slice 2.0c — Per-iteration feedback/lookback contract — SHIPPED 2026-05-24

**Status: GREEN 2026-05-24.** Three advisor-sharpened user picks
landed before authoring (Open #N4 + two follow-on questions the plan
prose hadn't surfaced); new `ForEachSubgraphWithHistoryNode` ships as
a sibling `StepNode` kind with declarative lookback offsets +
per-invocation history seeded from parent state bytes +
snapshot+restore aux semantics. Suite at **1791/1791** (+18 new tests
in `tests/runtime-for-each-subgraph-with-history.test.ts`); Phase 1
frame-parity matrix untouched (no shipped cipher uses the new kind);
bundle 554.37 KB gzipped (+~6 KB from 2.0b-ii's 548.39 KB).

**Three user picks LOCKED IN 2026-05-24** (advisor consult before
authoring sharpened the original (a/b/c) framing into ordered Q1/Q2/Q3):

- **Q1 (lookback declaration, closes Open #N4) = Declarative offsets.**
  Body declares `lookbackOffsets: readonly number[]` (e.g., `[2, 7, 15,
  16]` for SHA-256). Runtime sizes a ring buffer to `max(offsets)` and
  exposes only the requested priors via `aux["prior-{N}"]`. Memory
  bounded; data dependency explicit in spec. Mirrors PortContract's
  declarative-input posture. **Imperative full-history** option
  (plan's original (a) — `aux.priorIterations: Uint8Array[]` channel)
  rejected: doesn't bound buffer in advance, doesn't surface
  dependency in spec, and offers no real simplicity once you realize
  runtime still has to know `max(offset)` to know when to seed it.
  **Hand-rolled 48 leaves** (plan's (c)) rejected as dominated:
  pedagogy claim illusory (a/b emit identical `:r{t}` frames), spec
  size blows up (~240 nodes for the schedule alone; worse for
  SHA-512), authoring cost wildly different. Stays in plan as escape
  hatch if the toy fixture had surfaced unrecoverable complexity (it
  didn't).
- **Q2 (packaging) = Sibling node kind `for-each-subgraph-with-history`.**
  NOT a third mode on `for-each-subgraph`. The 2-mode invariant block
  in `runtime.ts::runForEachSubgraph` (item-array vs state-thread) is
  already ~90 lines of partial-fields × both-modes-set checks; a third
  mode would multiply to 3-choose-2 = 3 pairwise invariants and make
  the validator harder to read. Sibling kind keeps each kind's
  invariants local; the type-system discriminant carries the "these
  fields are inseparable" constraint without runtime ceremony.
  Mechanical cost is small: one new `StepNode` discriminant, one new
  Zod schema variant, one new `validateShapes` branch, one new walker
  function.
- **Q3 (reset scope) = Per-outer reset.** History buffer is a local
  variable inside `runForEachSubgraphWithHistory` — each invocation
  freshly initializes from parent state. When wrapped inside an outer
  iteration kind (iterate / for-each-subgraph / a future
  persistAcrossOuter-enabled FES-with-history), each outer iteration
  triggers fresh history. The aux snapshot+restore protocol (snapshot
  pre-existing `prior-{N}` values before the loop; restore after)
  preserves the surrounding scope's aux state across the node's
  lifetime — friendly to nesting and to specs that happen to use
  `prior-N`-shaped keys elsewhere. **Persist-across-outer** rejected:
  no shipped or near-future consumer needs it; YAGNI. Future cipher
  with cross-block history would add `persistAcrossOuter?: boolean`
  flag as the obvious mechanical extension.

**Contract finalized for Phase 2 onward** (per Invariant 3):

```ts
type ForEachSubgraphWithHistoryNode = {
  readonly kind: "for-each-subgraph-with-history";
  readonly id: string;
  readonly label?: string;
  readonly iterationCount: number | { readonly fromParam: string };
  readonly children: readonly StepNode[];
  readonly lookbackOffsets: readonly number[];
  readonly historyEntryByteLength: number;
};
```

Lifecycle per invocation:
1. **Validate** — `lookbackOffsets` non-empty + all positive integers;
   `historyEntryByteLength` positive integer; parent `state.shape ===
   "bytes"`; `state.bytes.length % historyEntryByteLength === 0`;
   seed count (`bytes.length / entryLen`) ≥ `max(offsets)`;
   `iterationCount` is literal number ≥ 0 (param-form deferred per
   Slice 2.0a precedent).
2. **Seed** — slice parent `state.bytes` into `historyEntryByteLength`
   chunks, defensive-copy each into local `history` array.
3. **Snapshot** — capture pre-existing `aux["prior-{N}"]` per offset
   (or absence) into a Map.
4. **Per iteration** — set `aux["prior-{N}"] = history[absIndex - N]`
   for each declared offset; reset state to zero `Uint8Array(entryLen)`;
   walk children with `:r{t}` suffix; validate body's exit state
   (bytes-shape AND length=entryLen); push defensive copy into history.
5. **Restore** — delete keys that were absent before; restore prior
   values for keys that were present.
6. **Exit** — concatenate full history (seeds + outputs) into a flat
   `BytesState`; assign to parent `state`.

**Touched files in this slice:**
- `src/core/types.ts` — `ForEachSubgraphWithHistoryNode` added to
  `StepNode` union with full doc-block (Q1/Q2/Q3 rationale, lifecycle
  invariants, aux key namespace caveat).
- `src/core/runtime.ts` — kind dispatch in `walk()`; new
  `runForEachSubgraphWithHistory` function paralleling
  `runForEachSubgraph` shape; widened `State` cast for TS-narrowing
  workaround when validating body exit state.
- `src/core/document-schema.ts` — `ForEachSubgraphWithHistorySchema`
  variant added to the discriminated union (no schemaVersion bump —
  pre-Slice-2.0c documents validate unchanged).
- `src/core/spec-shapes.ts` — new kind treated as bytes-in / bytes-out
  (body iteration starts with zero state of entryLen; node exit is
  concatenated history bytes).
- `src/core/graph.ts` — `ContainerNode.kind` widens to include
  `for-each-subgraph-with-history`; `walkSpec` builds container of
  that kind; `processScope` extends the iterate/for-each-subgraph
  spine-termination branch to cover the new kind (parent-scope spine
  treats it as one chain boundary; per-iteration spine inside the body
  is its own scope).
- `src/core/spec-mutations.ts` — `StepLocation.parent` + the visit
  walker's `parent` argument both widen to include the new kind;
  `duplicateRoundGroup` gains a defensive bail (same rationale as for
  `for-each-subgraph` — per-iteration content shifts aren't a designed
  operation); structural-diff walker (`computeStructuralChanges`)
  extends with two new branches so param edits inside both
  for-each-subgraph kinds surface in run-history-diff.
- `tests/runtime-for-each-subgraph-with-history.test.ts` (NEW, 18
  tests) — 8-iter XOR-shape happy path (cycle of period 3 with seeds
  [0x05, 0x03]) + iterationCount=0 degenerate case + fromParam
  deferral throw + composed `:b{i}:r{j}` suffix under iterate +
  12 contract-invariant throw cases (one per invariant for failure
  attribution clarity) + 2 aux-snapshot+restore behaviour tests
  (cleanup when absent before, restore when present before).

**Note on graph-view orphan warnings.** Body leaves declare reads of
`aux["prior-{N}"]` but no spec leaf writes those keys (the runtime
sets them between iterations). Slice 9 validateGraph's
`auxReadMissing` check will surface these as orange `!` glyphs on body
leaves — the intended user-visible signal for "this read is satisfied
by runtime, not by spec." Slice 2.10 graph-view polish lands a
honest depiction (lookback arrows from a virtual history-buffer node
into each body iteration); until then the orphan warning serves as
the explanation surface.

**Note on nesting two for-each-subgraph-with-history nodes.** Inner
overwrites the outer's `aux["prior-{N}"]` keys for the duration of the
inner's run, AND the inner's restore deletes/restores to PRE-inner
values, which correctly preserves outer's snapshot for resumption.
HOWEVER, an outer body leaf that ran *between* iterations and depended
on outer's `prior-{N}` value would see the wrong value after inner
returns (outer's runtime hasn't re-set its keys for the next outer
iteration yet). No shipped or planned consumer exercises this pattern;
defer the pattern audit until a real use case lands.

**Pass/fail gate — MET:**

- Toy fixture: 8 body frames emit with `:r0`..`:r7` suffixes; per-
  iteration aux reads populated; final exit state byte-equal to
  hand-computed full history. ✓
- Composed suffix nested under iterate: `:b{i}:r{j}` produced per
  type-order rule. ✓
- Phase 1 frame-parity matrix (Slice 1.11) green — no shipped cipher
  uses the new kind. ✓
- For-each-subgraph(-with-history) contract is now FINAL per
  Invariant 3 — Phase 2.1a+ may treat it as immutable.
- `npm run check` GREEN: biome + tsc + **1791/1791** vitest tests +
  vite build (~40s). Bundle 554.37 KB gzipped (+~6 KB from 2.0b-ii;
  Open #N8 envelope intact).

**Next:** Slice 2.1a — widen `StepRegistration.legacy` to optional +
ship `rotate-bits-right@1` as the first port-native registration.

### Slice 2.1a — `StepRegistration.legacy` optional + `rotate-bits-right@1`

**Goal:** widen the `StepRegistration` discriminated union so
`kind: "ported"` registrations may omit `legacy: StepExecutor`. Ship
the first port-native registration (`rotate-bits-right@1`) as evidence
the field's optionality is reachable.

**Scope:**

- `StepRegistration` in `core/registry.ts`:
  - `{ kind: "ported"; executor: PortedExecutor; shape: PortContract;
     doc: StepDocumentation; legacy?: StepExecutor }` — `legacy`
    becomes optional. Existing per-cipher tests (which rely on
    `legacy` being present for off-flag dispatch) continue to read it;
    when absent, the off-flag dispatch path throws with a clear
    "step type is port-native; requires portedDispatchEnabled: true"
    error.
- `rotate-bits-right@1` ships in `src/steps/rotate-bits-right.ts`:
  - Params: `{ bits: number, wordBits: 8 | 16 | 32 | 64 }`.
  - PortContract: one `input` port (polymorphic `byteLength`), one
    `output` port (same `byteLength` as input).
  - Layout tag on both ports: `"raw"` (Open #N5 may upgrade to
    `"word-array-be-32"` at Slice 2.2).
  - Executor: standard right-rotation over the interpreted word width;
    BE word codec inline (or via a shared helper if Slice 2.2 decides
    on a shared codec).
  - Registered as `{ kind: "ported", executor: rotateBitsRight,
    shape: rotateBitsRightPortContract, doc: rotateBitsRightDoc }` —
    NO `legacy` field.
- Test file: `tests/rotate-bits-right.test.ts`:
  - Round-trip pin (rotate right by 0 = identity).
  - Known-answer pin (rotate `0x12345678` right by 2 = `0x80123456`
    under wordBits=32).
  - Multi-word pin (8-byte input, wordBits=32, rotates each word
    independently).
  - Off-flag dispatch throws expected error.

**Pass/fail gate:**

- Type compiles with widened union.
- New test file all green.
- Phase 1 frame-parity matrix stays green (no shipped cipher uses
  `rotate-bits-right@1` yet).
- `npm run check` green.

### Slice 2.1b — `xor@1` widened N-way + `add-mod-32@1`

**Goal:** ship the remaining two primitives SHA-256 needs.

**Resolved at ship time (2026-05-24):**

- **Fork 1 — xor inputCount floor: N ≥ 1.** Single-operand identity is
  a legal authoring-time intermediate; reject N=0 (output byteLength
  undecidable). Pinned in xor's param-validation tests.
- **Fork 2 — add-mod-32 arity: N-way, NOT plan-literal 2-way.** The
  pre-ship sketch below reads "always 2 for SHA-256; future additions
  can widen" but the user-picked Fork 2 (2026-05-24) chose N-way for
  symmetry with `xor@1`. Modular addition is associative so the math
  is identical; SHA-256's `T1 = h + Σ1(e) + Ch + K[i] + W[i]` reads
  cleanly as one 5-operand node. Floor is N ≥ 2 (no single-operand
  identity case — indistinguishable from passthrough). Asymmetric
  N-floor vs xor (≥1) is intentional and documented in both
  executors' headers.
- **PortContract shape:** function-form on `inputs` (N varies),
  static-form on `outputs` (single fixed `output` port). Matches
  rotate-bits-right precedent and the "function form only when N
  varies on THIS side" rule from Slice 1.4.

**Scope (sketched — pre-ship, before Fork 2 resolution):**

- `xor@1` widened to N-way via `params.inputCount: N`.
  - **Per advisor sharpening S3:** each of N input ports reads from
    the spec's sink-only edge graph (`StepNode.inputs` map per Q-edges),
    NOT from `aux`. Port names: `operand0`, `operand1`, …
    `operand{N-1}`. PortContract `inputs` is function-form, returning
    the right map sized by `params.inputCount`.
  - Today's 2-way `xor` (if any exists port-native; aux-xor /
    xor-aux-into-state are 2-way variants) stays as-is — N-way is a
    new step type, not a widening of existing.
- `add-mod-32@1`:
  - Params: `{ inputCount: 2 }` (always 2 for SHA-256; future
    additions can widen). **[SUPERSEDED by Fork 2 above —
    ships N-way.]**
  - PortContract: 2 input ports + 1 output port, each polymorphic
    `byteLength` (must be multiple of 4 for 32-bit word arithmetic).
  - Executor: BE word decode, add modulo 2^32, encode back.
- Test files for each.

**Pass/fail gate:** KAT pins per primitive; Phase 1 matrix green.
**(Both gates met — suite 1869/1869.)**

### Slice 2.2 — Word-state encoding decision + Q-gate-9 extension — SHIPPED 2026-05-24

**Status: GREEN 2026-05-24.** Open #N5 resolved via user pick **(a+)**:
codec consolidation only, NO layout tag. See updated Open #N5 entry
above for rationale.

**What landed (4 files):**

- `src/core/word-codec.ts` (NEW) — per-width BE word codec + ROR
  helpers at all four canonical cryptographic word widths:
  `decodeBE8/16/32/64`, `encodeBE8/16/32/64`, `ror8/16/32/64`.
  32-bit-and-smaller paths use `number`; 64-bit uses `bigint` because
  JS number bit ops truncate to 32-bit. Per-width API instead of one
  parameterized `decodeBEWord(bytes, offset, bits)` because the unified
  return type `number | bigint` forces casts at every call site and
  BigInt allocation on the hot 32-bit path; per-width split also lets
  consumers with compile-time-known widths (add-mod-32) import only
  what they need. Width coverage extends to Speck rebuild (Phase 4b
  needs 16-bit) and SHA-512 (Phase 2c needs 64-bit).
- `src/steps/rotate-bits-right.ts` — inline `wordMask` / `decodeBE` /
  `encodeBE` / `ror32orSmaller` / `ror64` helpers removed; per-width
  helpers imported from `core/word-codec.ts`. Executor's `wordBits`
  dispatch HOISTED OUT of the per-word loop — picks the per-width
  triple once, runs a tight composed `decode → ror → encode` loop per
  branch. Net effect: 4 narrow loops instead of one parameterized
  loop, each lean enough for the JIT to inline cleanly.
- `src/steps/add-mod-32.ts` — inline `decodeBE32` / `encodeBE32`
  removed; imported from `core/word-codec.ts`. Header comment block
  updated to point at Slice 2.2 consolidation.
- `tests/word-codec.test.ts` (NEW, 44 tests) — direct unit coverage at
  every width: decode/encode KATs, decode/encode round-trip property,
  ROR identity (n=0), ROR small-rotation KATs hand-derived from the
  textbook formula, ROR full-rotation pair-composes-to-identity, high-
  bit unsigned handling (the load-bearing concern for the `>>> 0`
  coercions on 16/32-bit decode).

**Q-gate-9 framing (as adopted):** instead of extending Q-gate-9 to a
hypothetical `word-array-be-32` round-trip, the existing **26 rotate-
bits-right tests + 28 add-mod-32 tests** stand as the proof that the
shared codec produces byte-identical output to the deleted inline
helpers. Plus the 44 new word-codec direct tests pin the codec's own
behaviour. No separate parity-with-old-implementation test added — the
consumer suites already exercise every code path.

**Suite at 1913/1913** (+44 from word-codec). Bundle 567.76 KB gzipped
(+~9 KB from Slice 2.1b's 558.74 KB). Phase 1 matrix untouched.

**Pinned for future readers:** *layout tags appear when a consumer
needs them.* Adding `word-array-be-32` (or `-be-16`, `-be-64`) is a
~30-line follow-on commit if Phase 2.10's graph view eventually
demands word-vs-raw grey-out logic. Do not add speculatively.

**Next stop:** Slice 2.3 — Open #N3 (SHA-256 helpers Σ0/Σ1/Ch/Maj as
step types vs in-spec compositions vs hybrid).

### Slice 2.3 — SHA-256 helpers (Σ0, Σ1, Ch, Maj) — SHIPPED 2026-05-24

**Status: GREEN 2026-05-24.** Open #N3 resolved via user pick **(b)
Compositions** (the thesis-aligned answer; the advisor framing pinned
three constraints: (a) walks back Phase 1 cipher-specific elimination
work, (b)'s real cost is two genuinely universal primitives, and
Maj's XOR form `(x∧y) ⊕ (x∧z) ⊕ (y∧z)` avoids needing `or@1`). Suite
at **1968/1968** (+55 new across 3 test files); bundle **573.92 KB**
gzipped (+~6 KB from Slice 2.2's 567.76 KB). Phase 1 matrix
untouched. Open #N3 CLOSED.

**Two new primitives ship:**

- **`and@1`** (`src/steps/and.ts`) — N-way bitwise AND mirroring
  `xor@1`'s shape exactly. `inputCount` floor N≥1 (single-operand
  identity, useful during incremental authoring); operand ports
  `operand0..operand{N-1}`; output port `output`. Function-form input
  PortContract, static single-port output, polymorphic byteLength,
  `layout: "raw"`. 24 tests in `tests/and.test.ts` paralleling
  `xor.test.ts` (KATs, idempotence, annihilation, function-form
  exercise at multiple N values, dispatch-path guards).
- **`not@1`** (`src/steps/not.ts`) — 1-in 1-out bitwise complement,
  no params (NOT operates bit-by-bit; "any length" is the polymorphic
  byteLength on the input port). Fully-static PortContract (function
  form is overkill — N varies on neither side). 19 tests in
  `tests/not.test.ts` covering byte-wise flip KATs, involution
  property (¬¬x = x), length polymorphism, fresh-buffer invariant,
  dispatch-path guards.

**Composition KATs in `tests/sha256-helpers.test.ts` (12 tests):**

- Σ0(0x6A09E667) = **0xCE20B47E** — hand-derived TWO ways: (1) direct
  from textbook ROTR(H_0,2) ⊕ ROTR(H_0,13) ⊕ ROTR(H_0,22), with the
  gotcha digit pinned in a comment (ROR(H_0, 13) = 0x333B_504F, NOT
  0x3338_504F — the OR's nibble 4 is bits 19..16, where bit 19 of
  `H_0 << 19` is 1 from `H_0` bit 0; an earlier draft of the
  hand-derivation got this wrong by 0x03); (2) indirect via FIPS
  180-4 §A.1.1 round-0 working variables (T2 = a^(1) − T1; T1 =
  e^(1) − d^(0); Σ0(a) = T2 − Maj(a,b,c)). Both methods land on
  0xCE20B47E.
- Maj(H_0, H_1, H_2) = **0x3A6FE667** — hand-derived from textbook
  formula. Cross-pinned by oracle parity over all 8 SHA-256 IV
  words.
- TS oracle (rorU32/Σ0/Σ1/Ch/Maj via raw JS bit ops, `>>> 0` to
  collapse signed XOR back to unsigned) parity-checked against
  composition for: all 8 IV words (Σ0, Σ1); 5 IV-derived triples
  (Ch, Maj); 64 deterministic pseudo-random triples (all four
  helpers). 6 algebraic-property checks (Σ0(0)=0, Σ1(0xFFFFFFFF) =
  0xFFFFFFFF, Maj(x,x,x)=x, Ch(0,y,z)=z, Ch(0xFFFFFFFF,y,z)=y,
  Ch(x,y,y)=y).
- T2 = Σ0(a) + Maj(a,b,c) composes via `add-mod-32@1`: T2(H_0,H_1,H_2)
  = 0x0890_9AE5 (FIPS 180-4 §6.2.2 round-0 partial). Load-bearing
  integration check that all four port-native primitives chain
  correctly into a single intermediate value.

**Pinned trap caught (advisor consult pre-authoring):** plan's
pass/fail prose reads *"verified against `node:crypto`-based oracle"*
but `node:crypto` does NOT expose Σ0/Σ1/Ch/Maj — only full SHA-256.
The honest cross-check inside this slice is a hand-coded TS oracle
(implemented above); Slice 2.6 additionally cross-checks the full
SHA-256 hash against `node:crypto`. Advisor warning + Slice 2.1a
precedent (plan-cited KAT `0x12345678 ROR 2 = 0x80123456` was wrong)
together flagged the "hand-derive twice, cross-check" gate as
load-bearing — and it caught the ROR(H_0, 13) digit-4 error before
the test landed.

**Sign-extension gotcha:** JS `^` returns a SIGNED 32-bit number, so
the TS oracle's `(rorU32(x,2) ^ rorU32(x,13) ^ rorU32(x,22))` produces
a negative number when bit 31 ends up set. The composition's `beU32`
output is unsigned (via `>>> 0`). Initial test run flagged the
mismatch for SHA-256 IV words where the high bit comes through; fix
was `>>> 0` on the oracle's XOR result. Same care needed for any
future helper oracle.

**Touched files:**
- `src/steps/and.ts` (NEW, 232 lines)
- `src/steps/not.ts` (NEW, 125 lines)
- `src/ciphers/default-registry.ts` (+27 lines — 2 imports + 2
  registrations + register-block comment block updated)
- `tests/and.test.ts` (NEW, 24 tests)
- `tests/not.test.ts` (NEW, 19 tests)
- `tests/sha256-helpers.test.ts` (NEW, 12 tests)

**Pass/fail gate — MET:**
- `npm run check` GREEN: biome ci + tsc + **1968/1968** vitest (+55)
  + vite build (~40s).
- Bundle 573.92 KB gzipped — within Open #N8 envelope (Vite warns at
  500 KB, but the threshold is informational; bundle growth is on
  the per-slice radar).
- Hand-derived KATs match composition output byte-equal.
- Oracle parity holds across 64 pseudo-random triples + all 8 IV
  words.
- Phase 1 frame-parity matrix (Slice 1.11) green untouched — no
  shipped cipher uses `and@1` or `not@1` yet.

**Next stop:** Slice 2.4 — SHA-256 padding + length encoding + constants
(Open #N2 user pick: leaf-params vs `constant-load@1` primitive).

### Slice 2.4 — SHA-256 padding + length encoding + constants — SHIPPED 2026-05-24

**Goal:** ship SHA-256's preprocessing (padding + length) and
constants (K_0..K_63 + H_0..H_7) per **Open #N2** (constants entry
strategy).

**Ships three port-native primitives, all under the Slice 2.1+
posture (`kind: "ported"`, no `legacy`, no `meta`, no `shapeContract`;
reachable today via direct executor invocation in tests + the
dispatch-path guards):**

1. **`pad-with-byte@1`** — sentinel byte + zero fill to `padTarget`
   modulo `blockSize`. Params: `padByte`, `blockSize`, `padTarget`.
   For SHA-256: `{padByte: 0x80, blockSize: 64, padTarget: 56}`.
   Polymorphic byteLength on both ports (output length depends on
   run-time input length via `((padTarget - inputLen - 1) mod
   blockSize) + 1`).
2. **`append-be64-length@1`** — 8-byte BE encoding of original-message
   bit-length, appended to data. **Two static input ports** (`data`,
   `length-source`); one static output. The two-port decoupling is the
   load-bearing property: SHA-256 needs the length of the ORIGINAL
   message (not the post-padding data), so `length-source` wires to the
   pre-padding chain. No params. Polymorphic byteLength on all three
   ports.
3. **`constant-load@1`** — zero-input emitter of `params.bytes`. Empty
   static input map; **function-form output** with EXACT byteLength
   derived from `params.bytes.length`. First port-native primitive whose
   output byteLength is known at spec time (every prior port-native
   primitive's output length was polymorphic).

**Three user picks locked at slice start (after one advisor consult):**

- **Q1 (padding shape) = (a) Decompose into 3 primitives.** Advisor
  flagged that "SHA-256 padding ≠ ISO 7816-4 padding" (they share only
  the 0x80 sentinel; SHA-256's `mod 64 == 56` target + 8-byte length
  suffix are structurally different). User picked thesis-aligned
  decomposition (`pad-with-byte@1` + `append-be64-length@1`) over the
  monolithic `sha2.pad@1` (b) or the hybrid (c). Matches Slice 2.3's
  "(b) Compositions" precedent — primitives stay generic, the SHA-256
  spec composes them.
- **Q2 (constants — Open #N2 + sub-granularity) = (b) at 72 leaves.**
  Advisor surfaced a hidden granularity dimension under (b) — 72
  individual leaves vs. 2 tables vs. per-round bundled — user picked
  the maximally thesis-aligned option. Every constant becomes a visible
  chip in the graph.
- (Implicit) The padding primitive accepts a sentinel byte (not
  hardcoded 0x80) so the same primitive serves MD5, SHA-1, SHA-2-family
  and ISO 7816-4 (with `padTarget=0`). Width parameterization (blockSize +
  padTarget) covers SHA-512 / SHA-384 (`{0x80, 128, 112}`).

**Plan trap caught pre-implementation:** plan prose said "could lift
existing `iso7816-4-pad@1`" with parameterization for the length-suffix.
Advisor caught the lie-in-the-name risk — iso7816-4-pad would become a
step that does more than ISO 7816-4 padding. Decomposition into
`pad-with-byte@1` (generic) + `append-be64-length@1` (separate primitive)
sidesteps it.

**Touched files (8):**

- `src/steps/pad-with-byte.ts` — NEW (~230 lines incl. doc).
- `src/steps/append-be64-length.ts` — NEW (~165 lines incl. doc).
- `src/steps/constant-load.ts` — NEW (~205 lines incl. doc).
- `src/ciphers/default-registry.ts` — three new imports + three
  `r.register(...)` calls under a new "Slice 2.4" paragraph in the
  comment block; updated "Port-native primitives" header.
- `tests/pad-with-byte.test.ts` — NEW (24 tests).
- `tests/append-be64-length.test.ts` — NEW (17 tests).
- `tests/constant-load.test.ts` — NEW (31 tests).
- `tests/sha256-padding-composition.test.ts` — NEW (8 tests) — the
  load-bearing composition KAT, including a negative pin that flags
  the wrong wiring (length-source = padded data, not original message).

**Composition KAT** is the headline gate: `pad-with-byte@1` + then
`append-be64-length@1` over "abc" (3 bytes) produces the canonical
FIPS 180-4 §A.1 padded block (64 bytes, ending in `...0000 0000 0018`).
Cross-checked via hand-derived expected hex string. The
test file also pins H_0..H_7 = canonical FIPS 180-4 §5.3.3 sequences,
K_0/K_15/K_47/K_63 = FIPS 180-4 §4.2.2 spot-checks (4 chosen for
boundary coverage), and a 72-leaf-instantiation buffer-independence
smoke test.

**Sign-extension caveat** (from Slice 2.3) NOT triggered — the BE64
length encoding goes through `encodeBE64`'s bigint API which sidesteps
JS number-side 32-bit sign issues.

**Suite at 2048/2048** (+80 from Slice 2.3's 1968). Bundle: **585.51 KB
gzipped** (+~12 KB from Slice 2.3's 573.92 KB; carries the JS
`tsdoc`-comments + 3 new step files + their `detail` markdown
strings). Within Phase 2 envelope; still flags the Vite 500 KB warning
(Open #N8 informational).

**Phase 2 status:** 9 slices shipped (2.0a/b-i/b-ii/c, 2.1a/b, 2.2,
2.3, 2.4). 4 open spec decisions remain: **N1** (split-blocks port
shape — partially resolved at 2.0b), **N4** (lookback contract —
closed at 2.0c per design but specific lookback choices defer to
Slice 2.5), **N7** (cipher selector category — Slice 2.10), **N8**
(bundle size posture — informational, ~585 KB is past 500 KB
threshold; flag, not pre-engineer).

**Pass/fail gate (delivered):** padding KAT (composition of `"abc"`
matches FIPS 180-4 §A.1 byte-for-byte); constant byte-equality
(H_0..H_7 round-trip through `constant-load@1`).

**Next stop:** Slice 2.5 — message-schedule expansion (for-each-
subgraph-with-history wiring; first consumer of Slice 2.0c's contract).
σ0/σ1 helpers can either compose from existing primitives (consistent
with the Slice 2.3 + Slice 2.4 "(b) Compositions" precedent) or
re-open the Open #N3 framing for hash-specific helpers.

### Slice 2.5 — Message-schedule expansion — SHIPPED 2026-05-25

**Status: GREEN 2026-05-25.** Ships **`shift-bits-right@1`** as the
third foundational ARX primitive (after `rotate-bits-right@1` Slice
2.1a and `add-mod-32@1` Slice 2.1b), plus σ0/σ1 + W_0..W_63 message
schedule compositions per Slice 2.3 (b) precedent. Suite at
**2094/2094** (+46 new across 2 test files); bundle **590.43 KB**
gzipped (+~5 KB from Slice 2.4's 585.51 KB). Phase 1 matrix untouched.
Open #N4 lookback-shape concrete pick (offsets [2, 7, 15, 16]) baked
into the message-schedule emulation; will become a spec literal at
Slice 2.6.

**Plan-trap caught (pre-authoring advisor consult):** the plan prose
in this section read *"σ0/σ1 are different from Σ0/Σ1 (use ROR 7/18/3
and ROR 17/19/10 respectively)"* — wrong. Per FIPS 180-4 §4.1.2 the
THIRD operand of σ0 and σ1 is **SHR** (logical shift right, zero-fill),
NOT a third rotation. SHR drops the low n bits and zero-fills the top
n; ROR wraps them. Cannot be expressed via ROR alone (would need ROR
+ AND with a per-shift constant chip, which obscures the primitive's
identity in the trace and forces a per-shift `constant-load` for the
mask). The slice scope grew by one primitive: `shift-bits-right@1`
ships alongside the helper compositions. Iterative-slice-review
[[feedback_iterative_slice_review]] paid for itself.

**Ships one new primitive + two helper compositions + message
schedule:**

1. **`shift-bits-right@1`** (`src/steps/shift-bits-right.ts`, ~165
   lines incl. doc) — logical right-shift over each big-endian word.
   Params `{bits, wordBits ∈ 8|16|32|64}`. Mirror of `rotate-bits-
   right@1`'s shape: one polymorphic input port, one polymorphic
   output, `layout: "raw"` on both, per-width dispatch hoisted out of
   the inner loop. **One semantic divergence:** SHR by `bits ≥
   wordBits` short-circuits to all-zero output BEFORE entering the
   per-width loop, because JS `>>>` truncates the shift amount modulo
   32 (so raw `x >>> 32` returns `x`, not `0`). ROR is naturally
   periodic; SHR is not. Codec helpers `shr8/16/32/64` consolidated
   into `src/core/word-codec.ts` alongside the existing `ror*`
   siblings.
2. **σ0 / σ1 compositions** as test-level functions per Slice 2.3 (b)
   "Compositions" precedent. Three primitives chain: `rotate-bits-
   right@1` ×2 + `shift-bits-right@1` ×1 → `xor@1` (inputCount=3).
   No spec yet — port-native body wiring is Slice 2.6's payload; the
   composition lives in `tests/sha256-message-schedule.test.ts` for
   now, identical math to what the Slice 2.6 spec will produce.
3. **Message schedule W_0..W_63 emulation** — replicates the
   `for-each-subgraph-with-history` contract finalized in Slice 2.0c
   at test scope: seed W_0..W_15 from the 64-byte padded block (built
   via Slice 2.4's pad-with-byte + append-be64-length composition);
   compute W_16..W_63 via the FIPS 180-4 §6.2.2 recurrence
   `W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}` mod 2^32.
   The for-each-subgraph-with-history body would declare
   `lookbackOffsets: [2, 7, 15, 16]` and `historyEntryByteLength: 4`
   when wired in Slice 2.6.

**Oracle choice (advisor warning baked in):** FIPS 180-4 §A.1 does NOT
tabulate W_t directly — only the padded block, the per-round working
variables, and the final hash. The honest oracle is a TS-direct
re-implementation of the recurrence via raw JS bit ops (same pattern
as Slice 2.3's Σ0/Σ1 oracle, same sign-extension `>>> 0` discipline).
Two W_t values pinned as literal hand-derived KATs as defense against
oracle-side regressions:

- **W_16 = 0x61626380** — degenerate case (only one non-zero operand:
  W_0). Pins recurrence structure (offsets + sum-order) before σ0/σ1
  contribute.
- **W_17 = 0x000F0000** — σ1(0x00000018) contribution alone (all other
  operands are zero). The first W_t where σ1 actually fires. ROR-vs-
  SHR substitution regressions fail loudly here.

Plus σ0/σ1 themselves carry hand-derived KATs at single-bit inputs
(0x80000000) to pin the SHR's drop-vs-wrap divergence at the algebraic
boundary, plus oracle parity over all 8 IV words + 64 pseudo-random
words (deterministic LCG seed `0x0BADC0DE`, distinct from Slice 2.3's
`0xC0FFEE` so a shared latent oracle bug doesn't pass both suites).

**SHR-specific algebraic checks:**
- σ0(0xFFFFFFFF) = **0x1FFFFFFF** (NOT 0xFFFFFFFF — SHR³ zero-fills
  top 3 bits, so XOR with two all-ones words leaves the top 3 zero).
- σ1(0xFFFFFFFF) = **0x003FFFFF** (SHR¹⁰ zero-fills top 10 bits).
- These are the most direct witnesses that the composition routes
  through SHR, not ROR. A silent ROR-for-SHR substitution would
  produce 0xFFFFFFFF for both.

**Touched files (5):**

- `src/core/word-codec.ts` — added `shr8 / shr16 / shr32 / shr64`
  helpers + section block explaining the SHR-vs-ROR distinction and
  the `bits ≥ wordBits` caveat the executor handles.
- `src/steps/shift-bits-right.ts` — NEW (~165 lines incl. doc).
- `src/ciphers/default-registry.ts` — alphabetic-position import
  (between `serpent-sub-bytes` and `shift-rows`) + new
  `r.register("shift-bits-right@1", ...)` block + register-comment
  paragraph updated with Slice 2.5 context.
- `tests/shift-bits-right.test.ts` — NEW (30 tests) — KATs across
  all 4 wordBits, identity, multi-word independence, SHR ≥ wordBits
  short-circuit, information-loss property, param validation, both
  dispatch-path guards.
- `tests/sha256-message-schedule.test.ts` — NEW (16 tests) — σ0/σ1
  hand-derived KATs + algebraic SHR-divergence properties +
  W_0..W_63 schedule emulation for "abc" + W_16/W_17 literal KATs
  + TS-direct oracle parity over all 64 words + negative-check on
  alternative input ("a" message).
- `docs/plans/universal-port-phase-2-slices.md` — this Status section
  + the plan-prose fix in the Slice 2.5 description above (SHR-not-
  ROR correction).

**Pass/fail gate — MET:**
- `npm run check` GREEN: biome ci + tsc + **2094/2094** vitest (+46)
  + vite build (~42s).
- Bundle 590.43 KB gzipped (+~5 KB from Slice 2.4) — past Vite's
  500 KB threshold per Open #N8 (informational, not pre-engineer).
- Hand-derived KATs match composition output byte-equal (σ0 / σ1 /
  W_16 / W_17 literal pins).
- TS-direct oracle parity holds across all 64 W_t for "abc" + across
  8 IV words + 64 pseudo-random words for σ0/σ1.
- Phase 1 frame-parity matrix (Slice 1.11) green untouched — no
  shipped cipher uses `shift-bits-right@1` yet.

**Phase 2 status:** 10 slices shipped (2.0a/b-i/b-ii/c, 2.1a/b, 2.2,
2.3, 2.4, 2.5). 4 open spec decisions remain unchanged: **N1**
(partially resolved at 2.0b), **N4** (closed at 2.0c per design;
lookback offsets `[2, 7, 15, 16]` concrete pick baked into this
slice's emulation, becomes spec literal at Slice 2.6), **N7** (cipher
selector category — Slice 2.10), **N8** (bundle size — 590 KB,
informational).

**Next stop:** Slice 2.6 — compression function + outer block loop +
first end-to-end SHA-256. First slice where port-native primitives
exercise real spec edge-wiring (the runtime path that throws
*"requires spec edge-wiring (Slice 2.6+)"* today). Plus Open #N9
surface choice (spine-termination at for-each-subgraph boundary for
state-thread mode — SHA-256 compression is the forcing function).

### Slice 2.6 — Compression function + outer block loop + first end-to-end SHA-256

**Sub-sliced at 2.6 start (2026-05-25).** Advisor consult flagged that
the plan's prose for 2.6 glides past a load-bearing hidden foundation:
the spec edge-wiring mechanism doesn't exist yet, and you can't author
the SHA-256 spec without it. Splitting into:

- **Slice 2.6a** (this section) — Spec edge-wiring foundation (sink-
  side `portInputs` on leaves AND containers, runtime resolution, schema
  + validator, container `outputPorts`). Toy fixture pins the
  mechanism end-to-end.
- **Slice 2.6b** (next section) — Author the SHA-256 spec at
  `src/ciphers/sha-256.ts` on top of 2.6a's foundation; KAT against
  FIPS 180-4 §A.1 "abc". Open #N9 (spine-termination for state-thread
  for-each-subgraph) surfaces here when graph view first renders SHA-256
  compression — deferred from 2.6a start per advisor's option (c).

### Slice 2.6a — Spec edge-wiring foundation + toy fixture — SHIPPED 2026-05-25

**Status: GREEN 2026-05-25.** First end-to-end wiring path for port-
native primitives via sink-side `portInputs` on `StepLeaf` AND every
container kind (`StepGroup`, `IterateGroup`, `FeistelRoundGroup`,
`ForEachSubgraphNode`, `ForEachSubgraphWithHistoryNode`). Suite at
**2108/2108** (+14 new in the toy test file); bundle **592.88 KB**
gzipped (+2.45 KB from Slice 2.5's 590.43 KB). Phase 1 matrix
untouched.

**Resolved user picks (2026-05-25)** — surfaced before authoring,
covered Q-edges-1 through Q-edges-5 + builder-style for the eventual
SHA-256 spec:

- **Q-edges-1 (field name) = `portInputs`** — avoids collision with
  the existing `CipherSpec.inputs` (seed plaintext + key); mirrors
  `PortContract.inputs` vocabulary.
- **Q-edges-2 (scope) = Leaves AND containers** — containers expose
  declared output ports for downstream wiring; matches sink-only
  Q-edges intent fully.
- **Q-edges-3 (state-thread interaction) = Unbound ports fall back
  to implicit state thread** — preserves Phase 1's lift-via-projection
  behavior on lifted-legacy ports while letting portInputs override
  per-port. Pure port-native leaves (no `meta`) require every port
  wired; an unbound port throws.
- **Q-edges-4 (container output port names) = Author-declared per
  node, defaulting to `["out"]`** — single canonical output port
  carrying exit-state bytes; multi-output container semantics deferred
  until a real consumer surfaces.
- **Q-edges-5 (validation timing) = Spec-validator (pre-run, hard
  fail)** — validator emits `port-input-unwired` / `port-input-
  unresolvable` warnings AND runtime throws at leaf invocation if a
  reference can't resolve. Warnings cover editor authoring; throws
  are the Run-time gate.
- **Authoring style = Builder helper** — 2.6b will compose SHA-256
  via TypeScript builder functions emitting expanded leaves, mirroring
  AES's spec-builder precedent.

**Plan amendment after first author pass:** the initial 2.6a draft
shipped leaves-only (per a self-imposed scope reduction). Post-implementation
advisor consult caught the divergence from the Q-edges-2 pick — user
explicitly picked containers; the extension landed in the same commit.
Iterative-slice-review [[feedback_iterative_slice_review]] paid for
itself: container support is load-bearing for 2.6b's message-schedule-
into-compression handoff (the `for-each-subgraph-with-history` exit
needs to be readable from compression-body leaves).

**Ships (one slice, one commit):**

1. **`PortBinding` type + `StepLeaf.portInputs` field** (`core/types.ts`).
   Record-shaped (`Readonly<Record<string, PortBinding>>`) so the
   wiring map round-trips through JSON serialization without a custom
   Zod transformer (the trap that hit narrationOverride in Slice 1.10:
   `params: ReadonlyMap` got silently stripped on document decode).
2. **Container port-edge mixin** — every container kind (`StepGroup`,
   `IterateGroup`, `FeistelRoundGroup`, `ForEachSubgraphNode`,
   `ForEachSubgraphWithHistoryNode`) carries optional `portInputs?` AND
   `outputPorts?: readonly string[]` (default `["out"]`). The `portInputs`
   field on containers is purely forward-compatibility today — the
   runtime doesn't yet read it at container boundaries; only `outputPorts`
   is exercised in 2.6a.
3. **Runtime port-edge resolution** (`core/runtime.ts`). Per `walk`
   call (one per lexical scope), a `nodeOutputs: Map<nodeId, Map<port,
   Uint8Array>>` records every port-native leaf's outputs AND every
   container's exit-state bytes (via the new `publishContainerOutputs`
   helper). At each port-native leaf invocation: (a) resolve declared
   portInputs from `nodeOutputs` (throw on missing node or port), (b)
   fall back to `meta.stateInputPort` / `meta.auxReadPorts` projection
   for unbound ports on lifted-legacy steps, (c) for pure port-native
   leaves (no meta) verify every declared input port is wired (else
   throw with a sharper "input port X is not wired" message).
   Scope-isolation by construction — each recursive `walk` call gets
   its own `nodeOutputs` so iterate / for-each-subgraph iterations
   can't accidentally leak.
4. **Container exit-state publication** — `publishContainerOutputs(id,
   outputPorts)` encodes the current `state` via
   `stateToPortBytes(state, state.shape)` and writes the bytes under
   every declared port name. All shipped exit shapes (`bytes`,
   `matrix4x4-bytes`, `bitvec`) are encodable; bigint throws (no
   container produces it today). Container outputs do NOT carry layout
   metadata — downstream consumers see raw bytes regardless of whether
   the container exited as a matrix or as flat bytes. Acknowledged
   ship-as-is: a future cipher wiring `iterate/out` (matrix4x4-bytes,
   16 bytes) into a port-native primitive expecting `raw` would silently
   miss the layout mismatch. Surface when it bites; don't pre-engineer.
5. **Schema round-trip support** (`core/document-schema.ts`). Added
   `PortBindingSchema` + `portInputs` to `StepLeafSchema` + shared
   `containerPortEdgeFields` (portInputs + outputPorts) spread into
   every container schema. Pre-2.6a documents (no portInputs anywhere)
   validate unchanged.
6. **Validator** (`core/spec-shapes.ts`). New `GraphWarning` kinds:
   `port-input-unwired` (pure port-native leaf has an input port with
   no declared binding) and `port-input-unresolvable` (declared binding
   references a missing node or a port the upstream doesn't emit). The
   walker builds a scope-local `scopeOutputs` map matching the runtime's
   `nodeOutputs` scoping, then validates leaf bindings against it. The
   `<WarningGlyph>` renderer in `GraphView.tsx` formats both new kinds
   for the in-editor tooltip.
7. **Toy fixture** (`tests/runtime-port-edge-wiring-toy.test.ts` —
   15 tests across 6 describe blocks):
   - **Happy path** (4-leaf chain `constant-load → constant-load →
     rotate-bits-right → xor`) — pins the wiring math
     (`ROR32(0x01020304, 8) = 0x04010203`; XOR with mask = expected).
   - **Unwired port** — validator emits warning; runtime throws.
   - **Unresolvable refs** — both `missing-node` and `missing-port`
     warnings; both runtime throw paths pinned.
   - **Container outputs** — group wraps a `byte-substitution` leaf;
     downstream `xor` reads `group/out` to verify container exit-state
     publication. Wrong port name surfaces `missing-port`.
   - **Mixed-mode (Q-edges-3)** — lifted-legacy `byte-substitution`
     with `portInputs` override on the `state` port; pins that
     portInputs override BYPASSES the state-thread projection (the
     contrast between an all-`0xff` initial state and a constant-load
     source `[0..15]` makes the override observable via S-box output).
   - **Document round-trip** — `portInputs`-bearing spec encodes to
     JSON, decodes via `CipherDocumentSchema`, leaves' portInputs maps
     survive byte-identical. Insurance against the narrationOverride
     silent-strip trap.
   - **Off-flag passthrough** — running a portInputs spec with
     `portedDispatchEnabled: false` still hits the legacy guard.
8. **Updated 9 existing port-native step tests** — their on-flag
   dispatch-error tests previously asserted the "requires spec edge-
   wiring (Slice 2.6+)" placeholder throw; all updated to assert the
   new per-port "input port X is not wired" guard. `constant-load` is
   the special case (zero input ports) — its test now asserts success
   (a single-frame trace) since there's nothing to throw on.

**Touched files (10 src + 11 tests):**

- `src/core/types.ts` — `PortBinding` type + `StepLeaf.portInputs`
  field + container port-edge mixin on 5 container types.
- `src/core/document-schema.ts` — `PortBindingSchema` + portInputs on
  StepLeafSchema + shared `containerPortEdgeFields` on every container
  schema.
- `src/core/runtime.ts` — scope-local `nodeOutputs` map,
  `publishContainerOutputs` helper, restructured port-native dispatch
  to resolve portInputs first, fall back to meta projection, throw on
  unwired ports.
- `src/core/spec-shapes.ts` — `scopeOutputs` map + `recordContainerOutputs`
  helper + per-leaf port-input validation emitting `port-input-unwired`
  / `port-input-unresolvable`.
- `src/core/graph.ts` — `GraphWarning` discriminated-union widened with
  two new kinds.
- `src/ui/components/GraphView.tsx` — `formatWarning` extended with
  the two new kinds (renders inline in the warning glyph tooltip).
- 9 existing port-native test files updated to assert the new
  "input port X is not wired" throw instead of the placeholder
  "requires spec edge-wiring" message (`constant-load` switches to a
  success assertion since it has zero input ports).
- `tests/runtime-port-edge-wiring-toy.test.ts` — NEW (15 tests).
- `docs/plans/universal-port-phase-2-slices.md` — this status section.

**Pass/fail gate — MET:**
- `npm run check` GREEN: biome ci + tsc + **2108/2108** vitest (+14)
  + vite build (~42s).
- Bundle 592.88 KB gzipped (+2.45 KB from Slice 2.5) — past Vite's
  500 KB threshold per Open #N8 (informational, not pre-engineer).
- All four port-native primitives (rotate-bits-right, xor, add-mod-32,
  shift-bits-right, and, not, pad-with-byte, append-be64-length,
  constant-load) reachable end-to-end from a `runSpec` dispatch call
  via portInputs declarations.
- Phase 1 frame-parity matrix (Slice 1.11) still green — no shipped
  legacy/lifted-legacy spec uses `portInputs` yet, so the off-flag
  + on-flag parity holds unchanged.

**Phase 2 status:** 11 slices shipped (2.0a/b-i/b-ii/c, 2.1a/b, 2.2,
2.3, 2.4, 2.5, 2.6a). 4 open spec decisions remain: **N1** (closed at
2.0b), **N4** (closed at 2.0c, baked into 2.5's emulation, becomes
spec literal at 2.6b), **N7** (cipher selector category — Slice 2.10),
**N8** (bundle size — 593 KB, informational), **N9** (spine-termination
mode — deferred to mid-2.6b per the iterate-slice-review pattern).

**Next stop:** Slice 2.6b — author SHA-256 spec at `src/ciphers/sha-256.ts`
via builder helper, KAT against FIPS 180-4 §A.1 "abc". Open #N9
spine-termination user pick surfaces when graph view first renders
SHA-256 compression.

### Slice 2.6b — Author SHA-256 spec + first end-to-end "abc" KAT

**Goal:** on top of 2.6a's edge-wiring foundation, build the SHA-256
spec via a builder helper and run the FIPS 180-4 §A.1 "abc" KAT.
First port-native cipher.

**Scope (sketched):**

- Compression function body (64 rounds): T1 = h + Σ1(e) + Ch(e,f,g) +
  K_t + W_t; T2 = Σ0(a) + Maj(a,b,c); h=g, g=f, f=e, e=d+T1, d=c, c=b,
  b=a, a=T1+T2.
- After compression: 8-way add-mod-32 of working variables (a..h) into
  hash state (H_0..H_7).
- Outer per-block loop (`for-each-subgraph` item-array per Slice 2.0b
  / state-thread per Slice 2.0a — exact mode picked at slice start
  based on the topology that emerges). Outer state-thread = running
  hash state H_0..H_7 across blocks.
- Cipher spec authored at `src/ciphers/sha-256.ts` via builder helpers
  (e.g., `buildCompressionRound(t: number)`) per the user pick on
  authoring style. Saved-document JSON is fully expanded; helpers
  exist only at spec-construction time.
- KAT test: `tests/sha-256.test.ts` runs single-block "abc" KAT
  (FIPS 180-4 §A.1, expected
  `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`).
- Open #N9 user pick surfaces mid-slice when graph view first renders
  SHA-256 compression and the spine-suppression-at-for-each-subgraph
  boundary bug becomes visible.

**Pass/fail gate:** "abc" KAT passes byte-equal; per-frame trace exists
for every leaf execution (compression: 64 rounds × ~8 ops + helpers;
message schedule: 48 rounds × ~4 ops; padding + final = ~600 frames
per block).

### Slice 2.7 — Spec-level `requiresPortedDispatch` opt-in plumbing

**Goal:** wire the spec-level opt-in mechanism so the live UI can
launch SHA-256 (Slice 2.10's cipher selector) without a hand-rolled
flag.

**Scope (sketched, pure plumbing):**

- `CipherSpec` gains optional `requiresPortedDispatch?: boolean` field
  (OR: registry-derives by walking spec and checking any leaf
  `registration.kind === "ported"`). Pick at slice start.
- Spec store in `src/ui/stores/spec.ts` reads the field/derivation;
  passes `portedDispatchEnabled: true` to `runSpec` when applicable.
- `document-schema.ts`: schema bump if Q-pick is (a) explicit field.
  No bump needed if (b) registry-derived.
- Per-cipher tests untouched (they already use direct flag).

**Pass/fail gate:** SHA-256 spec runs end-to-end via the spec store
without a direct test flag; AES-128 / Speck32-64 / Serpent-128 / DES
specs continue to run under `portedDispatchEnabled: false` by default;
Phase 1 matrix still green.

### Slice 2.8 — `narrationOverride` populated for every SHA-256 leaf

**Goal:** first shipped use of Slice 1.10's foundation field.

**Scope (sketched):**

- Every SHA-256 leaf in the spec carries `narrationOverride:
  StepDocumentation` with cipher-specific prose. Examples:
  - `rotate-bits-right` leaf in Σ0's first rotation: override name to
    "ROR(x, 2) for Σ0", summary cites FIPS 180-4 §4.1.2.
  - `add-mod-32` leaf for T1: override name to "T1 = h + Σ1(e) +
    Ch(e,f,g) + K_t + W_t", references FIPS 180-4 §6.2.2.
  - `for-each-subgraph` outer block leaf: override summary to
    "SHA-256 processes the message in 512-bit blocks".
- `<StepDescription>` already reads `narrationOverride` per Slice 1.10
  wiring — no UI changes.

**Pass/fail gate:** every SHA-256 leaf renders cipher-specific
narration in `<StepDescription>` (manual browser smoke + unit test
walking the spec asserting `narrationOverride` is non-null on every
leaf).

### Slice 2.9 — Provenance overlay registry for SHA-256

**Goal:** wire cell-level provenance for SHA-256 words — hovering an
output word lights up source words in the consumed inputs (e.g.,
hovering T1 lights up h, e, f, g, K_t, W_t).

**Scope (sketched):**

- New `src/ui/provenance/sha-256.ts` module registers provenance
  callbacks for SHA-256-specific leaves.
- Contract test at `tests/provenance-registry-contract.test.ts`
  (existing) walks the registry; SHA-256's leaf types either register
  provenance OR land on `PROVENANCE_NO_OP_ALLOWLIST`.

**Pass/fail gate:** contract test green; manual browser smoke confirms
provenance highlighting works in linear view.

### Slice 2.10 — Graph view treatment + cipher selector entry

**Goal:** SHA-256 selectable from the live UI; graph view renders
SHA-256 with the for-each-subgraph node visualized cleanly.

**Scope (sketched):**

- User pick on **Open #N7** (cipher selector category — sibling vs.
  hash category) at slice start.
- Cipher selector updated per Q-pick.
- `SUPPORTED_CIPHER_MODES_BY_CIPHER` in `stores/cipher-mode.ts`
  updated.
- `defaults` in `stores/spec.ts` updated.
- Graph view's for-each-subgraph node rendering: probably mirrors
  iterate's existing visual (collapsible container). Feedback contained
  inside per parent plan's Q3 pass criteria.

**Pass/fail gate:** SHA-256 launches from UI; graph view renders
without warnings; smoke test in browser.

### Slice 2.11 — KAT parity matrix (Phase 2 close)

**Goal:** comprehensive KAT coverage gating Phase 2 close.

**Scope (sketched):**

- `tests/sha-256-kat-matrix.test.ts`:
  - FIPS 180-4 §A.1 single-block "abc" KAT.
  - FIPS 180-4 §A.2 multi-block 448-bit message KAT.
  - NIST CAVS short-message + long-message KATs (cross-checked with
    `node:crypto.createHash('sha256')` per project's external-oracle
    convention).
  - Multi-block stress test: 10 MB random input, byte-equal to
    `node:crypto` output (run guarded behind opt-in flag to keep
    `npm run check` under 60s).
- Final Phase 2 exit gate: all KATs green + `npm run check` green.

**Pass/fail gate:** all KATs byte-equal; total test count documented
(estimated 1748 prior + ~30 new across Slices 2.0–2.11 = ~1780).

## Phase 2 exit criteria

- All 15 sub-slices green individually.
- `npm run check` green at HEAD.
- SHA-256 spec ships under the universal-port contract end-to-end:
  - `rotate-bits-right@1`, `xor@1` (N-way), `add-mod-32@1` registered
    as `kind: "ported"` with NO `legacy` field.
  - `for-each-subgraph` spec node kind handles all three patterns
    (state-thread, item-array, feedback/lookback).
  - Spec-level `requiresPortedDispatch` opt-in plumbed.
  - `narrationOverride` populated for every SHA-256 leaf.
  - Provenance overlay registered for SHA-256.
  - SHA-256 selectable from the live UI; graph view renders cleanly.
- KAT parity matrix passes byte-equal vs. FIPS 180-4 §A.1 + §A.2 +
  `node:crypto` cross-check.
- Phase 1 frame-parity matrix (Slice 1.11) stays green untouched.

## Out of scope for Phase 2

- **AEAD / MAC / KDF.** SHA-256 is the first hash; AEAD / HMAC / HKDF
  ride on top in Phase 2b or Phase 3+.
- **SHA-224 / SHA-384 / SHA-512.** SHA-224 is trivial (same algo,
  different IV + truncated output) and a Phase 2b candidate. SHA-512
  needs 64-bit word arithmetic — likely needs `add-mod-64@1` +
  `rotate-bits-right` widened to `wordBits=64`; defer to Phase 2c.
- **AES / Speck / Serpent / DES rebuilds from medium primitives.**
  Phase 3+ (`aes` rebuild) and Phase 4+ (per-cipher rebuilds).
- **`bigint` layout** — defers to RSA / elliptic-curve future cipher.
- **Compose-and-save (b) for SHA-256 sub-primitives** — user composes
  Σ0 from rotate+xor and saves as a named element. Phase 4f per parent
  plan.
- **Hierarchical trace** (iii) — collapsible per-iteration drill-down
  for the scrubber. Per Q3-frame deferral; Phase 2's ~600 frames per
  block uses the flat trace and accepts the long scrubber.
- **TraceFrame port-info merge** — `PortedFrame` collapsing into
  `TraceFrame` (Phase 1 out-of-scope item 1.13+). Deferred again to
  whenever the graph edge-model simplification needs it.

## Operational notes

- **Commit cadence:** one commit per sub-slice. Co-author trailer per
  project convention.
- **Push cadence:** after each commit lands locally + check green.
- **Failure handling:** if a sub-slice gate fails, surface to user; do
  not silently continue. The previous green sub-slice is the rollback
  point.
- **Iterative slice review** (per memory
  `feedback_iterative_slice_review.md`): re-consult advisor before
  each new slice that surfaces a non-trivial design surface. Slices
  2.0a / 2.0b / 2.0c / 2.2 / 2.3 / 2.4 / 2.7 / 2.10 all carry user
  picks that warrant re-consult before authoring.
- **Bisect plan:** Slice 2.0a introduces the spec node kind on a toy
  fixture — that's the "baseline green" commit. If a later slice's
  KAT goes red, bisect from there forward.
- **Bundle size** (Open #N8): flag in commits if size grows >50 KB in
  any single slice; otherwise carry forward.
- **Frame-count budget:** SHA-256 traces are ~600 frames per block.
  Linear-view scrubber handles this — no Phase 2 work to shorten.
  Hierarchical trace (deferred) is the right long-term answer.
