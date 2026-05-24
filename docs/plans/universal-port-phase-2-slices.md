# Universal port-based dataflow — Phase 2 sub-slice plan

> **Status: DRAFT 2026-05-24 + Slice 2.0a GREEN 2026-05-24 + Slice 2.0b-i
> GREEN 2026-05-24 + Slice 2.0b-ii GREEN 2026-05-24.** Drafted after
> Phase 1 closed (1748/1748 tests, all 13 sub-slices + caveat 1+3
> follow-up green) and two advisor consults framed the Phase 2 surface.
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
> Next stop: **Slice 2.0c** (per-iteration feedback/lookback contract
> per Open #N4) — the third forcing requirement for SHA-256's message
> schedule.
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

### Open #N5 — Word-state encoding for SHA-256 (decided at Slice 2.2)

SHA-256 works on 8×32-bit BE words. Three candidates:

- (a) **Flat `bytes` layout with implicit BE-word interpretation in step
  executors.** Same posture as Speck today. Simplest; layout tag is
  the existing `"raw"`. Step executor decodes bytes → words at entry,
  encodes back at exit. Risk: every word-aware step duplicates the
  byte↔word codec.
- (b) **New `word-array-be-32` layout tag on PortContract.** Advisory
  only per Q1 hybrid posture — runtime still passes `Uint8Array`. Step
  executors share a codec helper. Matches `matrix-cm-4x4` precedent —
  honest about what the bytes mean. Q-gate-9 extends to validate
  word-array round-trip through project/reconstruct.
- (c) **New State variant `WordArrayState`.** Larger contract change;
  the universal-port plan's whole thesis is "State variants collapse
  to Uint8Array at the runtime layer." A new State variant would
  contradict that. Listed for completeness; almost certainly rejected.

**Forcing function:** Phase 0 findings (`port-projection.ts:299-314`)
already TODO-mark bitvec and bigint deferral. Word-array slots into the
same gap; Slice 2.2 makes the canonical pick.

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

### Open #N2 — Constants entry strategy (decided at Slice 2.4)

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

User pick at Slice 2.4 start.

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

### Slice 2.0c — Per-iteration feedback/lookback contract

**Goal:** widen the for-each-subgraph contract to handle the
**message-schedule** pattern (W_t reads W_{t-2,7,15,16}). This is the
third forcing requirement; SHA-256's message schedule cannot be
expressed without it.

**Scope:**

- For-each-subgraph contract gains feedback/lookback support per
  **Open #N4 user pick**:
  - (a) `aux.priorIterations: Uint8Array[]` channel populated by runtime
    before each iteration's body walks.
  - (b) Sibling node kind `for-each-subgraph-with-history@1` with
    explicit lookback port declarations.
  - (c) Hand-rolled 48 leaves (no iteration primitive for message
    schedule).
- Toy fixture in `tests/runtime-for-each-subgraph-feedback.test.ts`:
  - Fibonacci-shape 10-iteration generator: each iteration's output is
    `prior[-1] + prior[-2]` (mod 256, for 1-byte arithmetic). Starting
    seeds: `[1, 1]`. Expected sequence: `1, 1, 2, 3, 5, 8, 13, 21, 34,
    55`.
  - Pass/fail gate: 10 frames emit; sequence byte-equal to expected;
    feedback channel correctly populated per iteration.

**User picks needed at slice start:**

- **Open #N4** (feedback/lookback contract shape). Default candidate:
  (a) single node kind with `aux.priorIterations` channel — single
  vocabulary item handles all three patterns. (c) is the escape hatch
  if (a) and (b) both surface unacceptable complexity.

**Pass/fail gate:**

- Toy fixture passes byte-equal.
- Phase 1 frame-parity matrix stays green.
- For-each-subgraph contract is now FINAL — invariant 3 above.
  Subsequent slices treat it as immutable.
- `npm run check` green.

**If gate fails:** the contract can't accommodate all three patterns;
either re-design feedback shape, OR accept (c) hand-rolled message
schedule and skip iteration primitive for that case. Surface, re-open.

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

**Scope (sketched):**

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
    additions can widen).
  - PortContract: 2 input ports + 1 output port, each polymorphic
    `byteLength` (must be multiple of 4 for 32-bit word arithmetic).
  - Executor: BE word decode, add modulo 2^32, encode back.
- Test files for each.

**Pass/fail gate:** KAT pins per primitive; Phase 1 matrix green.

### Slice 2.2 — Word-state encoding decision + Q-gate-9 extension

**Goal:** resolve **Open #N5** (word-state encoding). Extend
`port-projection.ts` + `LayoutTags` to round-trip the chosen encoding.

**Scope (sketched):**

- User pick on (a) / (b) / (c) at slice start.
- If (a): no changes; `rotate-bits-right` and `add-mod-32` keep `"raw"`
  layout; word-codec helper lives in `core/word-codec.ts` shared by
  step executors.
- If (b): new layout tag `"word-array-be-32"` added to `LayoutTags`
  union; `port-projection.ts::stateToBytes` / `bytesToState` handle it
  symmetrically; `auxPortBytesToValue` extended to decode.
- If (c): new State variant — heavyweight; deferred unless (a) and (b)
  both fail.
- Q-gate-9 round-trip pin extended: synthetic frame with word-array
  layout round-trips through project/reconstruct byte-equal.

**Pass/fail gate:** round-trip pin green; Phase 1 matrix green;
`npm run check` green.

### Slice 2.3 — SHA-256 helpers (Σ0, Σ1, Ch, Maj)

**Goal:** resolve **Open #N3** (step types vs compositions).

**Scope (sketched):**

- User pick on (a) / (b) / (c) at slice start.
- If (a) step types: 4 new step types
  (`sha2.sigma-0@1`, `sha2.sigma-1@1`, `sha2.ch@1`, `sha2.maj@1`).
- If (b) compositions: 0 new step types; new `and@1` + `not@1`
  primitives ship in this slice (Ch/Maj need them).
- If (c) hybrid: Σ0/Σ1 compositions; Ch/Maj as step types.

**Pass/fail gate:** KAT pins per helper (Σ0(0x6a09e667) = …, etc.,
verified against `node:crypto`-based oracle).

### Slice 2.4 — SHA-256 padding + length encoding + constants

**Goal:** ship SHA-256's preprocessing (padding + length) and
constants (K_0..K_63 + H_0..H_7) per **Open #N2** (constants entry
strategy).

**Scope (sketched):**

- SHA-256 padding: append `0x80`, then `0x00` bytes until length ≡ 56
  (mod 64), then 8-byte BE message length in bits.
  - Could lift existing `iso7816-4-pad@1` (which is similar — append
    `0x80` + zeros) with a parameterization for the length-suffix?
    Decide mid-slice; default likely a new `sha2.pad@1` step type.
- Constants per Open #N2:
  - (a) leaf params: K's embedded in compression-round leaves.
  - (b) `constant-load@1`: new primitive; 72 leaves in the spec
    (8 H constants + 64 K constants).
- Initial hash values H_0..H_7 (FIPS 180-4 §5.3.3) seeded into the
  compression loop's starting state.

**Pass/fail gate:** padding KAT (padding of `"abc"` matches FIPS 180-4
§A.1); constant byte-equality (H_0 = `0x6a09e667`, etc.).

### Slice 2.5 — Message-schedule expansion

**Goal:** assemble W_0..W_63 using the for-each-subgraph feedback
contract from Slice 2.0c (or hand-rolled per Open #N4 (c)).

**Scope (sketched):**

- W_0..W_15: direct read of the 16 32-bit words of the message block.
- W_16..W_63: each `W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) +
  W_{t-16}` (mod 2^32). σ0/σ1 are different from Σ0/Σ1 (use ROR 7/18/3
  and ROR 17/19/10 respectively). 4 new helpers OR composition (same
  Open #N3 pattern — likely defer to Slice 2.3's pick).
- For-each-subgraph node with feedback/lookback for the 48-iteration
  expansion. OR hand-rolled 48 leaves if Open #N4 (c) was picked.

**Pass/fail gate:** W_0..W_63 byte-equal to FIPS 180-4 §A.1's
intermediate values for `"abc"` (Table A.1).

### Slice 2.6 — Compression function + outer block loop + first end-to-end SHA-256

**Goal:** assemble the full SHA-256 spec. First end-to-end run via
direct `runSpec({portedDispatchEnabled: true})` flag (no spec-level
opt-in plumbing yet — that's Slice 2.7).

**Scope (sketched):**

- Compression function body (64 rounds): T1 = h + Σ1(e) + Ch(e,f,g) +
  K_t + W_t; T2 = Σ0(a) + Maj(a,b,c); h=g, g=f, f=e, e=d+T1, d=c, c=b,
  b=a, a=T1+T2. Wrapped in inner for-each-subgraph (state-thread per
  Slice 2.0a).
- After compression: 8-way add-mod-32 of working variables (a..h) into
  hash state (H_0..H_7).
- Outer for-each-subgraph (item-array per Slice 2.0b) wrapping the
  full per-block compression. Outer state-thread = the running hash
  state H_0..H_7 across blocks.
- Cipher spec authored at `src/ciphers/sha-256.ts` and registered.
- KAT test: `tests/sha-256.test.ts` runs single-block "abc" KAT
  (FIPS 180-4 §A.1, expected
  `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`).

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
