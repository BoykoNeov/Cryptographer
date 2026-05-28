# Universal port-based dataflow — approved plan

> **Status: APPROVED 2026-05-21.** Drafted from a same-day session that
> consulted advisor TWICE (first pass on the proposal, second pass on
> the operationalized plan) and ran four rounds of user design picks.
> Original proposal text preserved below as "Design rationale" for
> historical context.
>
> **DES Phase 6e gate (manual browser smoke):** SATISFIED 2026-05-22 —
> the `docs/plans/des-feistel.md` plan's M1–M7 checklist completed across
> walks #1–#4. DES ships under the legacy contract; this plan unblocked
> and Phase 0 is closed green (see findings doc).
>
> **Predecessor (subsumed):** `~/.claude/plans/silly-brewing-sutton.md` —
> universal cipher-shape plan; registry consolidation falls out for free
> under unified ports.
>
> **Predecessor (interim, will deprecate gradually):**
> `docs/plans/des-feistel.md` — Feistel branching primitive. Finishes
> under legacy contract; under the ported contract DES is just splits +
> XORs + concats, and `FeistelRoundGroup` fades with deprecation.

## Goal

Replace the implicit single-state-thread executor contract with a
universal multi-port dataflow model: every cipher element accepts
0..N labelled `Uint8Array` inputs and produces 0..N labelled outputs.
With explicit mismatch rules, any element can wire to any other — the
editor becomes a true dataflow canvas. The registry shrinks from ~30
cipher-specific step types to ~10 universal primitives parameterized by
JSON. This recovers the README's "cipher = JSON" claim **at a finer
grain** — the cipher's algorithm itself becomes JSON, not just its
structure — and removes the architectural workaround that the Feistel
branching primitive currently is.

## Migration philosophy

**Preserve all shipped work.** Existing 1389+ tests become the oracle
for parity. Existing UI surfaces (linear view, narration, provenance
overlay, mirror registry, graph view, layout sidecar) carry forward
unchanged through the adapter shim. Rebuilds happen alongside legacy
specs and only flip the default once frame-mapped equivalence + KAT
parity is proven. Deprecation of cipher-specific step types happens
only when no shipped spec depends on them.

## Resolved design decisions

| ID | Question | Decision |
|---|---|---|
| Q1 | Port shape labels | **Hybrid (option c)** — ports carry `Uint8Array`; advisory `layout` tag (`raw`, `matrix-cm-4x4`, `be-word`, `le-word`, …) is a hint for editor + inspector but does not gate execution. |
| Q2 | Mismatch policy | **Warn-and-run, deterministic coercion.** Editor flags mismatches with a red glyph + inspector explanation. **Coercion rule:** right-pad with zeros to target length when source is shorter; truncate from the right when source is longer. Coercion appears as a visible trace step (e.g., *"coerced 8 → 16 bytes by right-zero-padding"*), making the breakage visible. |
| Q3 | Feedback loops (CBC IV chain, CTR counter) | **For-each-subgraph**, NOT explicit canvas feedback edges. Cycles stay contained inside the subgraph node; outside the node, canvas remains a DAG. |
| Q3-frame | For-each-subgraph frame emission | **(i) one frame per (body step × iteration)** — preserves today's flat trace, `:b{i}` stepId suffix, `blockIndex` stamp, and all UI surfaces (linear-view scrubber, frame-preservation logic, run-history-diff, mirror buttons). **(iii) hierarchical trace** (tree-shaped, drill-down by iteration) is recognized as a valuable future enhancement, layered on top of unified ports as its own plan — explicitly NOT in this plan to avoid coupling two large architecture changes. |
| Q-A | Primitive granularity | **Medium is canonical**: `byte-substitute`, `permute`, `gf-matrix-multiply`, `xor`, `add-mod`, `rotate`, `split`, `concat`. **Fine-grained primitives ship as a planned exploration construct** so users can experiment with novel ciphers; the AES selector defaults to medium. |
| Q-A-parity | Parity model (legacy ↔ ported equivalence) | **(β) Frame-equivalence at primitive boundaries + `frameMap` for compound decompositions + KAT parity at cipher boundary.** Phase 1 (mechanical adapter): exact frame-count preservation; no map needed. Phase 3+ (rebuilds): compound legacy steps (e.g., `aes.key-expansion@2`, today one frame) decompose into multiple ported frames (rotate → byte-substitute → xor → xor per word); `frameMap` documents and asserts the 1-to-N relationship; FIPS-197 KATs gate cipher-level correctness. **Pedagogical win:** decomposition makes previously hidden sub-steps visible in the scrubber. |
| Q-B | Sub-byte S-boxes (Serpent 4→4, DES 6→4) | **Both** — `byte-substitute` (8→8, applied N times) ships first; `lookup-substitute` (general k→m bits with explicit bit-packing in the trace) ships next. Both coexist indefinitely; differences documented in element help. |
| Q-C | In-element customization | **(a) parameters → (b) compose-and-save → (c) code/pseudocode/formulas**, strictly in order. Foundation designs for (a) and (b) only; do NOT pre-engineer hooks for (c). |
| Mirrors | Cross-mode mirror registry extension | **Stay opt-in** — system *suggests* inverse mirrors when inversion is known (S-box invert, GF-matrix invert, XOR self-inverse, rotate negate); user clicks to apply. No silent auto-sync — protects pedagogy experiments where the user deliberately wires the forward operation to decrypt. |
| Narration | Cipher-specific pedagogy preservation under rebuild | **(a) `narrationOverride: StepDocumentation` field on spec nodes**, folded into Phase 1's contract design. Falls back to step-type registry documentation when absent. Shipped AES spec carries cipher-specific overrides per leaf (e.g., `byte-substitute` → `{ name: 'SubBytes', summary: 'FIPS-197 §5.1.1...', references: [...] }`); experimental palette-dropped primitives get generic registry narration. Cipher pedagogy becomes JSON-native — forking AES to make a variant lets the author edit narration too. |
| Feistel | Disposition of `FeistelRoundGroup` / `BranchTrack` / `CombineKind` | **No retrofit, gradual fade.** DES ships under legacy. Adapter wraps legacy types. Rebuild expresses DES via universal primitives. Types removed only when no shipped spec depends on them. |
| Q-edges | Where do edges live in the spec? | **(c) Sink-only** — each node declares its own `inputs: { portName: { node, port } }`. Outputs are emergent via inverse query. Eliminates the dual-write corruption risk of storing edges on both endpoints; matches the typed-in-editor UX ("at this consumer, change which source it reads from"); no separate edges array to keep in sync with the node list. Decided 2026-05-23. |
| Q-gate-9 | Phase 0 load-bearing assertion | **`deepEqual(reconstruct(project(legacyFrame), layoutTags), legacyFrame)` byte-by-byte for all three lifted steps.** The 8 other gate items pass trivially when the adapter copies legacy frames — only this round-trip tests the migration's premise ("legacy state/aux split is one projection of unified ports"). Hidden engineering inside: design `layoutTags` rich enough that all 4 State variants (bytes / matrix4x4 / bitvec / bigint) AND aux-key names round-trip losslessly. A lossy round-trip is a Phase 0 finding, not a Phase 1 problem. Decided 2026-05-23. |
| Q-ports-add | Adding new ports to a node | **Pattern A (parameterized primitives) + Pattern B (tap/identity insertion), defer Pattern C (spec-local port extension).** A: e.g., `xor` with `params.inputCount: N` parameterizes its input port list — change params, contract refreshes. B: want a new debug-output on the post-MixColumns state? Insert an `identity`/`tap` primitive between source and consumer; tap has two outputs (`pass`, `tap`). C (each node declares extra ports beyond what its type contract says) breaks the "spec fully described by node-type contracts" invariant and is deferred indefinitely; no shipped use case demands it. Decided 2026-05-23. |

## Contract sketch

```ts
type PortShape = {
  readonly byteLength: number;
  // Advisory only; runtime always passes raw Uint8Array.
  readonly layout?: "raw" | "matrix-cm-4x4" | "be-word" | "le-word" | string;
};

type StepInputs = ReadonlyMap<string, Uint8Array>;
type StepOutputs = ReadonlyMap<string, Uint8Array>;

type PortedExecutor = (
  inputs: StepInputs,
  params: Json,
  ctx: StepContext,
) => StepOutputs;

// Renamed from StepShapeContract in Phase 0 to avoid collision with the
// existing single-thread shape contract at src/core/types.ts (palette chip +
// drop-anchor greying + validateShapes).
// **Slice 1.4 (2026-05-23) widened both sides to `PortShapeMap` —
// `ReadonlyMap | ((params) => ReadonlyMap)` — so dynamic-N steps
// (AES / Speck / Serpent / DES key-schedules with `params.rounds + 1`
// round-key output ports) can declare their per-leaf port surface in
// function form. See `docs/plans/universal-port-phase-1-slices.md` §1.4
// for the user pick rationale (chosen over a templated-name "keyN" lie
// and a `dynamicOutputs?` sibling field). Static contracts pass
// unchanged through the union — no source edits required.**
type PortContract = {
  readonly inputs: PortShapeMap;
  readonly outputs: PortShapeMap;
};

type StepRegistration =
  | { kind: "ported"; executor: PortedExecutor; shape: PortContract; doc: StepDocumentation }
  | { kind: "legacy"; executor: StepExecutor; doc: StepDocumentation };

// Spec node gains optional per-leaf narration override (Phase 1).
// Renderer falls back to registry documentation when absent.
type StepNode = {
  readonly kind: "step";
  readonly id: string;
  readonly type: string;
  readonly params: Json;
  readonly narrationOverride?: StepDocumentation;
};

declare function liftLegacyExecutor(reg: LegacyRegistration): PortedExecutor;
```

Edges are stored **sink-only on each node** (Q-edges, decided 2026-05-23): every node carries `inputs: ReadonlyMap<string, { node: string; port: string }>`; the consumer side declares where its inputs come from. Fan-out is computed by inverse query (`O(N)` walk over all nodes' inputs maps; cached in graph derivation). No aux/state distinction at the data-model layer.

```ts
type EdgeEndpoint = { readonly node: string; readonly port: string };

type StepNode = {
  readonly kind: "step";
  readonly id: string;
  readonly type: string;
  readonly params: Json;
  readonly inputs: ReadonlyMap<string, EdgeEndpoint>;  // sink-only edges
  readonly narrationOverride?: StepDocumentation;
};
```

The `State` union (`BytesState`, `MatrixState`, `BitVecState`, `BigIntState`) collapses to `Uint8Array` at the runtime layer; `MatrixState`'s column-major convention becomes a port `layout` tag. Trace frames record per-port byte arrays in/out of each step; the legacy state/aux split becomes one projection of that — **this is the load-bearing claim Phase 0 validates via the project→reconstruct→deepEqual round-trip (Q-gate-9).**

## Phased plan

Each phase has an explicit pass/fail gate. **If a gate fails, planning re-opens before subsequent phases proceed.** Phase 0's result in particular can force rewriting Phases 1–4.

### Phase 0 — Trace-shape unification spike (~3 days)

> **Status 2026-05-23: PHASE 0 GREEN — Phase 1 unblocked.** All 7 tasks complete. All 9 gate items walked (caveat on `outBlocksAux` documented). Findings doc at [`universal-port-phase-0-findings.md`](./universal-port-phase-0-findings.md). Plan unchanged — Phase 1 (adapter for every step + runtime dual-dispatch widened + `narrationOverride` field) starts on user demand; the DES Phase 6e gate completed 2026-05-22.
>
> Implementation log (closed):
> - Tasks 1–3 (types + `project`/`reconstruct` + Q-gate-9 test) shipped earlier 2026-05-23. **Naming refinement:** plan's `StepShapeContract` renamed to **`PortContract`** (collision with the existing identifier at `types.ts:319` — single-thread shape contract used by the palette chip + drop-anchor greying + `validateShapes`).
> - **Task 4 (`liftLegacyExecutor` adapter)** shipped. Side-map projection registry (`PROJECTION_METADATA` in `core/port-projection.ts`) was chosen over a `StepDefinition` field per the 2026-05-23 advisor consult: projection metadata is the lift's INPUT, not a permanent registration field; Phase 1's `StepRegistration` discriminated union supersedes the side-map entirely. Phase-0 strictness: lift throws if the legacy executor's `result.auxWrites` is non-empty (neither target writes aux).
> - **Task 5 (runtime dual-dispatch)** shipped. `RuntimeInput.portedDispatchEnabled?: boolean` per-call flag (not a module global) so legacy + ported runs stand side-by-side in tests. Side-map presence + flag gates the ported branch; legacy callers default to false and are byte-equivalent to pre-Phase-0. Frame's `auxRead` is built from metadata bindings on the port projection — NOT from the legacy executor's `result.auxReads` — which is the load-bearing claim.
> - **Task 6 (end-to-end KATs)** shipped. `tests/runtime-ported-dispatch.test.ts` — 6 assertions: side-map sanity + FIPS-197 Appendix C.1 (single-block AES-128) + NIST SP 800-38A §F.1.1 (4-block ECB) + frame-by-frame byte equality vs legacy × both cipher specs + `:b{i}` suffix preservation on ported iterate-body frames. Iterate-runtime `aux[outBlocksAux]` population verified at integration boundary (ECB ciphertext bytes match) — NOT at frame level (subsection in findings doc).
> - **Task 7 (findings doc + 9 gates walked)** shipped. All 9 items GREEN (8 by frame-by-frame parity propagation through every TraceFrame consumer; item 9 with the structuredClone barrier hardening).
> - **Bundled into close (advisor item 2):** Q-gate-9 hardened with `structuredClone(tags)` wrapper around `reconstruct` in all 4 assertions. Node ≥17's structuredClone handles ReadonlyMap natively. Anti-trivial discipline now enforced at runtime + type level.
> - **Pre-flight grep confirmed (advisor item 3):** only `src/ciphers/default-registry.ts:12,16` imports `byteSubstitution` / `addRoundKey` directly; spec-string references elsewhere are unaffected by the side-map approach.
> - **Final gate:** `npm run check` GREEN — biome + tsc + **1618/1618** vitest tests (+6 new) + vite build.

**Goal:** validate the load-bearing claim that today's UI layers consume a trace shape compatible with universal ports. **Scope widened** (per second-pass advisor review): a pure step alone (`aes.sub-bytes`) doesn't exercise the harder cases where state and aux co-flow or where iterate boundaries are involved — those are exactly the cases that would force the UI to fork.

**Scope:**
- Minimal `PortShape` / `PortedExecutor` / `PortContract` types in `src/core/types.ts`.
- `liftLegacyExecutor(legacy)` exercising three legacy contract shapes:
  - **Pure state-only:** `aes.sub-bytes` (state in → state out, no aux)
  - **Aux read:** `aes.add-round-key` (state + aux read of round key → state)
  - **Iterate body:** one ECB iteration (single block; validates `:b0` suffix, `blockIndex` stamping, `aux[outBlocksAux]` population)
- Dual-dispatch in `src/core/runtime.ts` (legacy vs ported registrations).
- Run AES-128 ECB encryption end-to-end with these three steps under the new contract.

**Pass/fail gate:**
- Linear view shows byte-identical frames for all three step types
- MatrixView highlights (diff-vs-prev, source/destination overlay) still work
- Provenance overlay still lights up source cells on hover
- Step narration still fires correctly (including round-key narration for `add-round-key`)
- Graph derivation produces byte-identical edges before/after
- `:b0` stepId suffix and `blockIndex` stamp preserved on iterate body frame
- Mirror registry buttons still render for ported steps (e.g., SubBytes inverse-mirror)
- Full 1389-test suite still passes
- **(load-bearing, Q-gate-9):** for all three lifted frames, `deepEqual(reconstruct(project(legacyFrame), layoutTags), legacyFrame)` holds byte-by-byte. The projection is the per-port `inputs`/`outputs` Maps; the `layoutTags` sidecar carries State-variant metadata (matrix column-major flag, bitvec `bitLength`, bigint endianness + length, original aux-key names) sufficient to reconstruct the legacy frame losslessly. **If the round-trip can't be made lossless without `layoutTags` growing absurdly large, the projection's design itself is wrong — surface to user and re-open planning before Phase 1.**

**If gate fails:** identify which UI layer forked OR what the projection lost, surface to user, revise plan before Phase 1.

### Phase 1 — Port contract + adapter for every existing step (1–2 weeks)

**Goal:** every shipped step type runs under the ported contract via `liftLegacyExecutor`. New ciphers can be written port-native without affecting legacy.

**Scope:**
- `liftLegacyExecutor` extended to handle all legacy executor shapes (aux reads/writes, iterate, FeistelRoundGroup tracks).
- Registry entries gain `kind` discriminator.
- Runtime dispatches by `kind`.
- Edge model in `core/graph.ts` simplified to port-to-port flows; `inferStateEdges` / `dropAuxOnlyStateEdges` / iterate-boundary suppression become legacy-only fallbacks.
- Trace frame shape gains explicit `inputs: ReadonlyMap<string, Uint8Array>` / `outputs: ReadonlyMap<string, Uint8Array>` projections.
- **`narrationOverride: StepDocumentation` optional field added to spec node types** in `core/types.ts`; `<StepNarration />` falls back to registry documentation when absent. Schema migration handles documents without the field. (No shipped spec uses overrides yet at this phase; the field is the contract that Phase 3+ rebuilds consume.)
- **For-each-subgraph node** added as a new spec node kind to express iterate under port semantics; emits one frame per (body step × iteration) per Q3-frame. Legacy `iterate` continues to work via adapter.

**Pass/fail gate (per (β) parity model, adapter sub-case):**
- Full 1389-test suite passes unchanged
- All five shipped ciphers (AES-128/192/256, Speck32/64, Serpent-128/192/256, DES) produce **exact frame-by-frame byte equivalence** — no decomposition yet, adapter preserves frame count exactly, so no `frameMap` is needed at this phase
- Graph view renders identically for all shipped ciphers (visual smoke per cipher)
- Inspector / narration / provenance / mirror buttons unaffected
- Coercion mechanism (Q2) round-tripped: deliberately wire mismatched ports in a test fixture and assert the right-pad / truncate-from-right behavior is observed and surfaced in the trace

### Phase 2 — SHA-2 native (first port-native cipher)

> **Status 2026-05-24: SUB-SLICE PLAN DRAFTED, awaiting Slice 2.0a sign-off.** Detailed at [`universal-port-phase-2-slices.md`](./universal-port-phase-2-slices.md). 15 sub-slices; user picks locked in (Q1 full scope + Q2 for-each-subgraph contract first + Q3 spec-level opt-in + Q4 outer-loop superset); 8 open spec decisions enumerated for slice-start picks.

**Goal:** ship a primitive that legitimately cannot fit single-state-thread, proving the port contract has earned its existence.

**Scope:**
- SHA-256 implemented entirely under the ported contract.
- New universal primitives: `add-mod-32`, `rotate-bits-right`, `xor` extended to N-way, `expand-message-schedule` (subgraph node).
- For-each-subgraph node for the compression-function 64-round iteration — validates Q3 + Q3-frame (flat per-iteration body frames).
- KAT against FIPS 180-4 published vectors.
- Linear view, narration (via `narrationOverride` per leaf), provenance overlay, graph view all work for SHA-256.

**Pass/fail gate:**
- SHA-256 KATs pass against FIPS 180-4
- The for-each-subgraph node renders cleanly with feedback contained inside; per-iteration frames scrubbable
- Pedagogical surfaces (linear view, narration, inspector) describe SHA-256 as well as they describe AES

### Phase 3 — AES rebuild from medium primitives

> **Inherits the container port contract from
> `docs/plans/scaffolding-suppression.md` (Phase A, Slice A2 — SHIPPED
> 2026-05-28).** Do NOT re-derive container seeding ad-hoc: the looping
> containers now carry optional `seedInput` / `bodyOutput` `PortBinding`
> fields (`core/types.ts`). AES's `iterate` (ECB/CBC) adopts `seedInput`
> (replacing `generic.split-blocks@1`/`blocksFromAux`) and `outputPorts`
> (replacing `generic.concat-blocks@1`) when rebuilt here — that's the
> "Phase B1" runtime resolution the A2 slice deferred for iterate/FES (A2
> currently THROWS if those fields are set on `iterate`/`for-each-subgraph`,
> so wiring them is part of this rebuild). Constants (S-box/Rcon) move to
> `cipherConstants` (A1). See the scaffolding-suppression plan's Phase B1.

**Goal:** prove the universal-primitive vocabulary expresses AES; achieve KAT parity at the cipher boundary with explicit `frameMap` documenting legacy-compound → ported-decomposed relationships per (β).

**Scope:**
- New primitives: `gf-matrix-multiply` (param: matrix + field), `permute` (param: index mapping), `xor`, `byte-substitute`.
- AES-128 spec authored as a JSON tree composed of medium primitives. Key-expansion is initially lifted under adapter; the compound becomes a candidate for decomposition exposure (turning today's hidden RotWord→SubWord→Rcon→XOR pipeline into scrubbable frames) if scope allows in this phase, or moved to Phase 4a.
- Each AES leaf carries a `narrationOverride` (e.g., `byte-substitute` → "SubBytes (FIPS-197 §5.1.1)", `gf-matrix-multiply` → "MixColumns (FIPS-197 §5.1.3)"). The shipped AES spec is its own self-documenting JSON.
- Mirror registry extended to recognize universal primitives — e.g., `byte-substitute` with an invertible table offers "Sync inverse to decrypt."
- Cipher selector gains an internal flag to swap legacy-AES ↔ ported-AES for parity testing; not user-visible until ported is canonical.
- **`frameMap` test infrastructure** — declarative mapping per legacy step: pure 1-to-1 steps (SubBytes, ShiftRows, MixColumns, AddRoundKey) map to one ported frame each; any compound step that gets decomposed carries a 1-to-N map documenting the ported-frame sub-sequence. Test asserts the legacy trace and the ported trace agree under the map; ciphertext at the cipher boundary matches exactly.

**Pass/fail gate (per (β) parity model):**
- FIPS-197 Appendix C KATs pass for ported AES at the cipher boundary (ciphertext bytes match)
- For every legacy-AES step, the corresponding ported-AES frame(s) agree byte-by-byte per the declared `frameMap`
- Linear view, narration (using `narrationOverride`), provenance, graph view, mirror buttons all work on ported AES
- Cipher selector swaps legacy-AES ↔ ported-AES without breakage
- Once green: ported AES becomes the shipped default; legacy AES stays in registry as adapter-wrapped reference for one additional release before deprecation

### Phase 4+ — Rebuilds, fine primitives, compose-and-save

**Goal:** complete the migration of all shipped ciphers; ship the fine-grained primitive vocabulary; ship compose-and-save (b).

**Scope (sub-phases, not pre-planned in detail):**
- **4a:** AES-192/256, AES-CBC, AES-CTR under ported contract (with `frameMap` for any compound decomposition that didn't land in Phase 3)
- **4b:** Speck32/64 rebuild — introduces `add-mod-16`, validates ARX vocabulary
- **4c:** Serpent rebuild — introduces `lookup-substitute` for 4→4 S-boxes; IP/FP as `permute`
- **4d:** DES rebuild — introduces native `split`/`concat`; validates that Feistel needs no special primitive
- **4d-bis (port-wiring editor):** **Plan AND ship the port-wiring editor UI** — the in-canvas affordance for the user to select a node and change which upstream output port each of its input ports reads from (and, symmetrically, which downstream `portInputs` reference its outputs). Until this slice lands, port wiring is **source-file-only**: every shipped cipher spec declares `portInputs` in TypeScript and the user has no in-app way to rewire. This sub-phase delivers:
  - a `setPortBinding(spec, stepId, portName, { node, port })` mutation helper in `spec-mutations.ts`, with reference-equality preservation matching `updateStepParams`
  - a graph-canvas gesture (drag from output port → input port, or click-to-arm) with port-contract compatibility checks (byteLength match, layout compatibility) at edit time — Q2 editor half lands here (red glyph on mismatched wirings + inspector explanation), closing the Phase 1 deferral at `docs/plans/universal-port-phase-1-slices.md:993-1003`
  - per-input dropdown fallback for keyboard / accessibility paths
  - integration with the existing `applyDocument` save/load round-trip (no schema bump — `portInputs` is already part of `StepLeaf`)
  - **firm position: after 4a–4d, before 4e–4f.** The cipher rebuilds (4a–4d) execute UNDER the source-file-only wiring regime; compose-and-save (4f) cannot ship without it, so it must land in between. The sub-phase gets its own plan file (`docs/plans/port-wiring-editor.md`) drafted at the start of 4d-bis with its own advisor consult — the design space (gesture, compatibility surface, layout-sidecar interaction) is open and warrants explicit slicing.
- **4e:** Fine-grained primitive vocabulary shipped + AES-fine exploration spec authored (parallel to AES-medium canonical) — Q-A's "fine primitives as exploration construct" commitment delivered here
- **4f:** Compose-and-save (b) — user wires N primitives, names them, saves as a new named element appearing in the palette. **Depends on 4d-bis** (user cannot compose without a wiring affordance).

**Constraint on 4a–4d (cipher rebuilds): keep the port-wiring editor in mind.** The rebuilds happen *before* 4d-bis, but they are the corpus the editor will rewire at runtime. Two specific authoring disciplines apply to every rebuilt spec:

- **`portInputs` shapes must round-trip cleanly through edit mutations.** Prefer flat, named-string bindings (`{ node: "id", port: "outputN" }`) over computed/dynamic constructions that read awkwardly after an edit replaces one entry. Today's specs already meet this — call out any rebuild that's tempted to deviate.
- **Port names should be stable and learner-readable.** Avoid generated port names that look fine at authoring time but become opaque in a "rewire from..." dropdown listing every output port in the canvas. `output0..output{N-1}` (the split-bytes/concat convention) is fine; ad-hoc names like `_t7` are not.

If a rebuild discovers a port-shape or naming constraint that would make the editor's compatibility check awkward, raise it as a 4d-bis blocker and adjust the spec — don't paper over it.

**Gate for each sub-phase:**
- KAT parity with legacy spec at cipher boundary
- `frameMap` declared and tested for any compound decomposition
- All UI surfaces work
- Mirror buttons surface for known-invertible primitives

### Phase 5 — Deprecate legacy step types

**Goal:** remove the legacy executor contract from the codebase when nothing depends on it.

**Scope:**
- Audit shipped specs for legacy step type usage; migrate or accept as deprecated.
- Remove `FeistelRoundGroup`, `BranchTrack`, `CombineKind` from `core/types.ts` once no shipped spec uses them.
- Remove `liftLegacyExecutor` once no legacy registrations remain.
- Schema migration handles older saved documents (`CipherDocument.schemaVersion` bump).

**Pass/fail gate:**
- No legacy registrations in `core/registry.ts`
- Schema migration handles all older saved-document versions
- Full test suite passes with the contract surface reduced

## What gets preserved vs. fades

| Preserved | Fades |
|---|---|
| All 1389+ existing tests (oracle for parity) | Cipher-specific step types (`aes.sub-bytes`, `serpent.sub-bytes`, `des.s-box-substitution-stage`) once rebuilds ship |
| Linear view, narration (via `narrationOverride` per leaf), provenance overlay, mirror registry, graph view | The aux/state distinction at the data-model layer |
| Branched-layout positioning logic (per-track gutters) — transfers to SHA-2, AEAD, any multi-port shape | `FeistelRoundGroup`, `BranchTrack`, `CombineKind` types |
| DES KAT vectors, FIPS-197 vectors, Serpent test vectors | `inferStateEdges`, `dropAuxOnlyStateEdges`, iterate-boundary suppression in graph derivation |
| Layout sidecar (per-spec.id, localStorage) | Implicit single-state-thread executor contract |
| `cross-mode-mirror-registry.ts` pattern (extended to universal primitives) | |
| Flat trace + `:b{i}` stepId suffix + `blockIndex` stamp (Q3-frame option (i)) | |

## Deferred for future planning

- **(c) In-element code customization** — form TBD (sandboxed TS snippet, pseudocode interpreter, mathematical formula DSL). Don't engineer hooks now. Plan when (a) and (b) are stable.
- **(iii) Hierarchical trace** — tree-shaped trace with drill-down by iteration / subgraph. Lets users scrub at block granularity for multi-block modes (CBC with 100 blocks → 100 collapsible iteration summaries, drill into one when curious). Decoupled from this plan because shipping it inside Phase 1 would couple two large architecture changes simultaneously (port contract + trace tree); each is large independently, together is much riskier. Recognized as valuable; future arc with its own gates. Today's flat trace per (i) is the Phase 0+ semantics.
- **Auto-mirror policies for compose-and-save (b) elements** — system can offer inverses for known-invertible primitive compositions; needs design once (b) ships.
- **Streaming / large-input handling** — today's runtime works on full byte arrays. Streaming hash, file encryption, large-input modes may require chunked port semantics; not in scope here.
- **Codegen target** — JSON spec → binary export was the original motivating use case (`CLAUDE.md`). The unified port contract is a strict improvement for codegen (no closure capture), but the concrete codegen plan is separate work.
- **Cross-iteration data-dependency visibility for `for-each-subgraph-with-history` bodies.** The runtime's `aux["prior-N"]` auto-publish (`runtime.ts:1170`) is silent — no `TraceFrame` records the cross-iteration handoff. Slice S2(l) of the SHA-256 density polish plan added `inferHistorySeedEdges` to synthesize edges from the spine predecessor to the seed-window fetches (iterations 0..seedCount−1), but the W_t → W_{t+k} cross-iteration handoffs (for SHA-256: 64 iterations × 4 dependencies = ~128 edges in the expanded msg-schedule) are NOT in the graph. **Future slice in this plan family:** extend `inferHistorySeedEdges` to also synthesize cross-iteration edges from each iteration's W_t output to subsequent iterations' W_{t+2/7/15/16} fetches. (The gradual obstacle-aware routing plan that would have bundled this dense recurrence web was abandoned 2026-05-28; with these edges added they render via the standard edge renderer under the orientation-driven offsets layout.)

## Pointers

- Original proposal: drafted 2026-05-21 (full text preserved below).
- Advisor consults: 2026-05-21 same session — first pass (seven points on the proposal) and second pass (five operational concerns on the operationalized plan) both incorporated as decisions or deferred items above.
- Predecessor (subsumed): `~/.claude/plans/silly-brewing-sutton.md`.
- Predecessor (interim, deprecate gradually): `docs/plans/des-feistel.md`.
- Contract surface to touch: `src/core/types.ts` (State union, StepExecutor, IterateGroup, FeistelRoundGroup), `src/core/runtime.ts` (walker), `src/core/graph.ts` (derivation), `src/core/edge-value-lookup.ts` (inspector).
- Memory entry: `project_universal_port_dataflow_proposal.md` — kept in sync with this doc's decisions.

---

## Design rationale (original proposal text, preserved)

### The proposal (user's words, paraphrased)

Every element in every cipher should accept **0..N byte-array inputs** and
produce **0..N byte-array outputs**. 0 is an edge case with little practical
implication. Inputs and outputs are arrays of bytes; the element does
mathematical operations on them and emits more byte arrays. With explicit
rules for mismatches between an element's declared port shapes and the actual
data flowing into them, **every element could be connected to every other in
theory** — the editor becomes a true dataflow canvas.

That's the architectural target.

### Why it's compelling

The current "one implicit state thread + named aux side channel" model is a
**rendering convention** that matches textbook diagrams, not a data-model
truth. The underlying mathematics has always been "named byte arrays flowing
along labeled edges." Multiple recent design pressures are already pushing
toward the unified shape:

- **Feistel exists *because* the single-state model can't express L/R splits.**
  `FeistelRoundGroup`, `BranchTrack`, and `CombineKind` (`src/core/types.ts:176`,
  `types.ts:125`, `types.ts:170`) are a special primitive bolted on to dodge a
  limitation that disappears under unified ports. Under multi-output nodes,
  Feistel is just: split node (1 in, 2 out) → F on R → XOR with L (2 in, 1 out)
  → swap. No primitive needed.
- **AEAD's "ciphertext + tag" doesn't fit "1 state in, 1 state out" cleanly.**
  Same for hash/MAC/KDF output multiplicity.
- **The graph view already spends substantial derivation machinery** —
  replicas (`replicateHighFanoutSources` in `core/graph.ts`), spine inference
  (`inferStateEdges`), aux/state distinction, iterate-boundary suppression,
  port-spreading, edge bundling — **to derive a multi-port-ish picture FROM
  the single-state-thread model.** Under unified ports much of this evaporates
  because the data model would literally match what you see on the canvas.
- **The pedagogical payoff is direct.** Drag SubBytes onto a Speck pipeline →
  port shapes don't match → red glyph that's *itself* a lesson ("this expects
  16 bytes, you fed it 8"). That's exactly the pedagogy this project exists
  for.
- **Codegen target stays JSON.** No regression on the "spec is data, not code"
  invariant — improved by the contract (no closure capture).

### The universal-S-box example (2026-05-21 session)

A concrete instance of the unification's power: today `aes.sub-bytes`
hardcodes "for each of 16 bytes in a column-major matrix, look up in the
S-box." Under universal ports it becomes a `byte-substitute` primitive
parameterized by `{ table: Uint8Array[256] }`, accepting N bytes in →
N bytes out. AES uses N=16. A hypothetical 8×8 AES variant uses N=64. A
Speck-sized experiment uses N=4. **The element is the same; only its
parameters and input length differ.** Same logic applies to MixColumns
(a `gf-matrix-multiply` parameterized by matrix size + field), ShiftRows
(a `permute` parameterized by an index map), and AddRoundKey (an `xor`).

### Migration strategy (incremental dual-contract)

A wholesale rebuild is too expensive: ~30 registered step types, ~1389 tests,
runtime, trace shape, the entire inspector/narration/provenance layer all sit
on top of the current contract. The proposed migration:

1. Define the port contract alongside today's contract.
2. Adapter shim `liftLegacyExecutor(legacy)` maps today's contract to ported.
3. Runtime supports both; registry entries declare which contract they speak.
4. Graph derivation simplifies — every edge IS a port-to-port flow, declared
   by the spec, not inferred from frames.
5. New ciphers (first candidate: SHA-2) lead with the unified shape.
6. Deprecate legacy when nothing depends on it.

This preserves shipped work, doesn't freeze the project for months, and gets
to the unified destination with new ciphers leading the way.

## Architectural decisions — 2026-05-26 user-set rules

> **Status: USER DECISIONS, 2026-05-26.** Crystallized during the
> SHA-256 density polish S2 session when the manual smoke surfaced a
> graph-derivation gap (port-flow edges missing from
> `deriveAuxGraph`). Picking between "per-edge" vs "whole-spec"
> suppression of legacy state-spine inference forced the user to
> state their long-term position on hybrid specs. The position
> below extends — does not contradict — the plan's existing
> migration-philosophy paragraph; it tightens the destination state.

### Rule 1 — All shipped ciphers and hashes are port-native byte-flat

**Long-term state:** every shipped cipher / hash in this project is
authored as a pure port-native spec. No hybrid specs — meaning no
spec that mixes `kind: "legacy"` leaves with `kind: "ported"`
leaves — ever ship to `main`. Phase 5's "deprecate legacy when
nothing depends on it" is the final state; this rule commits to
that destination ahead of time and locks future authoring to it.

**Permissive byte-flat dataflow.** The contract between nodes is
*always bytes*. Quoting the user directly so the framing is
preserved:

> A output byte array, B reads byte array. A may provide additional
> information to B, but since we can connect in theory everything
> there, B may not care about the additional info, and that's okay,
> this shouldn't break the program, padding and truncating should
> happen. (it may break the cipher or hash, that's okay).

Two corollaries baked into the framing:

1. **Any node can wire to any other node.** The editor is a true
   dataflow canvas — wiring `xor@1.output` into `aes.sub-bytes@1`
   input is geometrically allowed even if the consumer's expected
   byteLength differs. The runtime's coercion-warning-and-run path
   (Slice 1.12) handles the mismatch by padding or truncating;
   the cipher's resulting output may be wrong, but the program
   doesn't throw. That's pedagogically the point — the user sees
   the wrong digest and learns *why* it was wrong.
2. **Metadata is optional, ignorable, never load-bearing.** The
   `layout` tag on a port (`raw`, `matrix-cm-4x4`, `be-word`, …) is
   advisory only. A consumer is free to ignore the producer's tag,
   reinterpret the bytes, and produce a wrong (but defined) result.
   This was already Q1's resolution at the plan's design-decisions
   table — restated here in user-vision framing.

**Why this rule:** the "tinker with the cipher and watch the trace
diverge" pedagogy depends on the user being able to wire anything
to anything. Hybrid specs would force the spec author to think in
two contracts simultaneously and limit which connections are
visually meaningful. Pure port-native means one mental model.

**How to apply:**
- New cipher authoring: must be 100% port-native from day one. No
  exceptions for "this operation doesn't fit the vocabulary" — see
  Rule 2 for how specialized math is handled.
- Phase 3 / Phase 4d rebuilds (AES, DES, etc.): each rebuild
  delivers a fully port-native spec. User-accepted incremental
  development is fine — intermediate commits during a rebuild may
  produce hybrid-shape WIP specs; the dev's graph view will look
  broken during those windows and the user does not care. Once
  shipped, the spec must be 100% port-native.
- Graph derivation, validation, mirror registry, narration: all
  may assume "either fully legacy OR fully port-native" at the
  spec level (no per-node mixing in shipped specs).

### Rule 2 — Specialized math is internal to a node; ports stay byte-flat

**RSA shape, by user pick (Q3 of 2026-05-26 follow-up questions):**
modular exponentiation does NOT cross a port boundary as a BigInt.
Instead, the RSA spec wires byte-flat primitives at the boundary —
e.g., `bytes-to-bigint-BE@1` (or similar) consumes byte-flat
plaintext, internally constructs a BigInt, and emits a single
byte-flat representation. The `rsa.modular-exponentiation@1` node
consumes those bytes, parses internally into a BigInt, exponentiates,
serializes back to bytes, emits. A symmetric `bigint-to-bytes-BE@1`
(or whatever the canonical RSA byte format is) sits on the output
side.

**Generalization:** any future cipher whose internal math needs a
specialized state shape (BigInt for RSA, GF(2^k) elements for ECC,
polynomial coefficient vectors for lattice-based KEMs) handles that
shape *inside* the node executor. The node's port surface is always
`Uint8Array`. Serialization choices (big-endian vs little-endian,
fixed-length vs variable-length, padding rules) become explicit
spec-level primitives — visible chips in the graph, editable,
pedagogically named.

**Why this rule:** keeps the port contract simple (always bytes)
and pushes serialization decisions into the spec author's
explicit choice. The author can't accidentally use a node that
"only works with BigInt input" — there's no such thing. Every
node consumes bytes; what it does with them internally is a
matter of the executor's logic.

**Consequence:** the publicly-declared `BigIntState` and
`BitVecState` types in `core/types.ts` are dead — they describe a
state shape that crosses port boundaries, but under Rule 2 no
state shape does. Per user decision Q1 of 2026-05-26, both are
scheduled for **deprecation in Phase 5 cleanup**. The
"polymorphic state shape" branches in `deriveAuxGraph` and
adjacent code that exist to handle these shapes become dead code
at the same time — to be audited and removed as part of the S2
follow-up work in `docs/plans/sha-256-density-polish.md`.

### Rule 3 — Whole-spec suppression of legacy state-spine inference is safe

**Direct consequence of Rules 1+2.** Under "no hybrids ever," the
two-state-of-the-world picture for graph derivation is binary:

| Spec kind | Predicate (e.g. `requiresPortedDispatch`) | Legacy state-spine inference |
|---|---|---|
| Pure legacy (today's AES / Speck / Serpent / DES) | false | fires — arrows visible ✓ |
| Pure port-native (today's SHA-256, future everything) | true | skipped — port-flow arrows are the truth ✓ |

There is no third row. Hybrid is not a shipped state. The
"whole-spec suppression" implementation strategy — `if
requiresPortedDispatch(spec) then skip legacy state-spine
inference` — is permanently safe under this rule set.

**Incremental rebuilds in development:** Phase 3 AES (and similar)
may produce hybrid intermediate states during a rebuild. The dev
running those experiments will see broken graphs for the legacy
portion in their feature branch. The user has explicitly accepted
this (Q2 pick of 2026-05-26) — broken dev windows are fine; main
never holds a hybrid.

### Follow-up questions logged (not blocking)

- **Q3 deferred-to-author-time (RSA serialization specifics):** the
  exact set of byte-flat RSA serialization primitives (BE/LE,
  PKCS#1 v1.5 padding, OAEP padding, key-length padding) is
  designed when RSA is actually authored. Rule 2 fixes the
  *shape* (serialization is spec-level primitives, not internal
  to modexp) but leaves the *vocabulary* to author-time.
- **Q4 polymorphic-state cleanup:** the audit of `deriveAuxGraph`
  for dead `BigIntState` / `BitVecState` branches is folded into
  the S2 follow-up plan (`docs/plans/sha-256-density-polish.md`,
  Slice S2(g)). May overlap with S2(f) suppression work; reassess
  scope when that lands.

### Cross-references

- `docs/plans/sha-256-density-polish.md` — S2 follow-up tracking
  the port-flow edge derivation work (S2(e), S2(f), S2(g)) these
  rules unblock.
- `feedback_all_specs_port_native.md` (memory) — user-vision
  directional preference, sibling to this addendum.
