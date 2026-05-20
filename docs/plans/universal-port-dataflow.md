# Universal port-based dataflow — architectural proposal

> **Status: PROPOSAL, not approved. Drafted 2026-05-21 from a session
> conversation. Next-session hand-off: call `advisor()` FIRST THING with
> this doc + the conversation context, then user decides direction.**
>
> Position in time: drafted AFTER the DES+Feistel plan (Phases 1–5 + 6a/b/c/d
> shipped, 6e remaining) and the universal cipher-shape plan
> (`~/.claude/plans/silly-brewing-sutton.md`, not yet started). This proposal
> is **broader** than the cipher-shape plan — that one consolidates registries
> while preserving today's executor contract; this one rewrites the executor
> contract itself.
>
> If approved, this proposal **subsumes** the universal cipher-shape plan
> (the cipher-shape work falls out for free under unified ports). It also
> means recent design work on the Feistel branching primitive
> (`FeistelRoundGroup`, `BranchTrack`, `CombineKind`) was an interim — the
> branching shape is native under unified ports, no special primitive needed.

## The proposal (user's words, paraphrased)

Every element in every cipher should accept **0..N byte-array inputs** and
produce **0..N byte-array outputs**. 0 is an edge case with little practical
implication. Inputs and outputs are arrays of bytes; the element does
mathematical operations on them and emits more byte arrays. With explicit
rules for mismatches between an element's declared port shapes and the actual
data flowing into them, **every element could be connected to every other in
theory** — the editor becomes a true dataflow canvas.

That's the architectural target.

## Why it's compelling

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
  invariant.

## Open design questions (must be answered before this is a plan)

### Q1: Shape labels on ports — "array of bytes" isn't quite enough

AES's `MatrixState` is 16 bytes **with a column-major convention**
(`types.ts:19`). Speck32/64 is 4 bytes **with two-word ARX interpretation**
(`types.ts:14` + byte↔word codec in the executor). Serpent is 16 bytes
**with optional bitslice interpretation**. Layout matters; "array of bytes" by
itself loses it.

Three positions to choose from:

- **(a) Per-port shape tag** — ports declare both byte length AND interpretation:
  `{ kind: "bytes-cm4x4", length: 16 }`, `{ kind: "bytes-be", length: 4 }`.
  Type-checking happens at edge boundaries. Most rigorous, most boilerplate.
- **(b) Bytes are just bytes; layout is consumer responsibility** —
  ports carry only `Uint8Array`. The consumer interprets. Maximum
  composability ("any element can connect to any other"), least safety.
  A user can wire 16 bytes from AES SubBytes into Serpent's bit-permutation
  and it'll run with surprising results.
- **(c) Hybrid — bytes + optional advisory shape tag** — the bytes ARE
  the canonical contract; tags are hints for the editor (mismatch warning,
  inspector formatting) but don't gate execution. The runtime always passes
  raw `Uint8Array`s; the editor lights up red on mismatch but lets the user
  override.

**User's stated lean: "array of bytes"** — pushes toward (b) or (c). The
pedagogical argument favors (c): mismatches are *visible* but not *blocking*,
because seeing what breaks IS the lesson.

### Q2: Mismatch rules — what happens when port shapes don't align?

Three pedagogies:

- **Coerce silently** — pad / truncate to match. Worst for learning (hides
  what went wrong).
- **Refuse to run** — execution stops at the mismatch. Safest, but pedagogy
  is "you can't do this" rather than "here's what happens when you do."
- **Warn loudly, run anyway, show the user what broke** — editor flags the
  mismatch with a red glyph + inspector explanation; runtime coerces (zero-pad
  or truncate) and continues. The trace shows the coercion explicitly so the
  user sees the consequence.

**Recommended: warn-and-run.** It matches the project's "let users
experiment, watch it break, learn from the break" philosophy.

### Q3: Aux feedback loops (CBC IV chain, CTR counter)

Today's CBC has `auxWritten("chain") → auxRead("chain")` between consecutive
iterations of `iterate` — a backward edge in time the current `iterate`
primitive collapses into a single per-iteration update.

Under unified ports, this is either:
- An explicit feedback edge on the canvas (visually intuitive but introduces
  cycle handling into graph derivation), or
- A "for-each subgraph" node where one of its ports is wired to its own
  next-iteration input (the iterate primitive in new clothes).

This needs an explicit design answer. The unified model doesn't get this for
free.

## What the new contract would look like

Roughly (sketch, not committed):

```ts
type PortShape = {
  // Bytes-only, length-typed. Optional advisory layout tag (Q1 option c).
  readonly byteLength: number;
  readonly layout?: "raw" | "matrix-cm-4x4" | "be-word" | "le-word" | string;
};

type StepInputs = ReadonlyMap<string, Uint8Array>;
type StepOutputs = ReadonlyMap<string, Uint8Array>;

type StepExecutor = (inputs: StepInputs, params: Json, ctx: StepContext) => StepOutputs;

type StepShapeContract = {
  readonly inputs: ReadonlyMap<string, PortShape>;
  readonly outputs: ReadonlyMap<string, PortShape>;
};
```

Edges become `{ from: { nodeId, portName }, to: { nodeId, portName } }` —
already most of what `GraphEdge` describes today, just with explicit port
identity instead of the aux/state distinction.

The `State` discriminated union (`BytesState`, `MatrixState`, `BitVecState`,
`BigIntState`) collapses to `Uint8Array` everywhere. `BitVecState` and
`BigIntState` aren't shipped today; `BytesState` and `MatrixState` differ only
by the column-major convention which becomes a port `layout` tag under (c).

The `Aux` map disappears — every value is just a port flow now.

## Migration strategy — incremental, not wholesale

A wholesale rebuild is too expensive: ~30 registered step types, ~1389 tests,
runtime, trace shape, the entire inspector/narration/provenance layer, the
DES+Feistel plan's recent design work, the universal cipher-shape plan all
sit on top of the current contract.

The proposed migration:

1. **Define the port contract alongside today's contract.** New types in
   `core/types.ts`: `PortShape`, `StepInputs`, `StepOutputs`, a new
   `PortedExecutor` flavor. Today's `StepExecutor` stays as `LegacyExecutor`.
2. **Adapter shims.** A `liftLegacyExecutor(legacy): PortedExecutor` wrapper
   maps today's `(state, params, aux) → (state, auxWrites)` to
   `(inputs, params) → outputs` mechanically. Every shipped step gets one
   line in the registry; no rewrite needed.
3. **Runtime supports both.** Registry entries declare which contract they
   speak; the runtime dispatches accordingly. Trace is unified: every frame
   records per-port byte arrays in/out, with the legacy state/aux split being
   one possible projection of that.
4. **Graph derivation simplifies.** Under unified ports, `inferStateEdges` and
   `dropAuxOnlyStateEdges` and the iterate-boundary suppression
   (`core/graph.ts:43`) become unnecessary — every edge IS a port-to-port
   flow, declared by the spec, not inferred from frames. The replication
   pipeline keeps its visual role but applies to all edges uniformly.
5. **New ciphers use the new shape directly.** First candidate: a hash
   function (SHA-2 / SHA-3) — picked deliberately because it has no
   "one state thread" pretense. Second candidate: DES if it hasn't shipped
   yet (would replace the Feistel branching primitive with native port
   splits).
6. **Deprecate legacy when nothing depends on it.** Once every shipped cipher
   has either been rewritten or stays under the adapter forever, the legacy
   executor flavor can be removed. Realistically, AES/Speck/Serpent stay under
   the adapter indefinitely — the cost of rewriting them isn't justified once
   the adapter works.

This preserves shipped work, doesn't freeze the project for months, and gets
to the unified destination with new ciphers leading the way.

## What this proposal does NOT decide

- Whether to do this at all (user's call, after advisor).
- The exact `PortShape` discriminator (Q1 a/b/c).
- The exact mismatch policy (Q2: coerce / refuse / warn-and-run).
- Feedback-loop handling (Q3: explicit feedback edges vs for-each subgraph).
- Whether `BitVecState` and `BigIntState` survive as port layouts or are
  modeled as bytes with a `layout` tag.
- Whether to ship DES under the legacy contract first (per current
  `docs/plans/des-feistel.md`) or hold DES for the unified contract.

## Next-session hand-off — DO THIS FIRST

1. Call `advisor()` with the full session context (the conversation that
   produced this doc) + this doc as input. Ask specifically: does the
   incremental dual-contract migration hold up under scrutiny, or are there
   load-bearing assumptions I'm missing?
2. Surface the advisor's response per the global feedback-visibility rule.
3. Bring the open questions (Q1/Q2/Q3) to the user with concrete option
   sketches; let them pick before any code lands.
4. Only then, if approved, draft a phased implementation plan with the
   first slice being the type contract + adapter shim (no behavior change).

## Pointers

- Conversation that produced this doc: 2026-05-21 session, the "what kind of
  data do elements in the graph view expect" question that led to the
  universal-ports proposal.
- Related (narrower) effort that this proposal would subsume:
  `~/.claude/plans/silly-brewing-sutton.md` — universal cipher-shape plan
  (registry consolidation, not contract rewrite).
- Related (interim) effort whose design becomes redundant under this
  proposal: `docs/plans/des-feistel.md` — the Feistel branching primitive
  is a workaround for the limitation this proposal removes.
- Current contract surface area: `src/core/types.ts` (State union,
  StepExecutor, IterateGroup, FeistelRoundGroup), `src/core/runtime.ts`
  (walker), `src/core/graph.ts` (derivation), `src/core/edge-value-lookup.ts`
  (inspector).
